# Finding Sheet — ZDI-CAN-33367 (Linux kernel `skb_zerocopy()` drops `SKBFL_SHARED_FRAG`)

One-page datasheet. Status claims are dated **as of 2026-11-01**: no CVE is
assigned yet, and the upstream fix is **merged to mainline** (`79dc34beb1fd`)
but not yet in any upstream stable release. Analysis only — the
public PoC's source is not reproduced here (see Scope & ethics at the end).

| Field | Value |
|---|---|
| ID | ZDI-CAN-33367 (Trend Micro ZDI) — **no CVE assigned as of 2026-11-01** |
| ZDI title | "Linux Kernel skbuff skb_zerocopy Improper Ownership Management Local Privilege Escalation Vulnerability" |
| Component | Linux kernel — `skb_zerocopy()` (`net/core/skbuff.c`); consumers: nfnetlink_queue (NFQUEUE `NFQA_PAYLOAD`) and Open vSwitch upcalls |
| Class | Page-cache write via in-place ESP decrypt over splice-backed skb frags → local privilege escalation |
| CVSS 3.1 | 7.8 HIGH — `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Reported by | Trend Micro ZDI; tested by ZDI on kernel 7.3-rc1 / Debian trixie (validator: `KERNEL release=7.3.0-rc1 machine=x86_64`). Full report + public PoC reached LKML 2026-10-20/21 via an accidental public CC (see Prior art) |
| Introduced | `af2806f8f90a` "net: Export skb_zerocopy() to zerocopy from one skb to another" (~kernel 3.14) |
| Fix | Zizhen Liu, "net: skbuff: propagate shared-frag marker in skb_zerocopy()" — netdev v2 2026-10-22 → net tree 2026-10-23 → **mainline `79dc34beb1fd`** (verified 2026-11-01); stable backport pending |
| Attack vector | Local, unprivileged, race-free; no KASLR leak, no extra capabilities, works with `NoNewPrivs=1` |
| Requirements | Unprivileged user namespaces + `nlmon`, `nfnetlink_queue`/`nft_queue`, `cls_u32`, `act_pedit`, `act_mirred`, `esp4` (plus `xfrm_user`, `hmac(sha256)`, `cbc(aes)`) |

## Affected versions & repro matrix

Anything from ~3.14 (`af2806f8f90a`) onward that routes packet payloads through
`skb_zerocopy()` (NFQUEUE `NFQA_PAYLOAD`, OVS upcalls) is exposed. Kernels that
already carry the Dirty Frag fix `f4c50a4034e6` (mainline ≥ v7.1) are **still
vulnerable**: the fix makes ESP honor the marker, but `skb_zerocopy()` drops the
marker before the check.

Root repro matrix (TuxCare, 2026-10-22):

| Distro | Verdict | Notes |
|---|---|---|
| AlmaLinux 8 | Vulnerable | ships the Dirty Frag fix — which does **not** cover this bug |
| AlmaLinux 9 | Vulnerable | same |
| AlmaLinux 10 | Vulnerable | same |
| CloudLinux 9 | Vulnerable | |
| CloudLinux 10 | Vulnerable | |
| Debian 12 | Vulnerable | TuxCare notes its 6.1 kernel needs a slightly different trigger |
| Debian 13 | Vulnerable | |
| Ubuntu 24.04 | Vulnerable | AppArmor unprivileged-userns restriction bypassed |
| Ubuntu 26.04 | Vulnerable | AppArmor unprivileged-userns restriction bypassed |
| CentOS 6 | Not affected | 2.6.32 predates `skb_zerocopy()` |
| CentOS 7 | Not affected | 3.10 has the helper, but its ESP code always makes a private copy of nonlinear data |

Fixed-kernel rollout (verified 2026-11-01): **Fedora shipped early** — F43
`kernel-7.2.13-100` and F44 `kernel-7.2.13-200` carry the fix backported
atop v7.2.13 (changelog 2026-10-26). **AlmaLinux moved fixed kernels to
production on 2026-10-28**: `kernel-4.18.0-553.178.1.el8_10` (AL8),
`kernel-5.14.0-687.60.1.el9_8` (AL9), `kernel-6.12.0-211.69.1.el10_2`
(AL10) — the 2026-10-23 testing kernels also carry it. **Trap**: Rocky Linux
9.8 ships `kernel-5.14.0-687.60.1.el9_8` — the *same NVR* as the fixed
AlmaLinux kernel — **without** the fix (verified via rpm changelog by
centminmod, 2026-10-29); judge by changelog, not NVR. KernelCare rebootless
patch (2026-10-27): out for **EL9 and EL10** on AlmaLinux, CloudLinux, RHEL,
Oracle Linux, Rocky; EL8 ready for release; Debian and Ubuntu in progress —
no fixed RHEL kernel yet as of 2026-11-01.

## Fix commits

| Commit | Role | Status as of 2026-11-01 |
|---|---|---|
| `af2806f8f90a` | Introducing commit — exports `skb_zerocopy()` for skb→skb zerocopy; the flag drop ships with it (~3.14) | present in every kernel since ~3.14 |
| `f4c50a4034e6` | Dirty Frag fix (Hyunwoo Kim @v4bel, CVE-2026-43284) — "xfrm: esp: avoid in-place decrypt on shared skb frags"; ESP honors `SKBFL_SHARED_FRAG` | merged 2026-05-07; in mainline ≥ v7.1. Necessary but **not sufficient** — defeated whenever a transfer path drops the flag |
| `79dc34beb1fd` | "[PATCH v2 net] net: skbuff: propagate shared-frag marker in skb_zerocopy()" — Zizhen Liu, Reviewed-by Eric Dumazet, 2026-10-22, Cc stable | **merged** — posted 2026-10-22 (<https://lists.openwall.net/netdev/2026/10/22/204>), committed to the net tree 2026-10-23, verified in Linus' tree 2026-11-01 (<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=79dc34beb1fdb3da79753e51e15c68591a2561fe>). **Not in 7.2.14/7.3.1** (2026-10-30, verified via ChangeLogs) — stable backport pending |

## Root cause — anchored to the 2-line fix

**1. The transfer that drops the flag.** `skb_zerocopy()` moves frag
descriptors from `@from` into `@to` and takes a page reference on each frag —
but never propagates `skb_shinfo(from)->flags & SKBFL_SHARED_FRAG`. A
destination skb sharing the source's page-cache-backed frags therefore reports
`skb_has_shared_frag() == false` (fix commit message).

**2. Why ESP then decrypts in place.** Since the Dirty Frag fix
`f4c50a4034e6`, ESP input relies on `skb_has_shared_frag()` to decide whether
an uncloned nonlinear skb must be copied via `skb_cow_data()` before decrypt.
With the marker lost, the check passes as "safe" and the AEAD decrypt runs **in
place over the source frags**.

**3. Planting file pages into the frag.** `splice(file → pipe → UDP socket)`
hands the skb a nonlinear frag that is literally a page-cache page of any file
the attacker can read (e.g. a setuid binary or `/etc/passwd`). When that packet
rides through NFQUEUE, `skb_zerocopy()` retains the page but loses the marker —
so the decrypted plaintext lands on the page-cache copy of the read-only file:
attacker-chosen bytes at an attacker-chosen offset, written without ever
opening the file for writing.

The upstream fix is exactly two added lines in `net/core/skbuff.c`, propagating
the marker at the transfer boundary as the other frag-transfer helpers already
do (`Fixes: af2806f8f90a` + `f4c50a4034e6`, Cc stable):

```diff
@@ -3942,6 +3942,8 @@ skb_zerocopy(struct sk_buff *to, struct sk_buff *from, int len, int hlen)
 	}
 	skb_shinfo(to)->nr_frags = j;

+	skb_shinfo(to)->flags |= skb_shinfo(from)->flags & SKBFL_SHARED_FRAG;
+
 	if (i > 0 && from->unreadable)
 		to->unreadable = 1;
```

**Net primitive:** from an unprivileged user with zero capabilities, write
attacker-chosen bytes at an attacker-chosen offset into the page cache of any
readable file. The validator's `MMAP_VIEW target_bytes=5a4652472d4f4b21
mmap_matches_desired=1` confirms the patched bytes are visible via `mmap()`.
Patching a setuid binary's page cache this way is the LPE path; in this repo it
is closed in-lab only against a purpose-built target.

## The 7-gap family

The Dirty Frag fix protects only while `SKBFL_SHARED_FRAG` survives every hop.
Seven transfer paths are known to drop it — all the same defect class ("flag
dropped by some frag-transfer path"):

| # | ID | Frag-transfer path that drops the flag | Note |
|---|---|---|---|
| 1 | CVE-2026-43503 | frag copy/shift helpers — `__pskb_copy_fclone`, `skb_shift` | |
| 2 | CVE-2026-46300 | coalescing — `skb_try_coalesce` ("Fragnesia") | |
| 3 | CVE-2026-53363 | IPTFS | |
| 4 | CVE-2026-64566 | IPTFS | |
| 5 | CVE-2026-80977 | error-handling helper | |
| 6 | CVE-2026-90049 | an error path inside `skb_zerocopy()` itself | **A kernel carrying only this fix is NOT protected against ZDI-CAN-33367** — the main success path still drops the flag |
| 7 | **ZDI-CAN-33367** | `skb_zerocopy()` main path — NFQUEUE `NFQA_PAYLOAD` + OVS upcalls | this repo |

Family lineage: Dirty Pipe → Copy Fail (CVE-2026-31431) → Dirty Frag
(CVE-2026-43284) → the 7 propagation gaps above.

## Attack surface

**Who calls `skb_zerocopy()`:**

- nfnetlink_queue — every `NFQA_PAYLOAD` netlink message built for an NFQUEUE
  verdict (nftables `queue` / libnetfilter_queue consumers);
- Open vSwitch — upcall messages from the datapath to userspace.

Both build the netlink message over the packet's frags — including
splice-planted page-cache frags — and lose the marker at build time; the
trigger does not need a queue daemon to ever read the payload.

**Full requirement list for the public chain:** unprivileged user namespaces
(`unshare(CLONE_NEWUSER|CLONE_NEWNET)`), `nlmon`, `nfnetlink_queue` +
nftables `queue` (nft_queue), `cls_u32`, `act_pedit`, `act_mirred`, `esp4`
(with `xfrm_user`, `hmac(sha256)`, `cbc(aes)`, ESN).

## Verified public-PoC decode

Syscall sequence (ZDI's public LKML report; local copy
`odd/research/zdi-lkml-report-33367.txt`) — all steps as an ordinary user:

```
unshare(CLONE_NEWUSER|CLONE_NEWNET)        # userns_uid=0, fresh netns (unshare=OK)
ip link set lo up; ip link add nlmon0 type nlmon
xfrm: state 127.0.0.1 esp spi=0x100 transport, policy dir_in
      auth hmac(sha256)-128, enc cbc(aes), ESN
nft: table skbaudit / chain outq / hook LOCAL_OUT -> NFQUEUE 0
     (copy_mode=NFQNL_COPY_PACKET, copy_range=65535, flags GSO|UID_GID)
sendmsg UDP probe (sent=522): linear bytes owned + nonlinear splice-backed frag
     = 8 bytes of the target read-only file
     -> NFQUEUE builds the NFQA_PAYLOAD netlink skb via skb_zerocopy()
        (nfq_msglen=618; frag at [96,104)) — SKBFL_SHARED_FRAG lost HERE
tc on nlmon0 egress: u32 -> pedit 24 keys (FRAME length=96; rewrites ONLY the
     linear prefix into a valid authenticated ESP packet) -> mirred redirect to lo
esp4 input on lo: skb_has_shared_frag()==false -> skips skb_cow_data()
     -> AEAD decrypt IN PLACE over the retained file-backed frag
     (INNER_UDP_RECEIVED len=528, "decrypted in place, delivered on lo";
      all /proc/net/xfrm_stat counters 0 — no error path)
```

Validator's observed numbers (harmless-scratch mode, kernel 7.3.0-rc1 x86_64,
Debian trixie guest, run as unprivileged `testuser`):

| Observation | Value |
|---|---|
| Target | `/var/tmp/zf-scratch-8k.bin` — 8 KiB (8192 B), `uid=0 gid=0 mode=0444`, non-executable, fully synced (clean page cache) beforehand |
| Precondition denial | `WRITE_DENIAL open(O_WRONLY) errno=13 (Permission denied)` — the user cannot open the file for writing |
| SHA-256 before | `a52335f7f41fbbb0ea7896689621111ae31a7426a2235ae066bfc1e7255990a6` |
| Write through the bug | 8 bytes at offset **4160** → decrypted plaintext `5a 46 52 47 2d 4f 4b 21` ("ZFRG-OK!") |
| Capabilities | `CapInh/CapPrm/CapEff/CapBnd/CapAmb=0`, `NoNewPrivs=1` — zero capabilities throughout |
| Trigger telemetry | `sent=522 target_spliced=8 vector_spliced=514`; `changed=1 guards_ok=1 target_exact=1` |
| SHA-256 after | `7aaed173fe012e8870c209625be04ac9230cee3bff2f97582e088edf0e85ee5a` |
| mmap view | `MMAP_VIEW target_bytes=5a4652472d4f4b21 mmap_matches_desired=1` |
| Eviction | `EVICTION fadvise=DONTNEED window_recovered_to_original=0`; SHA-256 after eviction unchanged — the patch survived the eviction attempt as run |
| Result | `RESULT ZEROFRAG_REPRODUCED=1`, validator exit code 0 |

## Mitigations

| Mitigation | Effect / cost |
|---|---|
| `user.max_user_namespaces=0` (Debian: `kernel.unprivileged_userns_clone=0`) | blocks the public PoC; breaks rootless containers and browsers |
| blacklist `nlmon` + `act_pedit` | removes the capture and rewrite primitives the chain needs |
| Kubernetes seccomp `RuntimeDefault` | blocks `unshare(CLONE_NEWUSER)` (Docker's default seccomp already does) |
| Ubuntu AppArmor userns restriction | **not a mitigation** — bypassed by the PoC |
| KernelCare rebootless patch | EL9 + EL10 out (AlmaLinux, CloudLinux, RHEL, Oracle, Rocky), EL8 ready, Debian/Ubuntu in progress — as of 2026-10-27. Verify with `kcarectl --update && kcarectl --patch-info \| grep -i 33367` |

Detection: Sysdig TRT rule **"Page Cache Poisoning via Spliced File Pages to
Loopback"** — matches the distinctive single-process sequence: userns+netns
unshare → nlmon up → XFRM state → NFQUEUE rule → tc pedit+redirect →
`splice()` to a 127.0.0.1 socket.

## Prior art & references

- **ZDI advisory + public PoC** — Trend Micro ZDI; the report (with validator
  stdout and PoC source) became public on LKML/netdev 2026-10-20/21 through an
  accidental CC, before fixes existed — part of a 6-report batch, none with a
  CVE at leak time; no known in-the-wild exploitation as of 2026-11-01 —
  <https://lkml.iu.edu/2610.2/14824.html>
- **Upstream fix** — Zizhen Liu `<pointerliu@126.com>`, netdev v2, 2026-10-22,
  Reviewed-by Eric Dumazet, Cc stable; merged to mainline as `79dc34beb1fd`
  (net tree 2026-10-23; verified in Linus' tree 2026-11-01) —
  <https://lists.openwall.net/netdev/2026/10/22/204> ·
  <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=79dc34beb1fdb3da79753e51e15c68591a2561fe>
- **Eric Dumazet LKML reply** (2026-10-22) — the kernel team had already
  received a report *with patch* from another source ~1 week before ZDI's leak —
  <https://lkml.iu.edu/2610.2/15245.html>
- **Dirty Frag prior art** — Hyunwoo Kim (@v4bel), CVE-2026-43284, fix
  `f4c50a4034e6` — <https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md>
- **Detection & triage** — Sysdig Threat Research Team (rule name, mitigations) —
  <https://www.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws/>
- **Repro matrix** — TuxCare (2026-10-22) —
  <https://tuxcare.com/blog/zdi-ksmbd-bugs-cve/>
- **AlmaLinux** — advisory blog (2026-10-23) —
  <https://almalinux.org/blog/2026-10-23-zdi-can-33367/>
- **CloudLinux** — mitigation writeup — <https://blog.cloudlinux.com/zdi-can-33367/>
- **Family prior art** — Dirty Pipe → Copy Fail (CVE-2026-31431, AF_ALG AEAD —
  same in-place-crypto-over-page-cache family) → Dirty Frag (CVE-2026-43284).

**Scope & ethics:** analysis and attribution only. The public PoC already
circulates via LKML; nothing in this repo reproduces its source or hardens it
into a turnkey exploit. Status claims updated 2026-11-01.
