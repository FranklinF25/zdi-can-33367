# Penetration Test Report — ZDI-CAN-33367

Lab-anchored analysis of the Linux kernel `skb_zerocopy()` improper
ownership-management vulnerability: the helper drops `SKBFL_SHARED_FRAG`
when transferring fragment descriptors, so ESP input skips
`skb_cow_data()` and AEAD-decrypts **in place over page-cache pages**
planted via `splice()` — an unprivileged user rewrites the cached copy
of read-only files without ever opening them for writing. Claims trace
to this repo's artifacts or the public record cached in `odd/research/`.
The report, chain, and validator demo are Trend Micro ZDI's (LKML,
2026-10-21); the fix is Zizhen Liu's. Status claims are dated
**as of 2026-11-01**.

## 1. Pre-engagement Interactions

| Field | Value |
|---|---|
| Target | Linux kernel `net/core/skbuff.c` `skb_zerocopy()`; reachable via nfnetlink_queue (`NFQA_PAYLOAD`) and Open vSwitch upcalls |
| Scope | This repository's own QEMU lab and its purpose-built targets only, plus a differential oracle restricted to a self-owned scratch file (`poc/detector.c` never touches a file it does not own) |
| Authorization | Educational security research on self-owned lab infrastructure; no third-party systems engaged at any point |
| Out of scope | Remote surface (`AV:L`); any real-world binary or file not owned by the current euid; weaponized turnkey exploitation (ethics posture, mandatory for an unpatched bug) |
| CVSS 3.1 (ZDI) | 7.8 HIGH `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |

## 2. Intelligence Gathering

- **ZDI report** (LKML, 2026-10-21; `odd/research/zdi-lkml-report-33367.txt`):
  "Linux Kernel skbuff skb_zerocopy Improper Ownership Management Local
  Privilege Escalation Vulnerability"; tested on 7.3-rc1 / Debian trixie;
  **no CVE as of 2026-11-01** (Sysdig TRT, 2026-10-24; re-verified 2026-11-01).
- **The leak**: ZDI sent six reports to security@kernel.org on
  2026-10-20/21 but mistakenly CC'd public lists (LKML, netdev,
  connman); details + three PoCs public before fixes. Table:
  [leak-timeline](leak-timeline.md).
- **Fix** (merged to mainline as `79dc34beb1fd`, verified 2026-11-01;
  stable backport pending): "[PATCH v2 net] net: skbuff:
  propagate shared-frag marker in skb_zerocopy()", Zizhen Liu, netdev
  2026-10-22, Reviewed-by Eric Dumazet, Cc stable, net tree 2026-10-23
  (`odd/research/netdev-v2-propagate-shared-frag.txt`). Dumazet's LKML
  reply the same day: the team already had a report *with patch* from
  another source ~1 week before the leak
  (`odd/research/dumazet-lkml-reply.txt`).
- **Repro matrix** (TuxCare, 2026-10-22): root on AlmaLinux 8/9/10 —
  *with the Dirty Frag fix installed* — CloudLinux 9/10, Debian 12/13,
  Ubuntu 24.04/26.04 (bypasses Ubuntu's AppArmor userns restriction);
  CentOS 6/7 clean.
- **Vendor response** (as of 2026-11-01): **Fedora** shipped the fix
  early (F43 `7.2.13-100`, F44 `7.2.13-200`, 2026-10-26/27);
  **AlmaLinux production kernels** since 2026-10-28 (AL8
  `4.18.0-553.178.1.el8_10`, AL9 `5.14.0-687.60.1.el9_8`, AL10
  `6.12.0-211.69.1.el10_2`; the 2026-10-23 testing kernels also carry
  it); Rocky 9.8's same-NVR kernel does **not** carry it; KernelCare
  livepatch EL9+EL10 out / EL8 ready
- **Detection**: Sysdig TRT (2026-10-24) rule "Page Cache Poisoning via
  Spliced File Pages to Loopback" matches the exploit's syscall
  sequence.
- **Prior art**: Dirty Frag (CVE-2026-43284, Hyunwoo Kim, disclosed
  2026-04-30; fix `f4c50a4034e6` merged 2026-05-07, mainline ≥ v7.1);
  six gap CVEs May–Oct 2026 — this is the seventh drop of the same flag.
  Introduced by `af2806f8f90a` (~kernel 3.14).

## 3. Threat Modeling

- **Actor**: unprivileged local user; every step is an ordinary syscall
  — no capability beyond the user-created namespace, no KASLR leak,
  runs with `NoNewPrivs=1` (validator: `CapEff=0 CapBnd=0 NoNewPrivs=1`).
- **Asset**: page-cache integrity of read-only files — the bytes every
  process reads and executes. Poisoning a cached setuid binary or
  `/etc/passwd` page yields root; those targets stay analytical (§5.2).
- **Kill chain** (ZDI's public chain):
  1. `unshare(CLONE_NEWUSER|CLONE_NEWNET)`; bring up `lo` + `nlmon0`;
     XFRM ESP state on 127.0.0.1 (`hmac(sha256)-128` + `cbc(aes)`, ESN)
     + `dir in` policy; nftables NFQUEUE rule (queue 0, `COPY_PACKET`).
  2. `splice()` a read-only file's pages as the nonlinear frag of a UDP
     packet to 127.0.0.1 (linear prefix attacker-owned).
  3. NFQUEUE builds the netlink msg via `skb_zerocopy()` — **flag lost
     here**; destination keeps the file-backed frag but reports
     `skb_has_shared_frag() == false`.
  4. Tap via nlmon; `tc u32` + `pedit` (24 keys) rewrite only the linear
     prefix into a valid ESP packet; `act_mirred` redirects to `lo`.
  5. `esp4_input` sees no shared frag → skips `skb_cow_data()` → AEAD
     decrypt writes over the retained page-cache pages.
- **Composed failure**: three individually reasonable decisions — ESP's
  post-`f4c50a4034e6` trust in one marker, a transfer helper that copies
  descriptors but not the marker, and splice's generic wiring of
  readable files into skb frags.

## 4. Vulnerability Analysis

- **Root cause anchored to the fix.** The patch adds one functional line
  after `skb_shinfo(to)->nr_frags = j;` in `skb_zerocopy()`:

  ```c
  skb_shinfo(to)->flags |= skb_shinfo(from)->flags & SKBFL_SHARED_FRAG;
  ```

  The fix's commit message states the mechanism: the destination
  "holding the same page-cache backed frags as the source therefore
  reports skb_has_shared_frag() as false" — ESP "is decrypted in place,
  letting an unprivileged user write into the page cache of a
  root-owned read-only file".
- **The `Fixes:` pairing is the diagnosis**: `af2806f8f90a` introduced
  the lossy transfer; `f4c50a4034e6` created the consumer that trusts
  the marker. Vulnerable window = kernels with the Dirty Frag fix but
  not this patch — exactly the lab's A/B delta. (Sharpening detail: the
  pre-existing lines after the insertion point already propagate
  `from->unreadable` — fragment metadata made it across; the ownership
  marker did not.)
- **The 7-gap family**: seventh documented drop of `SKBFL_SHARED_FRAG`
  in a frag-transfer path since May 2026. Table + verdicts:
  [audit/shared-frag-flag-audit.md](../audit/shared-frag-flag-audit.md).
  **CVE-2026-90049 is a different bug in the same function** — a kernel
  carrying only its fix is *not* protected against 33367.
- **Attack surface**: `NFQA_PAYLOAD` (nfnetlink_queue) and OVS upcalls.
  The helper family is under active hardening upstream (Oct-2026 netdev
  series: `BUG_ON` → `-EFAULT`; devmem unreadable frags) — context, not
  our finding.

## 5. Exploitation

### 5.1 Primitive — reproduced safely, with attribution

The public chain and validator demo are ZDI's; our reproduction is an
independent safe oracle, `poc/detector.c` (rationale: writeup §0, §3):

- Creates its **own** scratch file — owned by the executing euid, mode
  0444, in its own created directory — and refuses any file or directory
  not owned by the current euid; the boundary exercised is exactly the
  one the bug breaks (read without write, on bytes we already own).
- Re-runs the NFQUEUE → `skb_zerocopy()` → nlmon → tc-pedit → ESP chain
  inside a private userns+netns against that file; emits
  `DETECTOR-RESULT: VULNERABLE|NOT-DETECTED` + `DISKCLEAN` evidence +
  exit code.
- **Expected outcomes** (lab A/B in `lab/`, delta = exactly the 2-line
  patch): `VULNERABLE` on a kernel with `f4c50a4034e6` but without the
  zerocopy fix; `NOT-DETECTED` with the patch applied. Lab run evidence
  lands in `lab/README.md` once the A/B harness has been executed.
- **Public corroboration** (ZDI validator stdout, cached): 8 KiB
  root-owned 0444 non-executable scratch file, 8 bytes changed at offset
  4160 as an unprivileged user (`WRITE_DENIAL open(O_WRONLY) errno=13`),
  SHA-256 verified, surviving `fadvise DONTNEED` (`RESULT
  ZEROFRAG_REPRODUCED=1`); the written bytes are the validator's own
  harmless 8-byte marker.

### 5.2 Escalation — closed in-lab against a purpose-built target ONLY

- The lab rootfs ships `secretgate` (`lab/rootfs/tools/secretgate.c`),
  a purpose-built SUID-root gate that prints the root flag only if its
  read-only data page was patched — built for this experiment, never a
  real-world binary.
- `poc/lpe.c` re-aims the detector's primitive exclusively at that
  binary; **expected** to print `LPE-RESULT: ROOT-FLAG-CAPTURED` (uid
  1000 reading the root-only flag through patched page-cache bytes) on
  the vulnerable side, `NOT-VULNERABLE` on the patched side. Public
  escalation targets (setuid binary, `/etc/passwd`) are discussed
  analytically only (§6); no real-world binary is targeted here.

## 6. Post Exploitation

- **What the primitive gives**: chosen bytes at chosen offsets of the
  page-cache copy of any file the user can read; the disk copy stays
  pristine (the page is never dirtied), so disk checksums, IMA against
  trusted storage, and offline forensics see nothing — ZDI's demo proves
  the divergence survives eviction (`fadvise DONTNEED`, disk hash
  unchanged).
- **Setuid/passwd implications (analytical)**: a cached setuid binary's
  text can be rewritten so the next execution of the still-clean
  on-disk file runs attacker instructions as root; a cached
  `/etc/passwd` page can gain a `uid 0` entry. Both need only read
  permission — the documented impact class of Dirty Pipe, Copy Fail,
  and Dirty Frag; we describe it, not demonstrate it outside the lab.
- **Volatility and detection**: page-cache edits evaporate on
  eviction/reboot — "volatile persistence"; the exploitation sequence
  (unshare → nlmon → XFRM state → NFQUEUE rule → pedit+redirect →
  splice to 127.0.0.1, one unprivileged process) is distinctive at
  syscall level, so runtime telemetry is the practical sensor (§7,
  `detect/`).

## 7. Reporting

### Remediation

- **Primary**: a kernel carrying Zizhen Liu's 2-line fix (netdev v2,
  2026-10-22, Reviewed-by Eric Dumazet, Cc stable; net tree 2026-10-23).
  **Merged to mainline as `79dc34beb1fd`** (verified 2026-11-01); **not
  yet in upstream stable releases** (7.2.14/7.3.1 of 2026-10-30 predate
  it) — track stable and vendor release notes.
- **Shipped fixed kernels**: Fedora F43 `7.2.13-100` / F44 `7.2.13-200`
  (2026-10-26/27); AlmaLinux production (2026-10-28): AL8
  `kernel-4.18.0-553.178.1.el8_10`, AL9 `kernel-5.14.0-687.60.1.el9_8`,
  AL10 `kernel-6.12.0-211.69.1.el10_2`; KernelCare livepatch EL9+EL10
  out / EL8 ready; no fixed RHEL kernel yet. **NVR trap**: Rocky 9.8's
  `5.14.0-687.60.1.el9_8` matches AlmaLinux's fixed NVR but lacks the
  fix — verify via the rpm changelog.
- **CVE-2026-90049's fix is not coverage** — different bug, same
  function.

### Mitigations (pending the fix)

- Restrict unprivileged user namespaces: `user.max_user_namespaces=0`
  (Debian: `kernel.unprivileged_userns_clone=0`) blocks the public PoC.
  Cost: rootless containers, browser sandboxes, some build tooling —
  scope to hosts that don't need userns.
- Blacklist `nlmon` + `act_pedit` where possible; the public PoC needs
  both (TuxCare: may not close every path).
- Kubernetes: enforce seccomp `RuntimeDefault` cluster-wide; Docker's
  default already blocks `unshare(CLONE_NEWUSER)`. Don't rely on
  Ubuntu's AppArmor userns restriction — the PoC bypassed it.
- **Detect**: Sysdig TRT's rule; `detect/` is this repo's original
  Falco adaptation (attribution in-file). The exploit leaves no disk
  trace, so runtime telemetry is the practical sensor.

### Risk statement (as of 2026-11-01)

Unpatched systems face an unprivileged local privilege escalation whose
public exploit works on current AlmaLinux, CloudLinux, Debian, and
Ubuntu releases — *including kernels already carrying the Dirty Frag
fix* — with no CVE to scan for and a working PoC open since 2026-10-21.
The upstream fix is merged to mainline (`79dc34beb1fd`) but has not yet
reached upstream stable releases or most vendors (Fedora and AlmaLinux
already ship it). Multi-user hosts, jump boxes, and container nodes on
affected kernels should mitigate now (above) and patch the day the
vendor ships the `skb_zerocopy()` fix. CentOS 6/7 clean. No in-the-wild
exploitation known as of 2026-11-01.
