# ZDI-CAN-33367 — Linux Kernel `skb_zerocopy` Shared-Frag Flag Drop: Analysis

Security research on **ZDI-CAN-33367** (ZDI: "Linux Kernel skbuff skb_zerocopy
Improper Ownership Management Local Privilege Escalation"; CVSS 3.1 **7.8 HIGH**,
`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`; no CVE assigned as of 2026-10-26 — it
will be referenced here when assigned, the repo name stays): an unprivileged
local user rewrites the **page-cache copy of read-only files** (setuid binaries,
`/etc/passwd`) without ever opening them for writing — the on-disk copy stays
pristine, so integrity checkers see nothing — and turns that into local root.
ZDI tested kernel 7.3-rc1 on Debian trixie; TuxCare reproduced as root on
AlmaLinux 8/9/10 *with the Dirty Frag fix installed*, CloudLinux 9/10, Debian
12/13, Ubuntu 24.04/26.04. The bug is **unpatched upstream as of 2026-10-26**,
and a working public PoC already circulates via ZDI's LKML disclosure mail.

1. `af2806f8f90a` (kernel ~3.14) introduced `skb_zerocopy()` — it transfers
   frag descriptors and page references to the destination skb but does **not**
   propagate `SKBFL_SHARED_FRAG`.
2. `f4c50a4034e6` (Dirty Frag fix, Hyunwoo Kim, mainline ≥ 7.1) created the
   `SKBFL_SHARED_FRAG` invariant and taught ESP input to skip in-place
   decryption when `skb_has_shared_frag()` is true.
3. NFQUEUE (`nfnetlink_queue` `NFQA_PAYLOAD`) and Open vSwitch upcalls use
   `skb_zerocopy()`, which **drops the flag** — the destination reports
   `skb_has_shared_frag()==false`.
4. ESP input therefore skips `skb_cow_data()` and AEAD-decrypts **in place**
   over splice-backed page-cache pages of a read-only file planted in the skb
   frag — unprivileged write to page cache. Fix (Zizhen Liu, netdev v2,
   Reviewed-by Eric Dumazet 2026-10-22, Cc stable, unmerged as of 2026-10-26):
   exactly **2 added lines** propagating the flag.

## Verification matrix

| Claim | Evidence |
|---|---|
| Root cause derived from the 2-line fix diff and kernel sources, not from blogs | [finding-sheet](docs/finding-sheet.md) |
| Public PoC decode verified end-to-end against the syscall sequence | [finding-sheet](docs/finding-sheet.md) |
| Lab A/B kernels with delta = exactly the 2-line netdev v2 patch (Dirty-Frag-fixed base, v7.2 line), both boot | `lab/scripts/build.sh` + `lab/out/ab-diffstat.txt` |
| **Safe detector: VULNERABLE on Dirty-Frag-fixed-but-unpatched kernel, NOT-DETECTED with the 2-line patch — touches only files it owns** | `poc/detector.c` in the lab → `DETECTOR-RESULT` lines |
| **In-lab LPE closure: uid 1000 patches page-cache bytes of a purpose-built SUID target and reads the root-only flag; disk copy proven pristine via block-level read** | `poc/lpe.c` + `lab/rootfs/tools/secretgate.c` → `LPE-RESULT: ROOT-FLAG-CAPTURED`, `DISKCLEAN` lines |
| Shared-frag audit: all 7 known `SKBFL_SHARED_FRAG` propagation gaps systematized + walk of every frag-transfer helper hunting the 8th | [audit/shared-frag-flag-audit.md](audit/shared-frag-flag-audit.md) |
| Falco rule matching the distinctive poisoning sequence (unshare → nlmon → XFRM → NFQUEUE → tc pedit+mirred → splice to 127.0.0.1) | [detect/](detect/) |

## Quick start

```bash
# build the A/B kernels + tools in Docker (prerequisites in the lab README)
# first build ~17 min (two kernels from one tree; cached re-runs take seconds)
lab/scripts/build.sh

# boot the A/B oracle (QEMU in Docker, KVM if available; ~11-12 s per flavor)
# observed 2026-10-27, tools running as real uid 1000:
lab/scripts/run.sh vuln     # DETECTOR-RESULT: VULNERABLE + LPE-RESULT: ROOT-FLAG-CAPTURED flag{zerofrag-lpe-in-lab} + DISKCLEAN=ok
lab/scripts/run.sh patched  # DETECTOR-RESULT: NOT-DETECTED + LPE NOT-VULNERABLE (gate stays GATELOCK)
```

## What is original here vs prior work

Prior work, with attribution: ZDI's vulnerability analysis and the public PoC
(disclosed to LKML in the 2026-10-20/21 leak); the 2-line fix by **Zizhen Liu**
(Reviewed-by Eric Dumazet); the **Dirty Frag** bug and `f4c50a4034e6` fix by
**Hyunwoo Kim** (the precondition this bug violates); Sysdig TRT's detection
rule and mitigation analysis. Original work in this repo: the
shared-frag-flag **audit systematization** — all 7 known propagation gaps of
the Dirty Frag fix in one table, plus a helper-by-helper hunt for an 8th gap
(honest negative if none) — the fix-anchored **safe differential oracle**
(`detector.c`, never touches files it does not own), the **in-lab LPE
closure** against a purpose-built SUID target (`secretgate` — no real-world
binary is ever targeted) with a block-level disk-clean proof, the **Falco
adaptation** of Sysdig's detection logic, and the **leak timeline** of the
accidental public disclosure.

## Documents

| Doc | What it is |
|---|---|
| [docs/finding-sheet.md](docs/finding-sheet.md) | One-page datasheet: versions, CVSS, root cause, fix commits, attack surface |
| [docs/report-ptes.md](docs/report-ptes.md) | PTES-structured report (7 phases) with lab evidence |
| [docs/research-writeup.md](docs/research-writeup.md) | Investigation narrative — methodology, dead ends, portable lessons |
| [docs/leak-timeline.md](docs/leak-timeline.md) | Dated chronology of the 2026-10-20/21 disclosure leak and aftermath |

## Repository layout

```
docs/            finding sheet · PTES report · research writeup · leak timeline
poc/             detector.c (safe differential oracle) · lpe.c (in-lab LPE closure)
lab/             QEMU kernel lab: A/B kernels, delta = exactly the 2-line fix
audit/           shared-frag-flag-audit.md — 7 known gaps + hunt for the 8th
detect/          Falco rule for the page-cache poisoning sequence
```

## References

- [ZDI report on LKML (accidental public disclosure)](https://lkml.iu.edu/2610.2/14824.html)
- [Fix v2 — "net: skbuff: propagate shared-frag marker in skb_zerocopy()" (Zizhen Liu, netdev)](https://lists.openwall.net/netdev/2026/10/22/204)
- [Eric Dumazet's LKML reply (independent earlier report with patch)](https://lkml.iu.edu/2610.2/15245.html)
- [Sysdig TRT — detecting and mitigating ZDI-CAN-33367 and five other Linux flaws](https://www.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws/)
- [TuxCare — repro matrix and livepatch status](https://tuxcare.com/blog/zdi-ksmbd-bugs-cve/)
- [AlmaLinux — ZDI-CAN-33367 statement](https://almalinux.org/blog/2026-10-23-zdi-can-33367/)
- [CloudLinux — ZDI-CAN-33367 writeup](https://blog.cloudlinux.com/zdi-can-33367/)
- [Dirty Frag (CVE-2026-43284) writeup — Hyunwoo Kim](https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md)
- Companion repo: [CVE-2026-31431 "Copy Fail"](https://github.com/FranklinF25/cve-2026-31431) —
  the family arc: Dirty Pipe → Copy Fail → Dirty Frag → 7 fix-propagation
  gaps → this bug, the 7th.

---

*Educational research artifact. Run only against systems you own or are
explicitly authorized to test. **THE BUG IS UNPATCHED UPSTREAM as of
2026-10-26** — no CVE has been assigned yet (it will be referenced here when
assigned; the repo name stays), and a public PoC already circulates via LKML.
See mitigations in the [finding sheet](docs/finding-sheet.md).*
