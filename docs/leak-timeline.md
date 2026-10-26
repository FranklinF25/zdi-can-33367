# Leak Timeline — ZDI-CAN-33367 and the 2026-10-20/21 disclosure

A dated chronology of the leak and its aftermath, built strictly from the
public record cached in `odd/research/`. Companion docs:
[report-ptes](report-ptes.md) · [research-writeup](research-writeup.md).
Status as of **2026-10-26**.

## Before the leak: the family

- **2026-04-30** — Hyunwoo Kim (@v4bel) submits the ESP page-cache-write
  report and a weaponized root exploit to security@kernel.org, and
  publishes the patch information to netdev the same day; Kuan-Ting Chen
  files an independent report (+9 h) and, on 2026-05-04, the
  shared-frag-approach patch that becomes the fix.
  Source: <https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md>
- **2026-05-07** — fix `f4c50a4034e6` ("xfrm: esp: avoid in-place decrypt
  on shared skb frags") merged into the netdev tree; the 5-day
  linux-distros embargo is broken by an unrelated third party; the Dirty
  Frag write-up is published.
  Source: <https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md>
- **2026-05-08** — `f4c50a4034e6` lands in mainline (v7.1+);
  CVE-2026-43284 assigned.
  Source: <https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md>
- **May → Oct 2026** — six CVEs document other paths that drop
  `SKBFL_SHARED_FRAG` after the Dirty Frag fix: CVE-2026-43503
  (frag-copy/shift helpers), CVE-2026-46300 (coalescing), CVE-2026-53363
  and CVE-2026-64566 (IPTFS), CVE-2026-80977 (error-handling helper),
  CVE-2026-90049 (an error path inside `skb_zerocopy()` itself).
  Source: <https://www.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws/>

## The leak: 2026-10-20/21

ZDI sent six reports to security@kernel.org but mistakenly CC'd public
lists (LKML, netdev, connman) — full details and three PoCs public
before fixes and before any CVE assignment.

| ZDI-CAN | Component | CVSS | Note at leak time |
|---|---|---|---|
| **33367** | skbuff `skb_zerocopy()` (this bug) | 7.8 | unprivileged LPE; public PoC; **no CVE** |
| 33774 | ksmbd SMB1/SMB2 dispatch race | 9.0 | pre-auth OOB per ZDI; fix `68f410faedaf` in maintainer tree only |
| 33549 | ksmbd SMB Direct RDMA int underflow | 9.0 | needs RDMA + writable share; PoC crashes kernel |
| 34068 | vmwgfx OOB write (LPE) | 8.8 | VMware guests only; no patch; title-only detail |
| 34076 | nvmet info leak | — | title only |
| 32005 | ConnMan DNS proxy stack overflow | — | userspace (not kernel) |

Notes from the record: none of the six had a CVE at leak time; the two
ksmbd bugs do **not** affect Samba/`smbd`; no known in-the-wild
exploitation as of 2026-10-26.

- **2026-10-20** — ZDI sends the ConnMan report (ZDI-CAN-32005) to the
  public ConnMan mailing list.
  Sources: <https://lkml.iu.edu/2610.2/14824.html> ·
  <https://www.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws/>
- **2026-10-21** — ZDI sends the five kernel reports (33367, 33774,
  33549, 34068, 34076) to security@kernel.org with public lists copied.
  The 33367 mail includes the full analysis, the exploit-chain
  description, and the harmless-scratch validator transcript.
  Sources: <https://lkml.iu.edu/2610.2/14824.html> ·
  <https://www.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws/>

## Aftermath: 2026-10-22 → 2026-10-26

- **2026-10-22** — Zizhen Liu posts
  "[PATCH v2 net] net: skbuff: propagate shared-frag marker in
  skb_zerocopy()" — the 2-line fix, `Fixes: af2806f8f90a` +
  `f4c50a4034e6`, Reviewed-by Eric Dumazet, Cc stable.
  **Unmerged upstream as of 2026-10-26.**
  Source: <https://lists.openwall.net/netdev/2026/10/22/204>
- **2026-10-22** — Eric Dumazet replies on LKML: the report was cut for
  length, no patch was visible in it, and "We were fortunate to receive
  a report with a patch from another source one week ago. Patch will be
  available soon." — the kernel team had its own report ~1 week before
  the leak.
  Source: <https://lkml.iu.edu/2610.2/15245.html>
- **2026-10-22** — TuxCare publishes the repro matrix: root via the
  public PoC on AlmaLinux 8/9/10 (*with the Dirty Frag fix installed*),
  CloudLinux 9/10, Debian 12/13, Ubuntu 24.04/26.04 (bypassing Ubuntu's
  AppArmor userns restriction); CentOS 6/7 not affected.
  Source: <https://tuxcare.com/blog/zdi-ksmbd-bugs-cve/>
- **2026-10-23** — AlmaLinux ships testing kernels: AL8
  `kernel-4.18.0-553.177.2.el8_10`, AL9 `kernel-5.14.0-687.59.2.el9_8`,
  AL10 `kernel-6.12.0-211.68.2.el10_2`; CloudLinux posts its advisory.
  KernelCare livepatch: EL10 out, EL9 in review, EL8 in progress.
  Sources: <https://almalinux.org/blog/2026-10-23-zdi-can-33367/> ·
  <https://blog.cloudlinux.com/zdi-can-33367/>
- **2026-10-24** — Sysdig TRT publishes detection and mitigation
  guidance: runtime rule "Page Cache Poisoning via Spliced File Pages to
  Loopback" (distinctive single-process sequence: userns+netns unshare →
  nlmon up → XFRM state → NFQUEUE rule → tc pedit+redirect → splice to
  127.0.0.1); confirms no CVE assigned and no known in-the-wild use;
  ranks the six reports for defenders.
  Source: <https://www.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws/>
- **2026-10-26** — this repository is published as a mirror of the
  leak's public record: safe differential detector (`poc/detector.c`),
  in-lab closure against a purpose-built target only (`poc/lpe.c` +
  `lab/rootfs/tools/secretgate.c`), an A/B kernel lab whose delta is
  exactly the 2-line fix, the propagation-gap audit, and these docs.
  Ethics posture: analysis + safe oracle + in-lab closure only; no
  weaponized turnkey exploit; no real-world binary targeted; prior art
  attributed to ZDI, Zizhen Liu, Hyunwoo Kim, Sysdig TRT, and TuxCare.

## Where things stand (as of 2026-10-26)

- Fix: posted (v2, reviewed), **not merged**, no distribution has it in
  a released kernel.
- CVE: **none assigned** for any of the six leaked reports.
- Exploitation: public PoC circulates; no known in-the-wild use.
- Defenders: apply the mitigations in
  [report-ptes §7](report-ptes.md#7-reporting) now; patch when vendors
  ship the `skb_zerocopy()` fix — and do not count CVE-2026-90049's fix
  as coverage.
