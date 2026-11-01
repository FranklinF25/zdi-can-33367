# Leak Timeline — ZDI-CAN-33367 and the 2026-10-20/21 disclosure

A dated chronology of the leak and its aftermath, built strictly from the
public record cached in `odd/research/`. Companion docs:
[report-ptes](report-ptes.md) · [research-writeup](research-writeup.md).
Status as of **2026-11-01**.

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
exploitation as of 2026-11-01.

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

## Aftermath: 2026-10-22 → 2026-11-01

- **2026-10-22** — Zizhen Liu posts
  "[PATCH v2 net] net: skbuff: propagate shared-frag marker in
  skb_zerocopy()" — the 2-line fix, `Fixes: af2806f8f90a` +
  `f4c50a4034e6`, Reviewed-by Eric Dumazet, Cc stable.
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
- **2026-10-23** — Jakub Kicinski commits the fix to the networking
  (net) tree, tagged for the stable kernels.
  Sources: <https://tuxcare.com/blog/zdi-ksmbd-bugs-cve/> ·
  <https://shahidmalla.com/blog/zdi-can-33367-linux-kernel-root-exploit>
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
- **2026-10-26/27** — Fedora ships the fix **ahead of upstream stable**:
  F43 `kernel-7.2.13-100` and F44 `kernel-7.2.13-200` carry the fix
  backported atop v7.2.13 (changelog 2026-10-26).
  Source: <https://linuxsecurity.com/advisories/fedora/fedora-43-kernel-2026>
- **2026-10-28** — AlmaLinux moves fixed kernels to **production**
  repositories for every supported release: AL8
  `kernel-4.18.0-553.178.1.el8_10`, AL9 `kernel-5.14.0-687.60.1.el9_8`,
  AL10 `kernel-6.12.0-211.69.1.el10_2`.
  Sources: <https://almalinux.org/blog/2026-10-23-zdi-can-33367/> ·
  <https://ctipilot.ch/entries/2026-10-25/zdi-linux-kernel-reports-public-skb-zerocopy-root-exploit/>
- **2026-10-29** — NVR trap documented: Rocky Linux 9.8 ships
  `kernel-5.14.0-687.60.1.el9_8` — the *same NVR* as the fixed AlmaLinux
  kernel — **without** the fix (verified via rpm changelog); judge fixed
  kernels by changelog, not NVR.
  Source: <https://community.centminmod.com/threads/add-cmsec-zdi-can-33367-skb_zerocopy-kernel-check-in-132-00stable.33328/>
- **2026-10-30** — upstream stable releases **7.2.14 and 7.3.1 ship
  without the fix** (verified in their ChangeLogs) — the `Cc: stable`
  backport is still pending. KernelCare livepatch out for EL9/EL10 on
  AlmaLinux, CloudLinux, RHEL, Oracle, Rocky; EL8 ready for release;
  Debian/Ubuntu in progress (status 2026-10-27).
  Sources: <https://cdn.kernel.org/pub/linux/kernel/v7.x/ChangeLog-7.2.14> ·
  <https://cdn.kernel.org/pub/linux/kernel/v7.x/ChangeLog-7.3.1> ·
  <https://tuxcare.com/blog/zdi-ksmbd-bugs-cve/>
- **2026-10-30** — Kyle Zeng (OpenAI) discloses a **new bug in the same
  root class** on netdev: "net: gro: avoid parsing headers from shared
  fragments" — GRO parses headers directly from frag0 when the linear
  head is empty, and `SKBFL_SHARED_FRAG` pages are writable through a
  file mapping, so validated headers can change before completion →
  KASAN slab-out-of-bounds in `udp6_gro_complete()` as UID 1000 on an
  unmodified kernel, plus a potential write path (UDP checksum/length
  through the invalid offset). Fix v2: disable the frag0 fast path for
  shared frags (`if (headlen || skb_has_shared_frag(skb))`). Not a flag
  *propagation* gap — the audit's honest negative stands — but the same
  "kernel trusts shared-frag bytes" root cause. "The issue was found by
  an LLM."
  Source: <https://lore.kernel.org/netdev/20261031050752.31869-1-kylebot@openai.com/>
- **2026-11-01** — fix **verified present in Linus' mainline tree** as
  `79dc34beb1fd` "net: skbuff: propagate shared-frag marker in
  skb_zerocopy()" (Zizhen Liu, -0/+2); still **no CVE** for any of the
  six leaked reports and no known in-the-wild exploitation; ZDI has not
  published formal advisories for the leak items.
  Source: <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=79dc34beb1fdb3da79753e51e15c68591a2561fe>

## Where things stand (as of 2026-11-01)

- Fix: **merged to mainline** — `79dc34beb1fd`, committed to the net tree
  2026-10-23, verified in Linus' tree 2026-11-01. **Not yet in upstream
  stable releases** (7.2.14/7.3.1 of 2026-10-30 predate it); backport
  tagged for stable.
- Distro rollout: Fedora F43/F44 (2026-10-26/27) and AlmaLinux production
  (2026-10-28) ship fixed kernels; KernelCare livepatch covers EL9/EL10;
  Rocky 9.8 same-NVR kernels do **not** carry the fix; no fixed RHEL
  kernel yet.
- CVE: **none assigned** for any of the six leaked reports.
- Exploitation: public PoC circulates; no known in-the-wild use.
- Follow-up: the 2026-10-30 GRO shared-frag bug (Kyle Zeng) confirms the
  root class outlives gap 7 — see the
  [audit addendum](../audit/shared-frag-flag-audit.md).
- Defenders: apply the mitigations in
  [report-ptes §7](report-ptes.md#7-reporting) now; patch when your
  vendor ships the `skb_zerocopy()` fix — and do not count
  CVE-2026-90049's fix as coverage.
