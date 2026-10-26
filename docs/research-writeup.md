# Research Writeup — ZDI-CAN-33367

The investigation narrative: method, family lineage, dead ends, detector
and audit design, and portable lessons. Companion documents: the one-page
datasheet ([finding-sheet](finding-sheet.md)), the structured
[PTES report](report-ptes.md), and the
[leak timeline](leak-timeline.md). Status claims dated as of 2026-10-26.

## 0. Method: the diff is the spec

This bug has no CVE record to distrust — as of 2026-10-26 it has no CVE
at all. What it does have is better: a two-line fix on netdev, and the
public ZDI report. The method is the same as in our sibling repo
([CVE-2026-31431](https://github.com/FranklinF25/cve-2026-31431),
"Copy Fail"): **start from the diff and the affected sources; treat every
prose description as a hint, not evidence.** The primary sources were
cached locally (`odd/research/`, 9 files) and every load-bearing claim in
these documents traces to one of them.

The fix diff is unusually informative for two lines. Read carefully, it
gives you:

1. **The exact lossy statement** — `skb_zerocopy()` assigns
   `skb_shinfo(to)->nr_frags = j;` and returns without merging
   `skb_shinfo(from)->flags & SKBFL_SHARED_FRAG` into the destination.
   One `|=` is the entire fix.
2. **The vulnerable window, by construction** — the `Fixes:` tags name
   *both* parents of the bug: `af2806f8f90a` (introduced the lossy
   transfer, ~3.14) and `f4c50a4034e6` (the Dirty Frag fix that created
   a consumer trusting the marker). A kernel is vulnerable precisely
   when it contains the second and not the patch. That predicate *is*
   the A/B lab delta and the detector's differential.
3. **A contrast hiding in the context lines** — immediately after the
   insertion point, the pre-existing code propagates `from->unreadable`
   across the same transfer. Fragment metadata made it across;
   the ownership marker did not. Whenever a fix inserts a missing
   propagation next to a working one, the audit question writes itself:
   what else walks the same path?
4. **The oracle, derived before building anything** — if the
   destination loses `SKBFL_SHARED_FRAG`, then `skb_has_shared_frag()`
   is false on an skb whose frags are page-cache pages, so ESP input
   skips `skb_cow_data()` and decrypts in place. The measurable
   behavior is: *bytes a read-only file owns change value after the
   packet processing, while the file was never opened for writing.*
   `poc/detector.c` measures exactly that, on a file the tool owns.

Then measure: the lab (`lab/`) boots the same kernel twice, the delta
being exactly the two-line patch, and runs the detector on both sides.
Expected: `DETECTOR-RESULT: VULNERABLE` on the unpatched side,
`NOT-DETECTED` on the patched side. ZDI's public validator run on
7.3-rc1 already demonstrates the vulnerable side end to end; our lab's
contribution is the differential — the *same* run going quiet with one
line added.

Even the diff's archaeology needed a second look: patch v1 of the fix
carried a wrong first `Fixes:` tag; v2 (2026-10-22) corrected it to
`af2806f8f90a` because "the function did not exist when cef401de7be8 was
merged". The spec is the diff — but verify the diff's own claims by
content, not by trusting its annotations blindly.

## 1. Lineage: one flag, leaked seven times

ZDI-CAN-33367 is not an isolated bug; it is the seventh known failure of
one invariant. The family (page-cache writes via in-place crypto over
splice-backed skb frags):

- **Dirty Pipe** (2022): overwrite `struct pipe_buffer` flags → write
  into any readable file's page cache. The original proof that page-cache
  integrity is a security boundary.
- **Copy Fail** (CVE-2026-31431, our [sibling
  repo](https://github.com/FranklinF25/cve-2026-31431)): AF_ALG AEAD
  decrypts in place into splice-fed tag pages → deterministic 4-byte
  page-cache writes.
- **Dirty Frag** (CVE-2026-43284, Hyunwoo Kim @v4bel; disclosed
  2026-04-30): xfrm-ESP input decrypts in place over splice-pinned frags
  of the *same* skb. Fix `f4c50a4034e6` (netdev 2026-05-07, mainline
  2026-05-08, ≥ v7.1): mark splice-backed frags with `SKBFL_SHARED_FRAG`
  at the datagram-append paths, and make esp4/esp6 take the
  `skb_cow_data()` copy path whenever the marker is set.
- **The seven propagation gaps** (May–Oct 2026): the fix only works if
  *every* path that moves frag descriptors carries the marker along.
  Six CVEs found drops before this bug: CVE-2026-43503 (frag-copy/shift
  helpers `__pskb_copy_fclone`, `skb_shift`), CVE-2026-46300 (coalescing
  via `skb_try_coalesce` — the "Fragnesia" work), CVE-2026-53363 and
  CVE-2026-64566 (IPTFS), CVE-2026-80977 (an error-handling helper), and
  CVE-2026-90049 (an error path inside `skb_zerocopy()` itself).
- **ZDI-CAN-33367**: the seventh drop — the *main* success path of
  `skb_zerocopy()`, reachable from unprivileged userland through
  NFQUEUE (`NFQA_PAYLOAD`) or Open vSwitch upcalls, and converted into a
  page-cache write by ESP in-place decrypt.

The pattern across all seven: the marker is set correctly at the splice
boundary, the consumer (ESP) checks it correctly — and some helper in
between copies descriptors + page references without the flag. A single
invariant, enforced at two ends, with a growing body of middle code that
nobody re-checks. That observation is what our
[audit](../audit/shared-frag-flag-audit.md) systematizes.

## 2. Dead ends and corrected assumptions

Honest dead ends from this investigation, each grounded in the record:

- **"OVS upcalls are the consumer" — incomplete.** Public commentary
  around the leak emphasized Open vSwitch upcalls as the
  `skb_zerocopy()` consumer. That reading makes the bug sound like it
  needs an OVS deployment — a much smaller population. The ZDI chain
  corrected this: nfnetlink_queue's `NFQA_PAYLOAD` audit messages reach
  the same helper from a plain netfilter rule, entirely inside an
  unprivileged user's own network namespace. The general lesson: a
  helper with two known callers has a much wider *reachable* surface
  than its most famous caller — enumerate callers, not headlines.
- **Conflating CVE-2026-90049 with this bug.** During May–Oct 2026 the
  CVE stream already carried an `skb_zerocopy()` entry — the error-path
  gap, CVE-2026-90049. It would be easy to conclude "zerocopy is fixed"
  and move on. It is not: 90049 is a *different* drop on the error path
  of the same function. **A kernel carrying only the 90049 fix is still
  vulnerable to 33367.** This is exactly why we anchor versions to the
  2-line content (or its tree) rather than to "the zerocopy CVE".
- **Choosing the lab base kernel.** The A/B lab needs a base that
  contains `f4c50a4034e6` (else the detector measures Dirty Frag, not
  this bug) but predates the zerocopy fix. Commit-ancestry checks are
  treacherous with the shallow clones everyone uses for speed — a depth
  clone can make a commit *appear* absent or present, and the merge
  topology of `netdev` → mainline can differ from what release tags
  suggest. The lab therefore does not trust ancestry: `build.sh` must
  verify **by content** — grep the built tree for the `f4c50a4034e6`
  marker logic and for the absence of the 2-line fix — before building
  either side. Same lesson as the sibling repo's merge-base trap:
  shallow histories lie; verify the artifact, not the lineage.
- **(Not a dead end, but a boundary we kept)** the escalation. Public
  write-ups project the primitive onto setuid binaries and `/etc/passwd`.
  We left those analytical: the detector already proves the
  permission-boundary crossing, and the in-lab closure
  (`poc/lpe.c` → `secretgate`) proves root impact without ever aiming
  the primitive at a real-world byte.

## 3. Detector design: a differential oracle with clean hands

`poc/detector.c` is the repo's front door, so its design is a statement:

- **Self-owned target.** The primitive's power is "rewrite the page
  cache of anything you can read". An oracle for that must never hold a
  target it does not own — otherwise the security tool is itself the
  abuse. The detector creates its own scratch file (owned by the
  executing euid, mode 0444, inside a directory it created), verifies
  the `open(O_WRONLY)` denial it expects, and refuses to operate on any
  file or directory not owned by the current euid. The differential
  stays crisp because the file is *read-only but self-owned*: the only
  boundary crossed is the one the bug breaks.
- **Self-contained crypto.** The chain needs a correctly keyed,
  authenticated ESP packet, which means computing `cbc(aes)` +
  `hmac(sha256)` transforms for the pedit-crafted linear prefix. The
  detector uses AF_ALG — the kernel's own userland crypto socket — for
  this self-check, so the tool has zero external dependencies and
  compiles `gcc -static` anywhere; no openssl, no host toolchain
  assumptions. (A pleasing coincidence: AF_ALG is the very interface
  broken by the sibling bug.)
- **Explicit verdicts, explicit hygiene.** Output is machine-checkable
  (`DETECTOR-RESULT: VULNERABLE|NOT-DETECTED`) and carries `DISKCLEAN`
  evidence — the file's SHA-256 and an eviction (fadvise) cycle proving
  the *disk* copy never changed, only the cached page.
- **Expected results** (the A/B predicate from §0): `VULNERABLE` on a
  tree with `f4c50a4034e6` but without the 2-line fix; `NOT-DETECTED`
  once the fix is applied. Both sides use the identical trigger code —
  the delta is the kernel, not the test.

## 4. Audit design: an invariant is N propagation surfaces

`f4c50a4034e6` did something subtler than fix a bug: it established an
**invariant** — "every skb frag whose pages are shared (e.g. splice-
backed page cache) carries `SKBFL_SHARED_FRAG`" — and then delegated
enforcement to *every future producer and transfer of fragment
descriptors*. Consumers (esp4/esp6 input) now trust a single flag bit.
That conversion is what made the class systemic:

- every helper that copies, shifts, coalesces, or re-homes frag
  descriptors is a **propagation surface**: if it moves the pages but
  not the marker, it silently downgrades a shared-frag skb into a
  "private" one;
- error paths count double, because they move descriptors under
  exceptional control flow that no happy-path test exercises — two of
  the seven gaps live on error paths (CVE-2026-80977, CVE-2026-90049);
- the surface keeps growing: zero-copy machinery, device-memory frags,
  and the ongoing hardening around `skb_zerocopy()` (an Oct-2026 netdev
  series converting a `BUG_ON` to `-EFAULT`) all touch the same
  descriptor plumbing.

Seven gaps in five months is the empirical argument that patch-by-patch
hardening cannot converge. [audit/shared-frag-flag-audit.md](../audit/shared-frag-flag-audit.md)
pins a tree, walks every frag-transfer helper in `net/core/skbuff.c`
and its callers (nfnetlink_queue, af_packet, OVS) with the single
question "does it preserve / need the marker?", gives a verdict per
helper — and, following the sibling repo's honest-negative tradition,
will publish a clean bill if no eighth gap is found rather than
overselling a near miss.

## 5. Prior work and what is ours

| Aspect | Prior work | This repo |
|---|---|---|
| Vulnerability report, chain, validator demo | ✔ Trend Micro ZDI (LKML, 2026-10-21; public by accident) | referenced and decoded; not copied |
| The 2-line fix | ✔ Zizhen Liu (netdev v2, 2026-10-22; Reviewed-by Eric Dumazet) | lab delta = exactly this patch |
| Dirty Frag prior art + the shared-frag fix | ✔ Hyunwoo Kim @v4bel (CVE-2026-43284; fix `f4c50a4034e6` with Kuan-Ting Chen's approach) | lineage + audit foundation |
| Repro matrix across distributions | ✔ TuxCare (2026-10-22) | cited as the exposure evidence |
| Runtime detection rule | ✔ Sysdig TRT (2026-10-24) | `detect/` Falco rule — original adaptation, attributed |
| Safe differential detector on self-owned files | — | ✔ `poc/detector.c` (independent implementation) |
| A/B kernel lab, delta = the 2-line patch, content-verified | — | ✔ `lab/` |
| LPE closure vs purpose-built target only | — | ✔ `poc/lpe.c` + `lab/rootfs/tools/secretgate.c` (expected: `LPE-RESULT: ROOT-FLAG-CAPTURED` in-lab) |
| Systematization of all 7 gaps + hunt for the 8th | partially (individual CVEs) | ✔ `audit/shared-frag-flag-audit.md` |
| Dated chronology of the leak itself | scattered threads | ✔ [leak-timeline](leak-timeline.md) |

The public PoC already circulates via LKML — that is part of the record
we mirror. Our code is an independent, safety-constrained implementation,
not a reproduction of the leaked exploit.

## 6. Portable lessons

1. **Ownership markers must survive every descriptor transfer.** A flag
   on `shinfo` is only as strong as the weakest memcpy of the
   descriptors it describes. Whenever a fix communicates through a
   marker bit, enumerate the transfers — don't wait for attackers to.
2. **A fix that adds an invariant creates N propagation surfaces.**
   Post-fix hardening is a survey problem, not a patch problem: seven
   gaps in five months, two of them on error paths, is what an
   unaudited invariant looks like.
3. **Leaked-before-fixed flips the defenders' playbook.** With the CC
   mistake, three PoCs were public before fixes existed and before any
   CVE was assigned. Defenders must track ZDI IDs and vendor advisories,
   and mitigate by exposure (userns restrictions, module blocklists,
   seccomp defaults) instead of waiting for scanner signatures.
4. **The safe-oracle pattern scales across this bug family.** Self-owned
   read-only target + derived trigger + machine-checkable verdict gives
   a binary answer with clean hands — reused here from the sibling repo,
   and applicable to any "write across a permission boundary" primitive.
5. **Verify commits by content, not ancestry or annotation.** A wrong
   `Fixes:` tag survived to patch v1; shallow clones make ancestry
   checks unreliable; the lab trusts greps of the tree it builds.

## References

- ZDI report (LKML, 2026-10-21):
  <https://lkml.iu.edu/2610.2/14824.html> (cached: `odd/research/zdi-lkml-report-33367.txt`)
- Fix v2, Zizhen Liu (netdev, 2026-10-22):
  <https://lists.openwall.net/netdev/2026/10/22/204> (cached: `odd/research/netdev-v2-propagate-shared-frag.txt`)
- Eric Dumazet's LKML reply (2026-10-22):
  <https://lkml.iu.edu/2610.2/15245.html> (cached: `odd/research/dumazet-lkml-reply.txt`)
- Dirty Frag write-up, Hyunwoo Kim:
  <https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md> (cached: `odd/research/dirtyfrag-writeup.md`)
- Sysdig TRT (2026-10-24):
  <https://www.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws/>
- TuxCare repro matrix (2026-10-22): <https://tuxcare.com/blog/zdi-ksmbd-bugs-cve/>
- AlmaLinux testing kernels (2026-10-23):
  <https://almalinux.org/blog/2026-10-23-zdi-can-33367/>
- CloudLinux: <https://blog.cloudlinux.com/zdi-can-33367/>
- Sibling repo (Copy Fail, CVE-2026-31431):
  <https://github.com/FranklinF25/cve-2026-31431>
