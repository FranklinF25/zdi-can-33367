# ZDI-CAN-33367 Lab — QEMU A/B kernel harness

Reproducible QEMU lab that boots **two** kernels built from the same
pinned mainline tree and runs the ZDI-CAN-33367 differential oracle on
each: the safe detector (`poc/detector.c`) and the in-lab LPE closure
(`poc/lpe.c`, aimed only at the lab's own purpose-built SUID target).

| Flavor | Source | Meaning |
|---|---|---|
| `vuln` | pristine **v7.2** tarball | Dirty Frag fix `f4c50a4034e6` present, `skb_zerocopy()` fix absent → VULNERABLE |
| `patched` | vuln + [`patches/0001`](kernel/patches/0001-net-skbuff-propagate-shared-frag-marker.patch) | the netdev v2 fix — exactly **2 added lines** → NOT-DETECTED |

The delta between the two kernels is asserted by the build to be exactly
the vendored 2-line fix (`lab/out/ab-diffstat.txt`: `net/core/skbuff.c |
2 ++`): the A/B isolates the single upstream fix under test and nothing
else. Both flavors share the identical config fragment on top of
`x86_64_defconfig`.

**Why v7.2:** the Dirty Frag fix `f4c50a4034e6` merged 2026-05-07
(mainline ≥ v7.1), and the `skb_zerocopy()` propagation fix is still
unmerged as of 2026-10-26 — so v7.2 is a tag that satisfies both sides of
the differential.

## Prerequisites

Docker (no host gcc/qemu needed). `/dev/kvm` is used automatically when
present (`--device /dev/kvm -enable-kvm -cpu host`); otherwise TCG
(`-cpu max`). A TCG retry only happens if KVM produces no kernel output.

## Build (one command)

```sh
lab/scripts/build.sh
```

Wraps itself in Docker (image `zdi-can-33367-lab` from `lab/Dockerfile`),
downloads the pinned kernel tarball
(`https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.2.tar.xz`),
verifies both content facts (below), builds both kernels sequentially,
compiles the static tools (`poc/detector.c`, `poc/lpe.c`,
`lab/rootfs/tools/secretgate.c`), packs the busybox initramfs, and
creates the ext4 probe disk. Progress: `lab/out/logs/build-*.log`.

Idempotent: finished `bzImage`s are skipped; `FORCE=1 lab/scripts/build.sh`
rebuilds. Optional content pin: `KSHA256=<sha256> lab/scripts/build.sh`
(the observed digest is always recorded in `lab/out/kernel-tarball.sha256`).
Artifacts in `lab/out/`: `bzImage-vuln`, `bzImage-patched`,
`initramfs.cpio.gz`, `probe.img`, `detector`, `lpe`, `secretgate`,
`ab-diffstat.txt`, `content-verify.txt`, `kernel-tarball.sha256`,
`logs/serial-<flavor>.txt`.

## Why content verification (not ancestry)

The tree arrives as a release tarball — there is no commit graph to ask
"is `f4c50a4034e6` an ancestor / is the v2 fix absent" (a shallow git
fetch would have no ancestry either). `build.sh` therefore asserts the
two facts on the source bytes and aborts loudly otherwise:

1. **Dirty Frag fix present** — the `SKBFL_SHARED_FRAG` marker-setting
   code exists in the splice→socket append path of both IP stacks
   (`net/ipv4/ip_output.c`, `net/ipv6/ip6_output.c`; in v7.2 at lines
   1233 and 1797 respectively). This is what makes spliced page-cache
   frags carry the shared marker on the *sending* path.
2. **zerocopy fix absent** — the body of `skb_zerocopy()` in
   `net/core/skbuff.c` does not reference `SKBFL_SHARED_FRAG` (the v2
   fix is the only thing that would add it).

One application note: the vendored patch hunk carries trailing context
from the in-flight devmem series (`from->unreadable`), which is not in
v7.2, so `git apply` rejects it — and `patch -F3` measured against the
real v7.2 tree **misplaces** the line into `skb_copy_and_csum_dev()`.
`build.sh` therefore applies, in order: `git apply` (works on any tree
that has the devmem context), then a trimmed-context variant via
`patch -F0` (only the 3 absent trailing context lines removed), then a
deterministic awk insertion whose bytes are extracted from the vendored
patch's own `+` lines. Whichever path runs, the build then verifies
**byte-exactly** that the tree delta is the two vendored lines and that
the propagation line sits inside `skb_zerocopy()` exactly once
(`lab/out/ab-diffstat.txt`).

## Run

```sh
lab/scripts/run.sh vuln     # BOOT=ok DETECTOR=vulnerable   LPE=root            DISKCLEAN=ok VERDICT=ok
lab/scripts/run.sh patched  # BOOT=ok DETECTOR=not-detected LPE=not-vulnerable  DISKCLEAN=ok VERDICT=ok
```

Each boot attaches the 8 MB ext4 probe disk (virtio). `lab/rootfs/init`
stages the SUID `secretgate` on it and bind-mounts it over `/usr/bin` so
the allowlisted path `/usr/bin/secretgate` is a real, splice-able file,
then runs the oracle as uid 1000 (busybox `setpriv`). Exit 0 = the
flavor behaved as its row promises.

The disk-clean proof runs outside the guest after each boot: `debugfs`
reads `/labbin/secretgate` straight from the ext4 blocks (no page cache
involved) and it must equal the built binary — the attack writes the
page cache only, on both flavors.

## Observed output

**expected — populated by the verification runs** (the sections below
describe what the deterministic markers look like; this repository does
not claim observed evidence until the runs are recorded here).

Expected `vuln` serial tail:

```
LAB-BOOT-OK 7.2 FLAVOR=vuln
PROBE-DISK ext4 /dev/vda
SG-STAGED path=/usr/bin/secretgate backing=ext4:/labbin/secretgate mode=4755
RUNAS setpriv uid=1000
DETECTOR-RESULT: VULNERABLE ...
DETECTOR-RC=0
LPE-START uid=1000 euid=1000 target=/usr/bin/secretgate gate_off=...
LPE-SHA256-BEFORE ...
LPE-CRYPTO aes128=PASS sha256=PASS
LPE-USERNS unshare=OK uid=0 euid=0 (ns-root, fresh netns)
LPE-NETNS lo=up(...) nlmon0=up(...)
LPE-NFT table=zfq chain=outq hook=LOCAL_OUT queue=0
LPE-NFQ queue=0 copy_mode=PACKET copy_range=65535 flags=GSO|UID_GID
LPE-PROBE packet_id=1 nfq_msglen=618 frag_start=96
LPE-GEOM msg_len=618 ct_len=544 fso=38 pedit_keys=24 vector=514
LPE-XFRM state=127.0.0.1-esp-0x33360001-transport ...
LPE-TC device=nlmon0 hook=egress classifier=u32 pedit_keys=24 redirect=lo status=PASS
LPE-SELFTEST inner_udp=received (len=528)
LPE-TRIGGER sent=522 target_spliced=8 vector_spliced=514
LPE-DIVERGED yes (bytes 474154454f50454e)          <- "GATEOPEN"
LPE-SHA256-AFTER ...
LPE-EXEC SECRETGATE euid=0 gate=GATEOPEN
LPE-RESULT: ROOT-FLAG-CAPTURED flag{zerofrag-lpe-in-lab}
LPE-RC=0
LAB-DONE
```

Expected `patched` differences (same chain runs, same decrypt fires, but
`skb_zerocopy()` propagated the marker so esp4 input copies the frags):

```
DETECTOR-RESULT: NOT-DETECTED ...
LPE-DIVERGED no (bytes 474154454c4f434b)           <- still "GATELOCK"
LPE-EXEC SECRETGATE euid=0 gate=GATELOCK
LPE-RESULT: NOT-VULNERABLE (no page-cache divergence — skb_zerocopy() propagated SKBFL_SHARED_FRAG)
LPE-RC=1
```

(The exact `frag_start`/`gate_off` numbers depend on the built binaries
and kernel message layout; `618/544/38/24/514` is the geometry observed
in ZDI's 7.3-rc1 transcript and is re-measured at runtime by the probe.)

## Detector details

`poc/detector.c` (canonical source; compiled statically into the
initramfs) is this repo's **safe oracle** for the same primitive,
operating only on files it creates itself. Its design, protocol
(`DETECTOR-RESULT: VULNERABLE|NOT-DETECTED`, `DETECTOR-DISK` evidence)
and exit codes are documented in that file and in the repo README's
verification matrix.

## LPE closure details

`poc/lpe.c` re-runs the same chain but aims the 8-byte write at exactly
one hard-coded target — `/usr/bin/secretgate` (allowlist: path +
`S_ISREG` + `S_ISUID` + root-owned, verified before anything else) —
rewriting its gate magic `GATELOCK` → `GATEOPEN` in the page cache, then
execs the SUID binary as uid 1000, which reads the root-only flag.
Exit codes: 0 = `ROOT-FLAG-CAPTURED`, 1 = `NOT-VULNERABLE`,
2 = `FAILED`. It sets no capabilities and needs none.

## Timings

TBD — populated by the verification runs (budget: Docker image build a
few minutes; tarball download ~145 MB; each kernel build the dominant
cost; each boot + oracle a few seconds with KVM, more under TCG).

## Notes

- The netdev v2 fix was still **unmerged** as of 2026-10-26 and no CVE
  had been assigned; the public PoC already circulates via the LKML
  disclosure. This lab is for defensive research and education only.
- Container jobs run as root, so `lab/out/` and `lab/kernel/src/`
  contents are root-owned on the host (both are gitignored). Clean them
  with:
  `docker run --rm -v "$PWD:/work" zdi-can-33367-lab rm -rf /work/lab/out /work/lab/kernel`
- The Dockerfile omits `libssl-dev`: the lab config builds with
  `CONFIG_MODULES=n`, which drops `CONFIG_MODULE_SIG` and its
  sign-file openssl dependency. If a future re-pin needs openssl
  headers, add the package back.
- If busybox lacks the `setpriv` applet, init runs the oracle directly
  (the tools still drop privileges internally where required).
