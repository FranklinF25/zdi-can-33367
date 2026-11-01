# ZDI-CAN-33367 — Falco detection rules for the page-cache poisoning sequence

Original Falco adaptation of the detection approach published by the Sysdig
Threat Research Team for **ZDI-CAN-33367** (Linux kernel `skb_zerocopy()`
drops `SKBFL_SHARED_FRAG` → ESP in-place decrypt over splice-backed
page-cache pages → local root). See their post, "Detecting and mitigating
ZDI-CAN-33367 and five other Linux flaws" (2026-10-24), whose commercial
rule **"Page Cache Poisoning via Spliced File Pages to Loopback"** matches
the full syscall sequence in Sysdig Secure. That rule is not part of the open
Falco feeds; the rules here are an independent, honest approximation for
stock open-source Falco, with attribution.

## The signal

Nothing legitimate does all of this from a single unprivileged process
(per Sysdig TRT):

1. `unshare(CLONE_NEWUSER|CLONE_NEWNET)`, then sysctl writes
2. bring up an `nlmon` interface
3. install XFRM state over netlink
4. add an nftables NFQUEUE rule
5. attach a `tc` `pedit` action with a redirect
6. `splice()` from a file into a socket on `127.0.0.1` — the trigger that
   lands the in-place decrypt over the page cache

Stock Falco evaluates single events with no cross-event state, so the full
sequence cannot be expressed as one community rule. We split it into:

- **prep rule** (Warning): unprivileged `unshare` creating user and/or
  network namespaces — broad, use for context and tuning;
- **trigger rule** (Critical): unprivileged `splice()` touching a
  loopback (`127.0.0.1`) socket — rare on its own, very high signal when
  it follows the prep events from the same process.

Tune the pair per site (see below). If you run Sysdig Secure, prefer the
original TRT rule, which matches the whole sequence.

## Install

```bash
# validate + load locally
falco -c /etc/falco/falco.yaml \
      -I falco/zdi-can-33367-page-cache-poisoning.yaml

# or drop the file in your custom-rules dir and restart falco
cp falco/zdi-can-33367-page-cache-poisoning.yaml /etc/falco/rules.d/
```

Requires a recent Falco (0.36+) with a syscall source (kernel module,
modern eBPF probe, or gVisor/Modern BPF). Fields used: `evt.type`,
`evt.dir`, `evt.arg.flags`, `user.uid`, `proc.name`, `proc.exepath`,
`fd.name`, `fd.type`.

## Tuning

- **False positives on the prep rule**: rootless container runtimes,
  some browsers and build tools legitimately create user namespaces. Treat
  it as context; alert on it only for hosts where unprivileged userns is
  supposed to be disabled (`user.max_user_namespaces=0`), where it then
  indicates policy bypass attempts.
- **False positives on the trigger rule**: rare, but audit anything that
  legitimately `splice()`s files into loopback sockets (some proxies,
  databases, or test harnesses). Add exclusions by `proc.name` /
  `proc.exepath` after verifying them.
- **Netlink fd naming varies** across Falco versions and probes, which is
  why the rules do not key on XFRM/NFQUEUE netlink writes directly. A
  commented stricter variant is included for sites where `fd.name` renders
  netlink sockets (`nl:...`); validate before enabling.
- **Docker/OCI**: with seccomp `RuntimeDefault`, step 1 is blocked
  outright — a good complement, not a substitute for detection.

## Limits

- Single-event semantics only: the prep rule fires on any unprivileged
  userns `unshare`; the trigger rule fires on the rare splice-to-loopback
  shape. Sequence correlation across the six steps is what the Sysdig
  Secure rule adds.
- No claim of coverage for variants that avoid loopback or splice
  (e.g. other in-place crypto consumers of shared frags).
- Test on hosts you own. Do not run the public PoC against production
  systems to validate detections — use a disposable VM or this repo's
  QEMU lab.

## Attribution

- Sequence and detection concept: Sysdig Threat Research Team, rule
  "Page Cache Poisoning via Spliced File Pages to Loopback"
  (Sysdig Secure Runtime Behavioral Analytics, 2026-10-24) —
  <https://www.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws/>
- Vulnerability analysis and public PoC: Trend Micro ZDI (LKML, 2026-10-21) —
  <https://lkml.iu.edu/2610.2/14824.html>
- Fix: Zizhen Liu, "[PATCH v2 net] net: skbuff: propagate shared-frag
  marker in skb_zerocopy()" (netdev, 2026-10-22; merged upstream as
  `79dc34beb1fd`, verified 2026-11-01; stable backports pending) —
  <https://lists.openwall.net/netdev/2026/10/22/204>

Rules licensed under the Falco repository's terms (Apache-2.0), consistent
with the Falco rules ecosystem.
