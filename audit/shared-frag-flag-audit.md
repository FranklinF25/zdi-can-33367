# Shared-Frag Flag Audit — `SKBFL_SHARED_FRAG` propagation in the Linux kernel

**Original contribution of this repo.** The Dirty Frag fix (`f4c50a4034e6`,
CVE-2026-43284, mainline ≥ v7.1) turned one bit — `SKBFL_SHARED_FRAG` — into
a security invariant: *"skb frags not privately owned by this skb must carry
the marker"*. Every kernel path that moves fragment descriptors between
socket buffers is a **propagation surface**: move the pages without the bit
and you silently downgrade a shared skb into a "private" one that ESP will
decrypt **in place** over page-cache pages. Seven such drops are publicly
known (ZDI-CAN-33367 is the seventh). This document systematizes the seven
and audits the frag-transfer helpers of a pinned tree for an eighth —
**conclusion first: no eighth gap found in the audited set** (honest
negative, in the sibling repo's tradition), with three near-misses recorded
so the next auditor starts where we stopped.

Status claims dated **as of 2026-11-01** (v7.2 sources fetched
2026-10-26, see [Reproducibility](#reproducibility)). Analysis only; no
exploit code (see each repo doc for the ethics posture).

## The invariant, with v7.2 line evidence

All citations below are from the **pinned tag `v7.2`** of
`git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`, fetched
2026-10-26 into `odd/research/` (sha256s in
[Reproducibility](#reproducibility)).

**Where the marker is SET** — the splice boundary in the datagram append
paths (added by the Dirty Frag fix):

```c
/* net/ipv4/ip_output.c:1229-1233 (__ip_append_data, MSG_SPLICE_PAGES) */
err = skb_splice_from_iter(skb, &msg->msg_iter, copy);
if (err < 0)
        goto error;
copy = err;
if (!(flags & MSG_NO_SHARED_FRAGS))
        skb_shinfo(skb)->flags |= SKBFL_SHARED_FRAG;
```

`net/ipv6/ip6_output.c:1797` carries the identical statement for IPv6.
`MSG_NO_SHARED_FRAGS` is an in-kernel opt-out for callers that know their
frag pages are private.

**Where the marker is CONSUMED** — ESP input decides between a private
copy and in-place authenticated decrypt:

```c
/* net/ipv4/esp4.c:876-890 (esp4_input) */
if (!skb_cloned(skb)) {
        if (!skb_is_nonlinear(skb)) { ... goto skip_cow; }
        else if (!skb_has_frag_list(skb) &&
                 !skb_has_shared_frag(skb)) {      // <-- the trust
                ... goto skip_cow;                  // in-place decrypt
        }
}
err = skb_cow_data(skb, 0, &trailer);               // private copy path
```

`net/ipv6/esp6.c:917-931 (esp6_input)` is the same gate. `skb_cow_data()`
(`net/core/skbuff.c:5369`) is the copier: it pulls frag bytes into a private
head via `__pskb_pull_tail()` (skbuff.c:5380) and/or `pskb_expand_head()`.

**Why transfers are surfaces.** The marker lives in
`skb_shinfo(skb)->flags`, i.e. in the *source* skb. The moment a helper
moves `skb_frag_t` descriptors (page pointers + offsets) into another skb's
`shinfo->frags`, the destination's `flags` field is a *different* word. If
the helper does not explicitly OR the marker in, the destination advertises
"my frags are private" while pointing at splice-backed page-cache pages.
The consumer (ESP) then takes the fast path over storage it does not own.
The seven known gaps are seven different helpers making the same omission.

## The seven known gaps

| # | ID | Dropping path | Discoverer / credit | Fix status as of 2026-11-01 |
|---|---|---|---|---|
| 1 | CVE-2026-43503 | frag-copy/shift helpers: `__pskb_copy_fclone`, `skb_shift` | Hyunwoo Kim (@v4bel) follow-up series (May 2026) | **fix present in v7.2** — verified at skbuff.c:2260 and skbuff.c:4385 (this audit) |
| 2 | CVE-2026-46300 | coalescing: `skb_try_coalesce` ("Fragnesia") | published 2026 | **fix present in v7.2** — verified at skbuff.c:6243 (this audit) |
| 3 | CVE-2026-53363 | IPTFS | published 2026 | fixed per the CVE record; fix lives in the xfrm/IPTFS code, **outside this audit's fetched file set** (not re-verified here) |
| 4 | CVE-2026-64566 | IPTFS | published 2026 | same as #3 |
| 5 | CVE-2026-80977 | an error-handling helper | published 2026 | fixed per the CVE record; **helper not identified by name in the public summaries we hold** — not re-verified here |
| 6 | CVE-2026-90049 | an error path inside `skb_zerocopy()` itself | published 2026 | fixed per the CVE record; plausibly the `BUG_ON` → `-EFAULT` hardening series on net-next (Oct 2026), which postdates v7.2 — **not re-verified here** |
| 7 | **ZDI-CAN-33367** | `skb_zerocopy()` **main success path** | Trend Micro ZDI (report + public PoC via LKML 2026-10-21) | fix = Zizhen Liu's netdev v2 (2026-10-22, Reviewed-by Eric Dumazet, Cc stable) — **MERGED**: net tree 2026-10-23, mainline `79dc34beb1fd` (verified 2026-11-01), stable backport pending. Gap 7 is the subject of this repo |

Operational caveat (worth repeating everywhere): **a kernel carrying only
gap 6's fix is NOT protected against gap 7.** They are different defects in
the same function: an error path and the main success path.

## Original audit: hunting the 8th — every frag-transfer helper in v7.2

Method: in the pinned `net/core/skbuff.c` (v7.2), enumerate every function
that (a) copies or moves `skb_frag_t` descriptors between skbs, (b)
re-parents foreign pages into an skb, or (c) clones/attaches frag lists —
then ask three questions: does it transfer *references* (shared) or *copy
pages* (private)? does it propagate/need the marker? can an unprivileged
user feed it splice-backed frags? Verdicts:

### A. Cross-skb frag-descriptor movers (the real propagation surfaces)

| Helper (v7.2 location) | What it does | Marker handling | Verdict |
|---|---|---|---|
| `skb_zerocopy()` — skbuff.c:3876 | transfers frag descriptors + page refs from `from` to `to` (`skb_frag_ref(to, j)` at :3926; `nr_frags = j` at :3929; returns at :3931) | **none** — the gap | **DROPPED-KNOWN — gap 7 (this bug)** |
| `__pskb_copy_fclone()` — skbuff.c:2225 | copies an skb, optionally reffing the original frags into the copy | `skb_shinfo(n)->flags \|= skb_shinfo(skb)->flags & SKBFL_SHARED_FRAG;` at :2260 | **PRESERVED** (gap-1 fix verified) |
| `skb_shift()` — skbuff.c:4274 | TCP SACK: shifts frag descriptors between adjacent skbs | propagation into `tgt` at :4385 | **PRESERVED** (gap-1 fix verified) |
| `skb_try_coalesce()` — skbuff.c:6172 | GRO/coalescing: memcpy's `from`'s frags into `to` (:6238-6241) | propagation at :6243, guarded by `nr_frags` | **PRESERVED** (gap-2 fix verified) |
| `skb_segment()` — skbuff.c:4777 | GSO software segmentation: builds `nskb`s sharing source frags | ORs marker from `head_skb`/`frag_skb` at :4997-4999 and from list skbs at :5016; additionally re-checks `skb_has_shared_frag(nskb)` at :5070 before allowing no-SG segmentation | **PRESERVED** |
| `skb_split()` — skbuff.c:4231 | splits one skb into two at `len` | `zc_flags = SKBFL_SHARED_FRAG \| SKBFL_PURE_ZEROCOPY` (:4234), propagated into `skb1` (:4238) | **PRESERVED** |

The two unprivileged-reachable **callers** that feed `skb_zerocopy()`:

| Caller (v7.2 location) | Reachability |
|---|---|
| `nfqnl_build_packet_message()` — net/netfilter/nfnetlink_queue.c:954, building the `NFQA_PAYLOAD` attribute | **the unprivileged trigger**: an nftables `queue` rule in the user's own network namespace (ownable via `unshare(CLONE_NEWUSER\|CLONE_NEWNET)`) routes any locally-generated packet through the queue; no queue listener is required — the flag is lost at *message build time*, before any verdict |
| `queue_userspace_packet()` — net/openvswitch/datapath.c:592, building `OVS_PACKET_ATTR_PACKET` | requires an Open vSwitch datapath in the namespace: module loaded in the init namespace and a dp created by a privileged `ovs-vswitchd`. Narrower than NFQUEUE in practice; **same fixed line covers it** — OVS-hosting multi-tenant boxes should treat themselves as exposed |

### B. Same-skb manipulation or page-copying helpers (not propagation surfaces)

| Helper (v7.2 location) | What it does | Verdict |
|---|---|---|
| `__pskb_pull_tail()` — skbuff.c:2875 | pulls frag bytes into the linear head by **copying** (memcpy into private head); shrinks/merges the skb's own frags | N.A. — makes bytes private; it is the mechanism `skb_cow_data()` uses to sanitize |
| `pskb_expand_head()` — skbuff.c:2294 | reallocates the linear head; the whole `shinfo` block — `flags` included — is memcpy'd to the new head (skbuff.c:2322-2324); frags never leave the skb | **PRESERVED** by construction (metadata moves with the frags it describes) |
| `skb_copy_ubufs()` — skbuff.c:1997 | copies ubuf-backed frags into private kernel pages | N.A.-COPIES-PAGES — privatizes by design |
| `skb_copy_expand()` — skbuff.c:2502 | full deep copy | N.A.-COPIES-PAGES |
| `pskb_carve` family — skbuff.c:6993, :7025-7041 | TCP receive carve: splits an skb/frag_list; children keep their own `shinfo`; clones share `shinfo` by design | N.A. — no cross-skb descriptor handoff |
| `skb_clone_fraglist()` — skbuff.c:922 | clones the frag_list (child skbs) of a cloned skb | N.A. — child skbs carry their own marker; clones share `shinfo` with the original |
| `skb_splice_bits()` — skbuff.c:3263 | skb → **pipe** (receive-side splice-out): pages referenced into pipe buffers | N.A. — not an skb→skb transfer (it is the read-side cousin of the planting primitive) |
| `skb_zerocopy_clone()` — called e.g. at skbuff.c:5002 | links zerocopy *destructor metadata* (`ubuf_info`) to a new skb | N.A. — metadata plumbing, not frag transfer; notably it does **not** repair the marker either (the ZDI report makes the same observation) |

### C. TX-side stream append (near-miss, documented)

`skb_zerocopy_iter_stream()` — skbuff.c:1912 — appends pages from a
user iterator into a TCP stream skb via `__zerocopy_sg_from_iter()`
(:1933). It does **not** set `SKBFL_SHARED_FRAG` on the devmem path (as
noted in the Oct-2026 netdev discussion of unreadable frags —
`odd/research/dumazet-lkml-reply.txt` context and the public netdev
thread). Recorded as a **near-miss, not an 8th gap**, for three reasons:
the pages it attaches are user/devmem pages rather than splice-backed
page-cache pages; it is transmit-side, and the known consumption of the
missing marker (esp4/esp6 input in-place decrypt) is receive-side; and
the splice-into-TCP case is marked at the datagram layer
(`ip_output.c:1233` covers `MSG_SPLICE_PAGES` appends). If someone finds
an RX-path consumer that trusts the marker on TX-built skbs, this entry
is where to look first.

## Conclusion — honest negative

**No eighth propagation gap found in the audited set.** Every cross-skb
frag-descriptor mover in the pinned `net/core/skbuff.c` (v7.2) either
propagates `SKBFL_SHARED_FRAG` (five helpers, lines cited above) or is the
known gap 7 (`skb_zerocopy()` main path — fix merged upstream as
`79dc34beb1fd`, stable backport pending). The
remaining candidates copy pages (privatizing) or never move descriptors
across skb boundaries. Near-misses worth keeping on the radar:

1. **`skb_zerocopy_iter_stream()` devmem path** (§C above) — no marker, but
   TX-side with non-page-cache pages today.
2. **OVS upcalls** — same missing line, materially narrower reachability
   than NFQUEUE but present on OVS-hosting hosts.
3. **Error paths generally** — two of the seven known gaps (#5, #6) live on
   error paths; this audit walked the success paths of the helpers above
   with the error branches read but not fuzzed. An 8th gap, if it exists,
   statistically hides there.

Scope limits stated plainly: this audit covered `net/core/skbuff.c` plus
the setter/consumer/caller files fetched for v7.2; IPTFS-internal
transfers (gaps #3-#4) and the error-handling helper of gap #5 were not
re-verified here (their code lives outside the fetched set), and drivers
implementing their own frag re-parenting (not in `skbuff.c`) are out of
scope.

## Post-audit follow-up (2026-10-30): the GRO shared-frag trust bug

Four days after this audit was published, Kyle Zeng (OpenAI) disclosed a
bug on netdev that is **not an 8th propagation gap** — the honest
negative above stands — but proves the root class outlives gap 7:
code that **trusts the contents** of shared frags, not just code that
drops the marker. Recorded here because it is the first public
confirmation that the surface extends past the flag itself.

"[PATCH net v2] net: gro: avoid parsing headers from shared fragments"
(<https://lore.kernel.org/netdev/20261031050752.31869-1-kylebot@openai.com/>,
v1 2026-10-30):

- **Mechanism.** When an skb has an empty linear head,
  `skb_gro_reset_offset()` (`net/core/gro.c`) exposes the first page
  fragment **directly** to GRO's header parsers (the `frag0` fast path).
  For an `SKBFL_SHARED_FRAG` skb, those bytes may still be **writable
  through a file mapping** — so headers validated during receive can
  differ from the headers later copied into the linear head and used
  during completion.
- **Impact.** Changing an IPv6 destination-options length between the
  short and full header fetches in `ipv6_gro_pull_exthdrs()` makes
  `ipv6_gro_complete()` pass an **out-of-bounds offset** to
  `udp6_gro_complete()` — a KASAN slab-out-of-bounds read triggered by a
  userspace reproducer **as UID 1000 on an unmodified kernel**. The same
  completion path writes the UDP checksum and length through the invalid
  offset. The packet carries trusted TCP GSO metadata and spliced file
  data, so it reaches completion without an skb zerocopy destructor or a
  second GRO packet — no second peer required.
- **Fix (v2).** One condition, `+2/-1` in `net/core/gro.c`: disable the
  direct-fragment fast path for skbs with externally writable fragments
  — `if (headlen || skb_has_shared_frag(skb)) return;` — so every header
  is pulled into the linear head before it is inspected
  (`Fixes: dff0b0161ad5`, Cc stable). Unmerged as of 2026-11-01.
- **Two things worth noting for auditors.** First, the fix makes **GRO a
  second consumer of `SKBFL_SHARED_FRAG`** (after ESP): the marker's
  load-bearing surface is growing, which strengthens the case for
  auditing every propagation hop. Second, the report states plainly:
  "The issue was found by an LLM" — with Codex credited for review and
  analysis assistance — an early data point for LLM-assisted kernel
  auditing in exactly this bug class.

## Related-but-different upstream hardening (context, not gaps)

- **`BUG_ON` → `-EFAULT` inside `skb_zerocopy()`** — Josef Bacik's Oct-2026
  netdev series (replaces `BUG_ON(!from->head_frag && !hlen)` with a
  warning + error return; review discussion surfaced that an OVS
  zero-length-packet path can reach the old `BUG_ON` with only
  namespace-scoped `CAP_NET_ADMIN`). Plausibly related to gap #6's CVE; the
  series postdates the v7.2 tag, so it is absent from the fetched tree.
- **Devmem "unreadable frags"** (`65249feb6b3d` lineage) — a *different*
  ownership property (pages the kernel cannot read) with its own flag
  plumbing; the netdev discussion of it is what surfaces the
  `iter_stream` near-miss above. Note for tree-drift auditors: in newer
  trees `skb_zerocopy()` also propagates `from->unreadable` right after
  `nr_frags = j;` — in v7.2 the function still ends at the plain
  `return 0;` (skbuff.c:3929-3931). Quote the tree you audited.

## Reproducibility

Fetch date 2026-10-26; base URL
`https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain`,
ref `h=v7.2`:

```bash
base='https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain'
curl -sL "$base/net/core/skbuff.c?h=v7.2"           -o skbuff-v7.2.c
curl -sL "$base/net/netfilter/nfnetlink_queue.c?h=v7.2" -o nfnetlink_queue-v7.2.c
curl -sL "$base/net/ipv4/ip_output.c?h=v7.2"       -o ip_output-v7.2.c
curl -sL "$base/net/ipv6/ip6_output.c?h=v7.2"      -o ip6_output-v7.2.c
curl -sL "$base/net/ipv4/esp4.c?h=v7.2"            -o esp4-v7.2.c
curl -sL "$base/net/ipv6/esp6.c?h=v7.2"            -o esp6-v7.2.c
curl -sL "$base/net/openvswitch/datapath.c?h=v7.2" -o datapath-v7.2.c
sha256sum skbuff-v7.2.c nfnetlink_queue-v7.2.c ip_output-v7.2.c \
          ip6_output-v7.2.c esp4-v7.2.c esp6-v7.2.c datapath-v7.2.c
```

Expected sha256s (the exact bytes every line citation above was made
against):

```
8984a047424c3d888a88d39008dbdfaeea387771ac601b75bc9515aa0e076c78  skbuff-v7.2.c
cc87eb70fabc1465dc5923e18b8d564b010a0d5ba3109260f7313e7b48a1ccd7  nfnetlink_queue-v7.2.c
33080f6943629efd4deb2126c6c3d13e7d0c38a6ec09158eaa8eed07ec5ef72e  ip_output-v7.2.c
a52475b2e7d6c0d0bf90d03e4c3343ff15ff514c21761de2fe392106722695c8  ip6_output-v7.2.c
9543640893afe7d58973a04106e86f00c2c3c03d9587bc76ad7989838ff6a561  esp4-v7.2.c
649ba22a34663a4f76852ba6918aa4fd6882381d302096624700ac460b1f8b42  esp6-v7.2.c
4196850ed50595a185b00b707a4427c5687fcaae569abae73b89675fd60372f2  datapath-v7.2.c
```

## Attribution

The vulnerability, chain, and validator demo are Trend Micro ZDI's (public
via the accidental LKML CC, 2026-10-21); the 2-line fix is Zizhen Liu's
(netdev v2, 2026-10-22; merged upstream as `79dc34beb1fd`); the Dirty Frag root cause and the shared-frag fix
approach (with Kuan-Ting Chen's patch) are Hyunwoo Kim's (@v4bel); the
"seven gaps" framing follows Sysdig TRT's 2026-10-24 summary. The GRO
shared-frag follow-up (2026-10-30) is Kyle Zeng's (OpenAI). The
helper-by-helper walk, verdict table, near-miss list, and pinned-tree line
evidence are this repo's original work.
