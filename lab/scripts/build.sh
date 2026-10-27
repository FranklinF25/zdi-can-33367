#!/usr/bin/env bash
# ZDI-CAN-33367 lab builder.
#
# Builds TWO kernels from ONE pinned mainline tree (v7.2 tarball):
#   vuln    = pristine v7.2  (contains the Dirty Frag fix f4c50a4034e6 but
#             NOT the skb_zerocopy() flag propagation -> VULNERABLE)
#   patched = vuln + lab/kernel/patches/0001 (the netdev v2 fix, exactly
#             2 added lines -> NOT-DETECTED / NOT-VULNERABLE)
#
# Both facts are verified by CONTENT before building (see step 3):
#   (a) SKBFL_SHARED_FRAG marker-setting code present in the ip(6)_append_data
#       splice path (net/ipv4/ip_output.c, net/ipv6/ip6_output.c) == the
#       Dirty Frag fix f4c50a4034e6 ("xfrm: esp: avoid in-place decrypt on
#       shared skb frags", merged 2026-05-07, mainline >= v7.1) is in;
#   (b) skb_zerocopy()'s body in net/core/skbuff.c does NOT propagate
#       SKBFL_SHARED_FRAG == the netdev v2 fix ("net: skbuff: propagate
#       shared-frag marker in skb_zerocopy()", unmerged as of 2026-10-26)
#       is OUT.
#
# WHY CONTENT, NOT ANCESTRY: the tree is fetched as a release tarball (and
# shallow git fetches have no ancestry either) — there is no commit graph
# to test `f4c50a4034e6 is an ancestor` / `the v2 fix is not`. The two
# facts above are exactly what those ancestry checks would establish, so
# we assert them on the source bytes instead, and abort loudly on mismatch.
#
# The vuln..patched delta is asserted to be EXACTLY the vendored 2-line
# diff (step 6). Note: the vendored patch hunk carries trailing context
# from the in-flight devmem series (`from->unreadable`) which is NOT in
# v7.2, so `git apply` rejects it — and `patch -F3` measured against the
# real v7.2 tree MISPLACES the line (into skb_copy_and_csum_dev()). The
# deterministic fallback chain is in step 6; whatever path applies, the
# result is verified byte-exactly against the vendored additions.
#
# Also compiles the lab tools (poc/detector.c when present, poc/lpe.c,
# lab/rootfs/tools/secretgate.c), packs the busybox initramfs, and creates
# the ext4 probe disk.
#
# Idempotent: existing bzImages are skipped (FORCE=1 rebuilds everything).
#
# Host usage:   lab/scripts/build.sh         (auto-wraps itself in docker)
# In container: /work/lab/scripts/build.sh   (detected via /.dockerenv)
set -euo pipefail

LAB="$(cd "$(dirname "$0")/.." && pwd)"     # <repo>/lab
REPO="$(cd "$LAB/.." && pwd)"
KVER=7.2
# Pinned mainline release tarball (single source of truth for both kernels):
KURL="https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-${KVER}.tar.xz"
IMG=zdi-can-33367-lab

# ---------- host wrapper: re-exec inside the container (detached) ----------
if [ ! -f /.dockerenv ]; then
    cd "$REPO"
    docker image inspect "$IMG" >/dev/null 2>&1 \
        || docker build -t "$IMG" lab/
    docker rm -f lab-build >/dev/null 2>&1 || true
    docker run -d --name lab-build -e FORCE="${FORCE:-0}" -e KSHA256="${KSHA256:-}" \
        -v "$REPO:/work" -w /work "$IMG" \
        bash /work/lab/scripts/build.sh
    echo "[build] container 'lab-build' started"
    echo "[build] live progress: lab/out/logs/build.log  or: docker logs -f lab-build"
    rc="$(docker wait lab-build)"
    docker logs lab-build 2>&1 | tail -n 40 || true
    docker rm lab-build >/dev/null
    exit "$rc"
fi

# ---------- everything below runs inside the container ----------
KSRC="$LAB/kernel/src"
TREE="$KSRC/linux-$KVER"
TARBALL="$KSRC/linux-${KVER}.tar.xz"
OUT="$LAB/out"
LOGS="$OUT/logs"
mkdir -p "$OUT" "$LOGS" "$KSRC"

log() { echo "[build $(date +%H:%M:%S)] $*"; }

# 1. Fetch the pinned tarball (idempotent). KSHA256 (optional) pins the
#    content; the observed digest is always recorded for the evidence trail.
if [ ! -f "$TARBALL" ] || [ "${FORCE:-0}" = "1" ]; then
    log "downloading $KURL"
    wget -q -O "$TARBALL" "$KURL"
fi
sha256sum "$TARBALL" | tee "$OUT/kernel-tarball.sha256"
if [ -n "${KSHA256:-}" ]; then
    [ "$(cut -d' ' -f1 "$OUT/kernel-tarball.sha256")" = "$KSHA256" ] || {
        echo "FATAL: tarball sha256 mismatch (expected $KSHA256)"; exit 1;
    }
fi

# 2. Extract a pristine tree when needed. The tree is stateful between the
#    two builds (vuln from pristine, patched after applying the fix), with
#    a marker so re-runs always start a build from the right state.
extract_tree() {
    log "extracting pristine linux-$KVER"
    rm -rf "$TREE"
    mkdir -p "$TREE"
    tar -C "$TREE" --strip-components=1 -xJf "$TARBALL"
    rm -f "$TREE/.lab-patched"
}
if [ ! -f "$TREE/Makefile" ]; then
    extract_tree
elif [ -f "$TREE/.lab-patched" ]; then
    # tree carries the fix: re-extract whenever the vuln image has to be
    # (re)built from pristine, or the base snapshot is missing
    if [ ! -f "$OUT/bzImage-vuln" ] || [ "${FORCE:-0}" = "1" ] || \
       [ ! -f "$OUT/skbuff.c.base" ]; then
        extract_tree
    fi
fi

# 3. CONTENT-VERIFY both kernel facts; abort loudly (this is the whole
#    point of pinning v7.2 — see the header comment).
CV="$OUT/content-verify.txt"
: >"$CV"
fail_cv() { echo "FATAL: $1" | tee -a "$CV"; exit 1; }
skb_func_body() { # print one function body from a kernel source file
    awk '/^skb_zerocopy\(struct sk_buff \*to/{f=1} f{print} f&&/^}/{exit}' "$1"
}
# skbuff.c source for the checks: the live tree while pristine; the frozen
# base snapshot on cached re-runs where the tree already carries the fix
if [ -f "$TREE/.lab-patched" ]; then
    SKBUFF_SRC="$OUT/skbuff.c.base"
    [ -f "$SKBUFF_SRC" ] || fail_cv "patched tree but no base snapshot — rerun with FORCE=1"
else
    SKBUFF_SRC="$TREE/net/core/skbuff.c"
fi
# (a) Dirty Frag fix present: marker-setting code in the splice->socket
#     append path of both IP stacks (verified upstream at
#     net/ipv4/ip_output.c:1233 and net/ipv6/ip6_output.c:1797 in v7.2)
for f in net/ipv4/ip_output.c net/ipv6/ip6_output.c; do
    n=$(grep -c 'skb_shinfo(skb)->flags |= SKBFL_SHARED_FRAG;' "$TREE/$f" || true)
    echo "content-check dirty-frag-marker $f hits=$n" | tee -a "$CV"
    [ "$n" -ge 1 ] || fail_cv "Dirty Frag fix (f4c50a4034e6) marker code missing in $f — wrong tree?"
done
# (b) zerocopy fix absent: skb_zerocopy() must not propagate the marker
n=$(skb_func_body "$SKBUFF_SRC" | grep -c 'SKBFL_SHARED_FRAG' || true)
echo "content-check zerocopy-propagation skb_zerocopy() SKBFL_SHARED_FRAG hits=$n (want 0)" | tee -a "$CV"
[ "$n" -eq 0 ] || fail_cv "skb_zerocopy() already propagates SKBFL_SHARED_FRAG — fix already present?"
# sanity: the helper itself exists in the tree
skb_func_body "$SKBUFF_SRC" | grep -q 'nr_frags = j' \
    || fail_cv "skb_zerocopy() body not found — unexpected net/core/skbuff.c"
log "content verification passed (see lab/out/content-verify.txt)"

# 4. Snapshot pristine skbuff.c for the byte-exact A/B delta assertion.
if [ ! -f "$TREE/.lab-patched" ]; then
    cp "$TREE/net/core/skbuff.c" "$OUT/skbuff.c.base"
fi

# 5. Build a kernel from the current tree state into $1 (bzImage-<name>).
build_variant() {
    local name="$1" t0 t1
    local img="$OUT/bzImage-$name"
    if [ -f "$img" ] && [ "${FORCE:-0}" != "1" ]; then
        log "$name: $img already exists, skipping (FORCE=1 to rebuild)"
        return 0
    fi
    t0=$(date +%s)
    : >"$LOGS/build-$name.log"
    log "$name: mrproper + defconfig + config fragment (log: lab/out/logs/build-$name.log)"
    (
        cd "$TREE"
        make mrproper                                            >>"$LOGS/build-$name.log" 2>&1
        make defconfig                                          >>"$LOGS/build-$name.log" 2>&1
        ./scripts/kconfig/merge_config.sh -m .config \
            "$LAB/kernel/config-fragment"                       >>"$LOGS/build-$name.log" 2>&1
        make olddefconfig                                       >>"$LOGS/build-$name.log" 2>&1
        # every =y symbol from the fragment must survive the merge
        while IFS= read -r want; do
            grep -qx "$want" .config || {
                echo "FATAL: $name: $want not set in final .config"; exit 1;
            }
        done < <(grep -E '^CONFIG_[A-Za-z0-9_]+=y$' "$LAB/kernel/config-fragment")
        # and the no-modules decision must survive too
        grep -qx '# CONFIG_MODULES is not set' .config || {
            echo "FATAL: $name: CONFIG_MODULES is not disabled"; exit 1;
        }
        log "$name: make -j$(nproc) bzImage"
        make -j"$(nproc)" bzImage                                >>"$LOGS/build-$name.log" 2>&1
    )
    cp "$TREE/arch/x86/boot/bzImage" "$img"
    t1=$(date +%s)
    log "$name: built in $((t1 - t0))s -> $img ($(du -h "$img" | cut -f1))"
}

build_variant vuln

# 6. Apply the vendored netdev v2 patch and ASSERT the tree delta is
#    exactly its 2 added lines. (Skip when the tree already carries it —
#    cached re-runs land here with a patched tree and both images.)
PATCHFILE="$LAB/kernel/patches/0001-net-skbuff-propagate-shared-frag-marker.patch"
if [ -f "$TREE/.lab-patched" ]; then
    log "tree already patched, skipping application"
else
log "applying $(basename "$PATCHFILE")"
# Every application path is verified by CONTENT afterwards: tool exit
# codes alone lie on this vendored mail. Measured in this lab: git 2.43
# parses the file as zero diffs yet returns rc=0 (a silent no-op — a
# "git apply succeeded" with an untouched tree), and the trimmed-context
# `patch -F0` variant misses the hunk on GNU patch 2.7. `patch -F3` is
# known to MISPLACE the line into skb_copy_and_csum_dev() and is never
# used. The deterministic path is the awk insertion of the vendored +
# lines (measured byte-exact on v7.2), so it runs FIRST; git apply and
# the trimmed variant stay as content-verified fallbacks for tree drift.
landed() {
    [ "$(skb_func_body "$TREE/net/core/skbuff.c" | grep -cF 'SKBFL_SHARED_FRAG' || true)" -eq 1 ]
}
TAB=$(printf '\t')
sed -n '/^@@/,$p' "$PATCHFILE" | grep '^+' | grep -v '^+++' \
    | sed 's/^+//' >"$OUT/vendored-addlines.txt"
NRFRAGS="${TAB}skb_shinfo(to)->nr_frags = j;"
awk -v nf="$NRFRAGS" -v addfile="$OUT/vendored-addlines.txt" '
    BEGIN { while ((getline l < addfile) > 0) add[nadd++] = l }
    /^skb_zerocopy\(struct sk_buff \*to/ { infn = 1 }
    infn && !done && seen && /^$/ {
        print
        for (i = 0; i < nadd; i++) print add[i]
        done = 1
        next
    }
    infn && $0 == nf { seen = 1 }
    { print }
' "$TREE/net/core/skbuff.c" >"$OUT/skbuff.c.patched"
[ "$(wc -l <"$OUT/skbuff.c.patched")" -ge "$(wc -l <"$TREE/net/core/skbuff.c")" ] \
    || { echo "FATAL: awk application produced a short file"; exit 1; }
mv "$OUT/skbuff.c.patched" "$TREE/net/core/skbuff.c"
if landed; then
    log "applied the vendored + lines with awk (verified in-function)"
elif git -C "$TREE" apply "$PATCHFILE" 2>>"$LOGS/patch.log" && landed; then
    log "git apply succeeded (verified)"
else
    TRIMSTART="^ ${TAB}if (i > 0 && from->unreadable)\$"
    sed -e 's/^@@ -3942,6 +3942,8 @@/@@ -3942,3 +3942,5 @@/' \
        -e "/${TRIMSTART}/,/^ \$/d" \
        "$PATCHFILE" >"$OUT/0001-trimmed-context.patch"
    patch -d "$TREE" -p1 -F0 --no-backup-if-mismatch \
        <"$OUT/0001-trimmed-context.patch" >>"$LOGS/patch.log" 2>&1
    if landed; then
        log "applied via patch -F0 on the trimmed-context variant (verified)"
    else
        echo "FATAL: no application path landed the vendored fix inside skb_zerocopy()"
        exit 1
    fi
fi
touch "$TREE/.lab-patched"
fi

# delta must be exactly the two added lines from the vendored patch
PROP_LINE=$'\tskb_shinfo(to)->flags |= skb_shinfo(from)->flags & SKBFL_SHARED_FRAG;'
diff -u "$OUT/skbuff.c.base" "$TREE/net/core/skbuff.c" >"$OUT/ab-diff.txt" || true
added=$(grep -cE '^\+([^+]|$)' "$OUT/ab-diff.txt" || true)
removed=$(grep -cE '^-([^-]|$)' "$OUT/ab-diff.txt" || true)
[ "$added" -eq 2 ] && [ "$removed" -eq 0 ] || {
    echo "FATAL: vuln..patched delta is not exactly 2 added lines (added=$added removed=$removed)"
    cat "$OUT/ab-diff.txt"; exit 1;
}
grep -qxF "+$PROP_LINE" "$OUT/ab-diff.txt" || {
    echo "FATAL: the added line is not the vendored propagation line"; exit 1;
}
n=$(skb_func_body "$TREE/net/core/skbuff.c" | grep -cF 'SKBFL_SHARED_FRAG' || true)
[ "$n" -eq 1 ] || {
    echo "FATAL: propagation line appears $n times inside skb_zerocopy() (want 1)"; exit 1;
}
{
    echo "net/core/skbuff.c | 2 ++"
    echo "vuln..patched delta = exactly the vendored netdev v2 fix (2 added lines, 0 removed)"
    cat "$OUT/ab-diff.txt"
} >"$OUT/ab-diffstat.txt"
log "A/B delta verified: net/core/skbuff.c | 2 ++ (lab/out/ab-diffstat.txt)"

build_variant patched

# 7. Compile the lab tools (all static).
log "compiling secretgate (SUID target)"
gcc -static -O2 -Wall -Wextra -o "$OUT/secretgate" "$LAB/rootfs/tools/secretgate.c"
mapfile -t HITS < <(grep -aboF -- "$(printf 'GATELOCK')" "$OUT/secretgate" || true)
[ "${#HITS[@]}" -eq 1 ] || {
    echo "FATAL: gate magic found ${#HITS[@]} times in secretgate (want exactly 1)"; exit 1;
}
GATE_OFF="${HITS[0]%%:*}"
log "gate magic \"GATELOCK\" at file offset $GATE_OFF"
log "compiling lpe"
gcc -static -O2 -Wall -Wextra -DGATE_OFF="$GATE_OFF" \
    -o "$OUT/lpe" "$REPO/poc/lpe.c"
if [ -f "$REPO/poc/detector.c" ]; then
    log "compiling detector"
    gcc -static -O2 -Wall -Wextra -o "$OUT/detector" "$REPO/poc/detector.c"
else
    log "poc/detector.c not present yet — installing NOT-DETECTED stub"
    printf '#!/bin/sh\necho "DETECTOR-ABSENT poc/detector.c not built yet"\necho "DETECTOR-RESULT: NOT-DETECTED (stub)"\nexit 1\n' \
        >"$OUT/detector"
    chmod 755 "$OUT/detector"
fi

# 8. Assemble the initramfs: busybox + init + tools + SUID target + flag.
log "assembling initramfs"
IRD="$OUT/initramfs-root"
rm -rf "$IRD"
mkdir -p "$IRD/bin" "$IRD/dev" "$IRD/proc" "$IRD/sys" "$IRD/tools" \
         "$IRD/usr/bin" "$IRD/root" "$IRD/etc" "$IRD/mnt/probe" "$IRD/tmp"
install -m 0755 /bin/busybox "$IRD/bin/busybox"
for app in sh su mount umount poweroff uname echo cat sleep mdev mkdir cp chown chmod grep; do
    ln -sf busybox "$IRD/bin/$app"
done
# busybox setpriv (uid 1000 drop in init) — only if this busybox has it
if /bin/busybox setpriv --help >/dev/null 2>&1; then
    ln -sf busybox "$IRD/bin/setpriv"
    log "initramfs: busybox setpriv applet available"
else
    log "initramfs: busybox setpriv missing; init falls back to direct exec"
fi
install -m 0755 "$LAB/rootfs/init" "$IRD/init"
install -m 0755 "$OUT/detector" "$IRD/tools/detector"
install -m 0755 "$OUT/lpe" "$IRD/tools/lpe"
# SUID-root target (allowlisted path for poc/lpe.c) + root-only flag
install -m 4755 "$OUT/secretgate" "$IRD/usr/bin/secretgate"
printf 'flag{zerofrag-lpe-in-lab}\n' >"$IRD/root/flag"
chmod 0400 "$IRD/root/flag"
printf 'root:x:0:0:root:/root:/bin/sh\nlab:x:1000:1000:lab:/tmp:/bin/sh\n' >"$IRD/etc/passwd"
printf 'root:x:0:\nlab:x:1000:\n' >"$IRD/etc/group"
mknod -m 0600 "$IRD/dev/console" c 5 1
mknod -m 0666 "$IRD/dev/null"    c 1 3
( cd "$IRD" && find . | cpio -o -H newc 2>/dev/null | gzip -9 ) \
    >"$OUT/initramfs.cpio.gz"
log "initramfs: $(du -h "$OUT/initramfs.cpio.gz" | cut -f1)"

# 9. ext4 probe disk: real-fs backing for the SUID target + the detector's
#    scratch file + the block-level disk-clean proof (debugfs in run.sh).
if [ ! -f "$OUT/probe.img" ] || [ "${FORCE:-0}" = "1" ]; then
    log "creating 8M ext4 probe disk"
    dd if=/dev/zero of="$OUT/probe.img" bs=1M count=8 status=none
    mkfs.ext4 -q -F "$OUT/probe.img"
fi

log "ALL DONE — artifacts:"
ls -la "$OUT" | grep -Ev 'initramfs-root|^total'
