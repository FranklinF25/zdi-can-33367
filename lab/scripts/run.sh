#!/usr/bin/env bash
# ZDI-CAN-33367 lab runner — boots one flavor in QEMU (inside docker) and
# judges PASS/FAIL from the serial log markers.
#
# Usage: lab/scripts/run.sh <vuln|patched>
#
# Oracle (run inside the guest as uid 1000 by lab/rootfs/init):
#   vuln:    DETECTOR-RESULT: VULNERABLE      + LPE-RESULT: ROOT-FLAG-CAPTURED
#   patched: DETECTOR-RESULT: NOT-DETECTED    + LPE-RESULT: NOT-VULNERABLE
# plus, for both flavors, a block-level disk-clean proof: debugfs reads the
# probe image's SUID secretgate straight from the filesystem blocks (no page
# cache involved); it must equal the built binary — the attack is a
# page-cache-only write.
#
# KVM is used when /dev/kvm exists (passed with --device /dev/kvm,
# -enable-kvm -cpu host); otherwise TCG (-cpu max). If a KVM boot fails to
# reach the boot marker, one TCG retry is attempted. Full serial output is
# captured to lab/out/logs/serial-<flavor>.txt.
set -u

V="${1:-}"
case "$V" in
    vuln|patched) ;;
    *) echo "usage: $0 <vuln|patched>"; exit 2 ;;
esac

LAB="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$LAB/.." && pwd)"
OUT="$LAB/out"
LOGS="$OUT/logs"
IMG=zdi-can-33367-lab

[ -f "$OUT/bzImage-$V" ] && [ -f "$OUT/initramfs.cpio.gz" ] && [ -f "$OUT/probe.img" ] || {
    echo "missing $OUT/bzImage-$V, initramfs.cpio.gz or probe.img — run lab/scripts/build.sh first"
    exit 1
}
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -t "$IMG" "$LAB"

mkdir -p "$LOGS"
LOG="$LOGS/serial-$V.txt"
: >"$LOG"

DEV=""; ACCEL="-cpu max"; MODE=tcg
if [ -e /dev/kvm ]; then
    DEV="--device /dev/kvm"
    ACCEL="-enable-kvm -cpu host"
    MODE=kvm
fi

APPEND="console=ttyS0 panic=-1 oops=panic flavor=$V"

boot_qemu() { # $1=mode $2=accel args $3=device args
    timeout -k 10 240 docker run --rm -i --name "lab-run-$V-$1" $3 \
        -v "$REPO:/work" -w /work "$IMG" \
        qemu-system-x86_64 $2 -m 1G \
        -kernel "lab/out/bzImage-$V" \
        -initrd "lab/out/initramfs.cpio.gz" \
        -drive file=lab/out/probe.img,if=virtio,format=raw \
        -append "$APPEND" \
        -nographic -no-reboot >>"$LOG" 2>&1
}

echo "[run] flavor=$V mode=$MODE log=$LOG"
t0=$(date +%s)
boot_qemu "$MODE" "$ACCEL" "$DEV"
rc=$?
docker rm -f "lab-run-$V-$MODE" >/dev/null 2>&1 || true

# Retry on TCG only when KVM produced no kernel output at all (broken or
# nested /dev/kvm). A guest failure is a real result — do not mask it.
if [ "$MODE" = kvm ] && ! grep -q "Linux version" "$LOG"; then
    echo "[run] KVM produced no kernel output (qemu rc=$rc), retrying with TCG"
    MODE=tcg
    boot_qemu tcg "-cpu max" ""
    rc=$?
    docker rm -f "lab-run-$V-tcg" >/dev/null 2>&1 || true
fi
t1=$(date +%s)

boot=fail detector=absent lpe=absent
grep -q "LAB-BOOT-OK" "$LOG" && boot=ok
grep -q "DETECTOR-RESULT: VULNERABLE" "$LOG" && detector=vulnerable
grep -q "DETECTOR-RESULT: NOT-DETECTED" "$LOG" && detector=not-detected
grep -q "LPE-RESULT: ROOT-FLAG-CAPTURED" "$LOG" && lpe=root
grep -q "LPE-RESULT: NOT-VULNERABLE" "$LOG" && lpe=not-vulnerable

echo "[run] ---- serial tail ($V) ----"
tail -n 20 "$LOG" | sed 's/^/[serial] /'

# Block-level disk-clean proof, OUTSIDE the guest: debugfs reads the probe
# image's SUID secretgate directly from the ext4 blocks. If the attack is
# page-cache-only, the on-disk copy must still equal the built binary —
# on BOTH flavors (on patched the file was never touched at all).
diskclean=absent
if [ "$boot" = ok ]; then
    disk_sha=$(docker run --rm -v "$REPO:/work" -w /work "$IMG" \
        debugfs -R 'cat /labbin/secretgate' lab/out/probe.img 2>/dev/null \
        | sha256sum | cut -d' ' -f1)
    built_sha=$(sha256sum "$OUT/secretgate" 2>/dev/null | cut -d' ' -f1)
    if [ -n "$disk_sha" ] && [ "$disk_sha" = "$built_sha" ]; then
        diskclean=ok
        echo "[run] disk-clean proof: debugfs block read == built binary"
    else
        diskclean=fail
        echo "[run] disk-clean proof FAILED (disk=$disk_sha built=$built_sha)"
    fi
fi

# Per-flavor expectations (the whole point of the A/B):
#   vuln    — detector VULNERABLE, uid 1000 captures the root flag
#   patched — detector NOT-DETECTED, no divergence
verdict=fail
case "$V" in
    vuln)
        [ "$boot" = ok ] && [ "$detector" = vulnerable ] \
            && [ "$lpe" = root ] && [ "$diskclean" = ok ] && verdict=ok
        ;;
    patched)
        [ "$boot" = ok ] && [ "$detector" = not-detected ] \
            && [ "$lpe" = not-vulnerable ] && [ "$diskclean" = ok ] && verdict=ok
        ;;
esac

echo "RESULT flavor=$V mode=$MODE qemu_rc=$rc time=$((t1-t0))s BOOT=$boot DETECTOR=$detector LPE=$lpe DISKCLEAN=$diskclean VERDICT=$verdict"

[ "$verdict" = ok ] || exit 1
exit 0
