# ZDI-CAN-33367 lab — kernel build + QEMU boot environment.
# One image used for both building (gcc, kernel deps) and running (qemu).
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Kernel-build deps + QEMU + busybox initramfs + e2fsprogs (probe disk,
# debugfs disk-clean proof). libssl-dev: CONFIG_MODULES=n drops the
# sign-file dependency, but x86_64 defconfig still builds certs/extract-cert
# (CONFIG_SYSTEM_TRUSTED_KEYRING), which includes openssl/bio.h — verified
# the hard way in this lab (build died at certs/extract-cert without it).
RUN apt-get update && apt-get install -y --no-install-recommends \
        bc \
        bison \
        flex \
        libelf-dev \
        libssl-dev \
        dwarves \
        cpio \
        gcc \
        make \
        wget \
        xz-utils \
        patch \
        git \
        ca-certificates \
        qemu-system-x86 \
        busybox-static \
        e2fsprogs \
    && rm -rf /var/lib/apt/lists/*

# Kernel trees arrive via bind mount; avoid git "dubious ownership" aborts
# when the mounted repo is owned by a different uid than the container user
# (build.sh also uses plain `git apply` on the tarball tree, which relies
# on safe.directory outside a proper clone).
RUN git config --global --add safe.directory '*'

WORKDIR /work
