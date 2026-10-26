# ZDI-CAN-33367 lab — kernel build + QEMU boot environment.
# One image used for both building (gcc, kernel deps) and running (qemu).
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Kernel-build deps + QEMU + busybox initramfs + e2fsprogs (probe disk,
# debugfs disk-clean proof). No libssl-dev: the lab config builds with
# CONFIG_MODULES=n, which drops CONFIG_MODULE_SIG and the sign-file
# openssl dependency. (If a future kernel pin ever needs openssl headers,
# add libssl-dev back here.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        bc \
        bison \
        flex \
        libelf-dev \
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
