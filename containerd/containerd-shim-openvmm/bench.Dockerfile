# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Self-contained benchmark image for containerd-shim-openvmm.
# Bakes in containerd, ctr, the shim binary, the guest agent, a Linux kernel,
# and the alpine test image so the whole thing is portable — just run:
#
#   docker run --rm --privileged --device /dev/kvm <image>
#
# Build via bench-build.sh (which compiles binaries and assembles the image).

FROM docker.io/library/ubuntu:24.04

ARG CONTAINERD_VERSION=2.0.4
ARG RUNC_VERSION=1.2.4
ARG TARGETARCH

# Install containerd + runc + basic tools.
RUN apt-get update -qq && \
    apt-get install -y -qq wget bc >/dev/null 2>&1 && \
    wget -q "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION}-linux-${TARGETARCH}.tar.gz" \
         -O /tmp/containerd.tar.gz && \
    tar -xzf /tmp/containerd.tar.gz -C /usr/local && \
    rm /tmp/containerd.tar.gz && \
    wget -q "https://github.com/opencontainers/runc/releases/download/v${RUNC_VERSION}/runc.${TARGETARCH}" \
         -O /usr/local/bin/runc && \
    chmod +x /usr/local/bin/runc && \
    apt-get remove -y wget && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# NOTE: Alpine image is pulled at runtime (containerd's boltdb metadata
# doesn't survive layer commits, and ctr pull needs mount which isn't
# available during unprivileged docker build).

# Copy in the shim binary, agent binary, and kernel.
COPY containerd-shim-openvmm-v2 /usr/local/bin/containerd-shim-openvmm-v2-real
COPY containerd-shim-agent      /usr/local/share/containerd-shim-agent
COPY vmlinux                    /usr/local/share/vmlinux
COPY initrd.img                 /usr/local/share/initrd.img

# Create a wrapper script that injects the env vars containerd won't pass.
RUN printf '#!/bin/bash\nexport OPENVMM_SHIM_KERNEL=/usr/local/share/vmlinux\nexport OPENVMM_SHIM_AGENT=/usr/local/share/containerd-shim-agent\nexport OPENVMM_SHIM_INITRD=/usr/local/share/initrd.img\nexec /usr/local/bin/containerd-shim-openvmm-v2-real "$@"\n' \
    > /usr/local/bin/containerd-shim-openvmm-v2 && \
    chmod +x /usr/local/bin/containerd-shim-openvmm-v2

# Copy in the benchmark script.
COPY bench-run.sh /usr/local/bin/bench-run.sh
RUN chmod +x /usr/local/bin/bench-run.sh

ENTRYPOINT ["/usr/local/bin/bench-run.sh"]
