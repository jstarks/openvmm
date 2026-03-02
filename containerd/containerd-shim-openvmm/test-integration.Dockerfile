# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Test image for containerd-shim-openvmm integration tests.
# Pre-installs containerd 2.0.4 and caches the alpine:latest image
# so repeated test runs don't re-download everything.

FROM docker.io/library/ubuntu:24.04

ARG CONTAINERD_VERSION=2.0.4
ARG TARGETARCH

# Install containerd from the official binary release.
RUN apt-get update -qq && \
    apt-get install -y -qq wget >/dev/null 2>&1 && \
    wget -q "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION}-linux-${TARGETARCH}.tar.gz" \
         -O /tmp/containerd.tar.gz && \
    tar -xzf /tmp/containerd.tar.gz -C /usr/local && \
    rm /tmp/containerd.tar.gz && \
    apt-get remove -y wget && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Pre-pull the alpine test image into containerd's content store.
# We start containerd briefly, pull, then stop it and preserve the state.
RUN /usr/local/bin/containerd &>/dev/null & \
    CTRD_PID=$! && \
    for i in $(seq 1 30); do \
        /usr/local/bin/ctr version &>/dev/null && break; \
        sleep 0.5; \
    done && \
    /usr/local/bin/ctr image pull docker.io/library/alpine:latest >/dev/null 2>&1 && \
    kill $CTRD_PID && wait $CTRD_PID 2>/dev/null || true
