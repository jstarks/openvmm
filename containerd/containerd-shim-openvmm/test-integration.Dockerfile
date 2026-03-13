# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Test image for containerd-shim-openvmm integration tests.
# Pre-installs containerd 2.1.0 and caches the alpine:latest image
# so repeated test runs don't re-download everything.

FROM docker.io/library/ubuntu:24.04

ARG CONTAINERD_VERSION=2.1.0
ARG TARGETARCH

# Install containerd from the official binary release, plus erofs-utils
# for the EROFS snapshotter (new in containerd 2.1).
RUN apt-get update -qq && \
    apt-get install -y -qq wget erofs-utils >/dev/null 2>&1 && \
    wget -q "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION}-linux-${TARGETARCH}.tar.gz" \
         -O /tmp/containerd.tar.gz && \
    tar -xzf /tmp/containerd.tar.gz -C /usr/local && \
    rm /tmp/containerd.tar.gz && \
    apt-get remove -y wget && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Alpine image tar is saved on the host by the build script and copied in.
# At runtime, `ctr image import` loads it instantly with no network needed.
COPY alpine.tar /opt/alpine.tar
