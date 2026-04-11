# syntax=docker/dockerfile:1
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Container image for running OpenVMM VMM tests on arbitrary Linux hosts.
# Built by flowey — versions are supplied via --build-arg from cfg_versions.rs.
#
# Usage:
#   docker run --device=/dev/kvm \
#     -v openvmm-cache:/cache \
#     -v ./results:/results \
#     ghcr.io/microsoft/openvmm/vmm-tests:latest

FROM mcr.microsoft.com/azurelinux/base/core:3.0

ARG NEXTEST_VERSION
ARG OPENVMM_DEPS_VERSION
ARG MU_MSVM_VERSION
ARG RUST_ARCH
ARG UEFI_ARCH

# Runtime dependencies (unzip needed for UEFI firmware ZIP extraction)
RUN tdnf install -y unzip curl && tdnf clean all

# cargo-nextest (auto-extracted remote tarball)
ADD --unpack --link \
    https://get.nexte.st/${NEXTEST_VERSION}/${RUST_ARCH}-unknown-linux-gnu.tar.gz \
    /usr/local/bin/

# Determine arch-specific directory names for the content dir layout.
# These must match what petri_artifact_resolver_openvmm_known_paths expects:
#   x86_64: kernel at bin/x64/vmlinux, initrd at bin/x64/initrd
#   aarch64: kernel at bin/aarch64/Image, initrd at bin/aarch64/initrd
ARG CONTENT_ARCH_DIR
ARG UEFI_CONTENT_DIR

# openvmm-deps: Linux kernel, initrd, petritools — placed directly into the
# content dir layout the artifact resolver expects.
ADD --unpack --link \
    https://github.com/microsoft/openvmm-deps/releases/download/${OPENVMM_DEPS_VERSION}/openvmm-deps.${RUST_ARCH}.${OPENVMM_DEPS_VERSION}.tar.bz2 \
    /opt/openvmm/bin/${CONTENT_ARCH_DIR}/

# UEFI firmware from microsoft/mu_msvm GitHub Releases (ZIP — not auto-extracted).
# Extracted into the deep path the artifact resolver expects.
ADD --link \
    https://github.com/microsoft/mu_msvm/releases/download/v${MU_MSVM_VERSION}/RELEASE-${UEFI_ARCH}-artifacts.zip \
    /tmp/uefi.zip
RUN mkdir -p "/opt/openvmm/bin/${UEFI_CONTENT_DIR}" && \
    unzip -q /tmp/uefi.zip -d /tmp/uefi && \
    find /tmp/uefi -name MSVM.fd -exec cp {} "/opt/openvmm/bin/${UEFI_CONTENT_DIR}/MSVM.fd" \; && \
    rm -rf /tmp/uefi /tmp/uefi.zip

# Pre-built artifacts assembled by flowey into the build context:
#   artifacts/bin/       — openvmm, pipette, tmk_vmm, etc.
#   artifacts/vmm_tests.tar.zst — nextest archive
#   artifacts/nextest.toml      — nextest config
COPY --link artifacts/ /opt/openvmm/

# Workspace skeleton — only Cargo.toml files and directory structure.
# nextest --workspace-remap only needs the crate directory layout to set
# working directories, not the full source tree (~250MB savings).
# See: https://github.com/nextest-rs/nextest/issues/692
COPY --link workspace/ /opt/openvmm/workspace/

# Entrypoint binary (built from vmm_tests/vmm_test_container_entrypoint)
COPY --link run-vmm-tests /opt/openvmm/run-vmm-tests

LABEL org.opencontainers.image.source=https://github.com/microsoft/openvmm
LABEL org.opencontainers.image.description="OpenVMM VMM test runner"
LABEL org.opencontainers.image.licenses=MIT

ENTRYPOINT ["/opt/openvmm/run-vmm-tests"]
CMD ["--profile", "default"]
