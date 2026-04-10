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

# openvmm-deps: Linux kernel, initrd, petritools (auto-extracted remote tarball)
ADD --unpack --link \
    https://github.com/microsoft/openvmm-deps/releases/download/${OPENVMM_DEPS_VERSION}/openvmm-deps.${RUST_ARCH}.${OPENVMM_DEPS_VERSION}.tar.bz2 \
    /opt/openvmm/deps/

# UEFI firmware from microsoft/mu_msvm GitHub Releases (ZIP — not auto-extracted)
ADD --link \
    https://github.com/microsoft/mu_msvm/releases/download/v${MU_MSVM_VERSION}/RELEASE-${UEFI_ARCH}-artifacts.zip \
    /tmp/uefi.zip
RUN unzip -q /tmp/uefi.zip -d /opt/openvmm/firmware/ && rm /tmp/uefi.zip

# Pre-built artifacts assembled by flowey into the build context:
#   artifacts/bin/       — openvmm, pipette, tmk_vmm, etc.
#   artifacts/vmm_tests.tar.zst — nextest archive
#   artifacts/nextest.toml      — nextest config
COPY --link artifacts/ /opt/openvmm/

# Entrypoint binary (built from vmm_tests/vmm_test_container_entrypoint)
COPY --link run-vmm-tests /opt/openvmm/run-vmm-tests

LABEL org.opencontainers.image.source=https://github.com/microsoft/openvmm
LABEL org.opencontainers.image.description="OpenVMM VMM test runner"
LABEL org.opencontainers.image.licenses=MIT

ENTRYPOINT ["/opt/openvmm/run-vmm-tests"]
CMD ["--profile", "default"]
