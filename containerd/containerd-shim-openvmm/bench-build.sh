#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Build a self-contained benchmark image for containerd-shim-openvmm.
#
# The resulting Docker image includes everything needed to run the benchmark:
# containerd, the shim, the guest agent, a Linux kernel, and a cached alpine
# image. Just run it on any machine with Docker and /dev/kvm:
#
#   docker run --rm --privileged --device /dev/kvm <image> [bench options]
#
# Usage:
#   ./bench-build.sh [OPTIONS]
#
# Options:
#   --kernel PATH        Path to vmlinux (default: auto-detect)
#   --release            Build shim in release mode (recommended for real benchmarks)
#   --tag TAG            Docker image tag (default: shim-bench:latest)
#   --export FILE        Also export the image as a .tar archive for portability
#   --run                Run the benchmark immediately after building
#   -- [ARGS]            Extra arguments passed to bench-run.sh when using --run
#   -h/--help            Show this help

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
KERNEL_PATH=""
RELEASE_MODE=0
IMAGE_TAG="shim-bench:latest"
EXPORT_FILE=""
RUN_AFTER_BUILD=0
RUN_ARGS=()

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)    KERNEL_PATH="$2"; shift 2 ;;
        --release)   RELEASE_MODE=1; shift ;;
        --tag)       IMAGE_TAG="$2"; shift 2 ;;
        --export)    EXPORT_FILE="$2"; shift 2 ;;
        --run)       RUN_AFTER_BUILD=1; shift ;;
        --)          shift; RUN_ARGS=("$@"); break ;;
        -h|--help)
            sed -n '2,/^$/s/^# \?//p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

if [[ ! -t 1 ]]; then
    RED='' GREEN='' BOLD='' RESET=''
fi

info() { echo -e "${BOLD}==>${RESET} $1"; }
ok()   { echo -e "${GREEN}OK${RESET}  $1"; }
die()  { echo -e "${RED}ERROR${RESET} $1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Locate repo root
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  MUSL_TARGET="x86_64-unknown-linux-musl"
             GNU_TARGET="x86_64-unknown-linux-gnu"
             CONTAINERD_ARCH="amd64" ;;
    aarch64) MUSL_TARGET="aarch64-unknown-linux-musl"
             GNU_TARGET="aarch64-unknown-linux-gnu"
             CONTAINERD_ARCH="arm64" ;;
    *)       die "Unsupported architecture: $ARCH" ;;
esac

# ---------------------------------------------------------------------------
# Step 1: Build shim binary
# ---------------------------------------------------------------------------
CARGO_PROFILE="debug"
CARGO_FLAGS=()
if [[ "$RELEASE_MODE" -eq 1 ]]; then
    CARGO_PROFILE="release"
    CARGO_FLAGS+=(--release)
fi

info "Building containerd-shim-openvmm (${CARGO_PROFILE})"
cargo build -p containerd_shim_openvmm "${CARGO_FLAGS[@]}" 2>&1

# Find the binary.
SHIM_BIN=""
for candidate in \
    "$REPO_ROOT/target/$GNU_TARGET/$CARGO_PROFILE/containerd-shim-openvmm-v2" \
    "$REPO_ROOT/target/$CARGO_PROFILE/containerd-shim-openvmm-v2"; do
    if [[ -x "$candidate" ]]; then
        SHIM_BIN="$candidate"
        break
    fi
done
[[ -n "$SHIM_BIN" ]] || die "Shim binary not found after build"
ok "Shim: $SHIM_BIN"

# ---------------------------------------------------------------------------
# Step 2: Build guest agent (static musl binary)
# ---------------------------------------------------------------------------
info "Building containerd-shim-agent (musl, release)"
cargo build -p containerd_shim_agent --target "$MUSL_TARGET" --release 2>&1

AGENT_BIN="$REPO_ROOT/target/$MUSL_TARGET/release/containerd-shim-agent"
[[ -x "$AGENT_BIN" ]] || die "Agent binary not found at $AGENT_BIN"
ok "Agent: $AGENT_BIN"

# ---------------------------------------------------------------------------
# Step 3: Locate kernel
# ---------------------------------------------------------------------------
if [[ -z "$KERNEL_PATH" ]]; then
    # Auto-detect from common locations.
    for candidate in \
        "$REPO_ROOT/.packages/underhill-deps-private/x64/vmlinux" \
        "$REPO_ROOT/.packages/underhill-deps/x64/vmlinux" \
        "/boot/vmlinux-$(uname -r)" \
        "/boot/vmlinuz-$(uname -r)"; do
        if [[ -f "$candidate" ]]; then
            KERNEL_PATH="$candidate"
            break
        fi
    done
fi

[[ -n "$KERNEL_PATH" && -f "$KERNEL_PATH" ]] || \
    die "Kernel not found. Pass --kernel /path/to/vmlinux"
ok "Kernel: $KERNEL_PATH"

# ---------------------------------------------------------------------------
# Step 4: Assemble staging directory
# ---------------------------------------------------------------------------
info "Assembling Docker build context"
STAGING="$(mktemp -d /tmp/shim-bench-staging.XXXXXX)"
trap "rm -rf '$STAGING'" EXIT

cp "$SHIM_BIN"   "$STAGING/containerd-shim-openvmm-v2"
cp "$AGENT_BIN"  "$STAGING/containerd-shim-agent"
cp "$KERNEL_PATH" "$STAGING/vmlinux"
cp "$SCRIPT_DIR/bench-run.sh"    "$STAGING/bench-run.sh"
cp "$SCRIPT_DIR/bench.Dockerfile" "$STAGING/Dockerfile"

# ---------------------------------------------------------------------------
# Step 5: Build ext4 rootfs image for virtio-blk boot (demand-paged, no initrd unpack)
# ---------------------------------------------------------------------------
info "Building ext4 rootfs image from agent binary"
ROOTFS_TMP="$(mktemp -d)"
mkdir -p "$ROOTFS_TMP/rootfs"
cp "$AGENT_BIN" "$ROOTFS_TMP/rootfs/init"
chmod 755 "$ROOTFS_TMP/rootfs/init"
# Create mount points the kernel expects before running init.
mkdir -p "$ROOTFS_TMP/rootfs/dev" "$ROOTFS_TMP/rootfs/proc" "$ROOTFS_TMP/rootfs/sys" "$ROOTFS_TMP/rootfs/tmp" "$ROOTFS_TMP/rootfs/run"

# Create a sparse ext4 image populated from the directory.
# 128MB is plenty for the ~35MB agent; sparse file means only used blocks
# consume actual disk space.
AGENT_SIZE=$(stat -c%s "$AGENT_BIN")
IMAGE_SIZE_MB=128
truncate -s "${IMAGE_SIZE_MB}M" "$STAGING/rootfs.img"
mkfs.ext4 -q -F -d "$ROOTFS_TMP/rootfs" "$STAGING/rootfs.img"
ok "Rootfs: $STAGING/rootfs.img (${IMAGE_SIZE_MB}MB ext4, agent=$(numfmt --to=iec $AGENT_SIZE))"
rm -rf "$ROOTFS_TMP"

# ---------------------------------------------------------------------------
# Step 6: Build Docker image
# ---------------------------------------------------------------------------

info "Building Docker image: $IMAGE_TAG"
docker build -q \
    --build-arg TARGETARCH="$CONTAINERD_ARCH" \
    -t "$IMAGE_TAG" \
    "$STAGING"

ok "Image built: $IMAGE_TAG"

# Print size.
IMAGE_SIZE=$(docker image inspect "$IMAGE_TAG" --format='{{.Size}}' 2>/dev/null || echo 0)
IMAGE_SIZE_MB=$((IMAGE_SIZE / 1024 / 1024))
info "Image size: ~${IMAGE_SIZE_MB} MB"

# ---------------------------------------------------------------------------
# Step 7: Optional export
# ---------------------------------------------------------------------------
if [[ -n "$EXPORT_FILE" ]]; then
    info "Exporting image to: $EXPORT_FILE"
    docker save "$IMAGE_TAG" -o "$EXPORT_FILE"
    EXPORT_SIZE_MB=$(( $(stat -c%s "$EXPORT_FILE") / 1024 / 1024 ))
    ok "Exported: $EXPORT_FILE (~${EXPORT_SIZE_MB} MB)"
    echo ""
    echo "To load on another machine:"
    echo "  docker load -i $EXPORT_FILE"
fi

# ---------------------------------------------------------------------------
# Step 8: Run instructions / immediate run
# ---------------------------------------------------------------------------
echo ""
echo "========================================="
echo "  Benchmark image ready: $IMAGE_TAG"
echo "========================================="
echo ""
echo "Run the benchmark:"
echo "  docker run --rm --privileged --device /dev/kvm $IMAGE_TAG"
echo ""
echo "Options (passed after image name):"
echo "  -n 20          Run 20 iterations (default: 10)"
echo "  -w 2           Warmup iterations (default: 1)"
echo "  --no-net       Disable networking (faster VM boot)"
echo "  --json         JSON output"
echo "  docker run --rm --privileged --cgroupns=host --device /dev/kvm $IMAGE_TAG"
echo ""
echo "Move to another machine:"
echo "  docker save $IMAGE_TAG | gzip > shim-bench.tar.gz"
echo "  # on the other machine:"
echo "  docker load < shim-bench.tar.gz"
echo "  docker run --rm --privileged --cgroupns=host --device /dev/kvm $IMAGE_TAG"
echo ""

if [[ "$RUN_AFTER_BUILD" -eq 1 ]]; then
    info "Running benchmark..."
    DOCKER_ARGS=(--rm --privileged --cgroupns=host)
    if [[ -e /dev/kvm ]]; then
        DOCKER_ARGS+=(--device /dev/kvm)
    fi
    docker run "${DOCKER_ARGS[@]}" "$IMAGE_TAG" "${RUN_ARGS[@]}"
fi
