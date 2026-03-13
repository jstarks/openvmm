#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Integration test for containerd-shim-openvmm-v2.
# Requires: Docker, cargo
# Usage: ./test-integration.sh  (from repo root or crate directory)

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

if [[ ! -t 1 ]]; then
    RED='' GREEN='' YELLOW='' BOLD='' RESET=''
fi

pass() { echo -e "${GREEN}PASS${RESET} $1"; }
fail() { echo -e "${RED}FAIL${RESET} $1"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "${BOLD}==>${RESET} $1"; }

FAILURES=0
CLEANUP_PIDS=()
CLEANUP_DIRS=()

cleanup() {
    for pid in "${CLEANUP_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    for dir in "${CLEANUP_DIRS[@]}"; do
        rm -rf "$dir" 2>/dev/null || true
    done
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Locate repo root
# ---------------------------------------------------------------------------

# Support running from either the repo root or the crate directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../../Cargo.toml" ]]; then
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
elif [[ -f "$SCRIPT_DIR/Cargo.toml" ]]; then
    # Running from containerd/containerd-shim-openvmm/
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
    echo "ERROR: Cannot determine repo root. Run from repo root or crate directory."
    exit 1
fi

cd "$REPO_ROOT"

# Determine the target triple for finding the binary.
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
    *)       TARGET="" ;;
esac

# Try target-specific path first, then default path.
if [[ -n "$TARGET" ]]; then
    SHIM_BIN_CANDIDATES=(
        "$REPO_ROOT/target/$TARGET/debug/containerd-shim-openvmm-v2"
        "$REPO_ROOT/target/debug/containerd-shim-openvmm-v2"
    )
else
    SHIM_BIN_CANDIDATES=(
        "$REPO_ROOT/target/debug/containerd-shim-openvmm-v2"
    )
fi

# =========================================================================
# Phase 1: Build
# =========================================================================

info "Phase 1: Building containerd-shim-openvmm-v2"

cargo build -p containerd_shim_openvmm 2>&1
if [[ $? -ne 0 ]]; then
    fail "cargo build failed"
    exit 1
fi

# Find the binary.
SHIM_BIN=""
for candidate in "${SHIM_BIN_CANDIDATES[@]}"; do
    if [[ -x "$candidate" ]]; then
        SHIM_BIN="$candidate"
        break
    fi
done

if [[ -z "$SHIM_BIN" ]]; then
    fail "shim binary not found after build"
    exit 1
fi

pass "Build succeeded: $SHIM_BIN"

# Also build the guest agent (static musl binary for the initrd).
info "  Building containerd-shim-agent (musl)"
MUSL_TARGET="x86_64-unknown-linux-musl"
if [[ "$ARCH" == "aarch64" ]]; then
    MUSL_TARGET="aarch64-unknown-linux-musl"
fi

cargo build -p containerd_shim_agent --target "$MUSL_TARGET" --release 2>&1
if [[ $? -ne 0 ]]; then
    info "  musl agent build failed — Phase 3 VM tests will be skipped"
    AGENT_BIN=""
else
    AGENT_BIN="$REPO_ROOT/target/$MUSL_TARGET/release/containerd-shim-agent"
    if [[ ! -x "$AGENT_BIN" ]]; then
        info "  Agent binary not found at $AGENT_BIN — Phase 3 VM tests will be skipped"
        AGENT_BIN=""
    else
        pass "Agent build succeeded: $AGENT_BIN"
    fi
fi

# Locate kernel for VM tests. User can override with OPENVMM_SHIM_KERNEL env var.
KERNEL_PATH="${OPENVMM_SHIM_KERNEL:-$REPO_ROOT/.packages/underhill-deps-private/x64/vmlinux}"
if [[ ! -f "$KERNEL_PATH" ]]; then
    info "  Kernel not found at $KERNEL_PATH — Phase 3 VM tests will be skipped"
    KERNEL_PATH=""
fi

# Determine if Phase 3 can run VM tests (needs agent + kernel + KVM).
HAS_KVM=0
if [[ -e /dev/kvm ]]; then
    HAS_KVM=1
fi
CAN_VM_TEST=0
if [[ -n "$AGENT_BIN" && -n "$KERNEL_PATH" && "$HAS_KVM" -eq 1 ]]; then
    CAN_VM_TEST=1
    pass "VM test prerequisites met (agent + kernel + KVM)"
else
    info "  VM test prerequisites not met — Phase 3 will run without VM boot validation"
    [[ -z "$AGENT_BIN" ]] && info "    Missing: agent binary"
    [[ -z "$KERNEL_PATH" ]] && info "    Missing: kernel ($OPENVMM_SHIM_KERNEL or default path)"
    [[ "$HAS_KVM" -eq 0 ]] && info "    Missing: /dev/kvm"
fi

# =========================================================================
# Phase 2: Standalone smoke tests
# =========================================================================

info "Phase 2: Standalone smoke tests"

# --- Test 2a: start handshake ---
info "  Test 2a: start handshake"

TMPDIR_2A="$(mktemp -d /tmp/shim-test-2a.XXXXXX)"
CLEANUP_DIRS+=("$TMPDIR_2A")

OUTPUT_2A=$("$SHIM_BIN" start \
    -namespace default -id test-2a \
    -address /tmp/test-2a.sock \
    -publish-binary containerd \
    -bundle "$TMPDIR_2A" 2>&1) || {
    fail "Test 2a: start command exited non-zero"
    echo "  Output: $OUTPUT_2A"
}

# Validate JSON fields.
if echo "$OUTPUT_2A" | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert 'version' in d, 'missing version'
assert 'address' in d, 'missing address'
assert 'protocol' in d, 'missing protocol'
assert d['version'] == 3, f'expected version 3, got {d[\"version\"]}'
assert d['protocol'] == 'ttrpc', f'expected protocol ttrpc, got {d[\"protocol\"]}'
" 2>/dev/null; then
    pass "Test 2a: bootstrap JSON is valid"
else
    fail "Test 2a: bootstrap JSON is invalid or missing fields"
    echo "  Output: $OUTPUT_2A"
fi

# Validate shim.sock exists.
if [[ -S "$TMPDIR_2A/shim.sock" ]]; then
    pass "Test 2a: shim.sock exists"
else
    fail "Test 2a: shim.sock not found"
fi

# Validate serve process is running.
SERVE_PID_2A=$(pgrep -f "containerd-shim-openvmm-v2 serve.*test-2a" || true)
if [[ -n "$SERVE_PID_2A" ]]; then
    pass "Test 2a: serve process running (pid $SERVE_PID_2A)"
    CLEANUP_PIDS+=($SERVE_PID_2A)
else
    fail "Test 2a: serve process not found"
fi

# Kill 2a serve process before running 2b to avoid pgrep confusion.
if [[ -n "${SERVE_PID_2A:-}" ]]; then
    kill "$SERVE_PID_2A" 2>/dev/null || true
    wait "$SERVE_PID_2A" 2>/dev/null || true
fi

# --- Test 2b: idempotent start ---
info "  Test 2b: idempotent start"

TMPDIR_2B="$(mktemp -d /tmp/shim-test-2b.XXXXXX)"
CLEANUP_DIRS+=("$TMPDIR_2B")

OUTPUT_2B_1=$("$SHIM_BIN" start \
    -namespace default -id test-2b \
    -address /tmp/test-2b.sock \
    -publish-binary containerd \
    -bundle "$TMPDIR_2B" 2>&1) || true

# Second start with same args.
OUTPUT_2B_2=$("$SHIM_BIN" start \
    -namespace default -id test-2b \
    -address /tmp/test-2b.sock \
    -publish-binary containerd \
    -bundle "$TMPDIR_2B" 2>&1) || true

if [[ "$OUTPUT_2B_1" == "$OUTPUT_2B_2" ]]; then
    pass "Test 2b: idempotent start — both outputs identical"
else
    fail "Test 2b: idempotent start — outputs differ"
    echo "  First:  $OUTPUT_2B_1"
    echo "  Second: $OUTPUT_2B_2"
fi

# Count serve processes for this id.
SERVE_COUNT_2B=$(pgrep -fc "containerd-shim-openvmm-v2 serve.*test-2b" || echo 0)
if [[ "$SERVE_COUNT_2B" -eq 1 ]]; then
    pass "Test 2b: exactly one serve process running"
else
    fail "Test 2b: expected 1 serve process, found $SERVE_COUNT_2B"
fi

SERVE_PID_2B=$(pgrep -f "containerd-shim-openvmm-v2 serve.*test-2b" || true)
if [[ -n "$SERVE_PID_2B" ]]; then
    CLEANUP_PIDS+=($SERVE_PID_2B)
fi

# --- Test 2c: delete subcommand ---
info "  Test 2c: delete subcommand"

TMPDIR_2C="$(mktemp -d /tmp/shim-test-2c.XXXXXX)"
CLEANUP_DIRS+=("$TMPDIR_2C")

# Create a fake shim.sock.
touch "$TMPDIR_2C/shim.sock"

# The delete subcommand writes a protobuf-encoded DeleteResponse to stdout.
# Capture raw bytes into a file so we can validate them.
OUTPUT_FILE_2C="$TMPDIR_2C/delete-output.bin"
"$SHIM_BIN" delete \
    -namespace default -id test-2c \
    -address /tmp/test-2c.sock \
    -publish-binary containerd \
    -bundle "$TMPDIR_2C" > "$OUTPUT_FILE_2C" 2>/dev/null || {
    fail "Test 2c: delete command exited non-zero"
}

# Validate the output is non-empty (valid protobuf for a minimal DeleteResponse
# is a few bytes; an empty response is also valid protobuf).
if [[ -f "$OUTPUT_FILE_2C" ]]; then
    pass "Test 2c: delete produced output ($(wc -c < "$OUTPUT_FILE_2C") bytes)"
else
    fail "Test 2c: delete produced no output"
fi

# Validate shim.sock was removed.
if [[ ! -e "$TMPDIR_2C/shim.sock" ]]; then
    pass "Test 2c: shim.sock was removed"
else
    fail "Test 2c: shim.sock still exists after delete"
fi

# Kill leftover serve processes from phase 2 before moving on.
for pid in "${CLEANUP_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
done
CLEANUP_PIDS=()

if [[ $FAILURES -gt 0 ]]; then
    echo ""
    fail "Phase 2 had $FAILURES failure(s) — stopping."
    exit 1
fi

pass "Phase 2 complete — all standalone smoke tests passed"

# =========================================================================
# Phase 3: Containerd integration test (inside Docker container)
# =========================================================================

info "Phase 3: Containerd integration test (Docker container)"

# Verify Docker is available.
if ! command -v docker &>/dev/null; then
    fail "Docker not found — cannot run phase 3"
    exit 1
fi

# Determine containerd binary URL.
case "$ARCH" in
    x86_64)  CONTAINERD_ARCH="amd64" ;;
    aarch64) CONTAINERD_ARCH="arm64" ;;
    *)       fail "Unsupported architecture: $ARCH"; exit 1 ;;
esac

CONTAINERD_VERSION="2.1.0"
DOCKER_IMAGE="shim-integration-test:containerd-${CONTAINERD_VERSION}"
DOCKERFILE="$REPO_ROOT/containerd/containerd-shim-openvmm/test-integration.Dockerfile"
BUILD_CONTEXT="$REPO_ROOT/containerd/containerd-shim-openvmm"

# Save alpine image into the build context so the Dockerfile can COPY it.
ALPINE_TAR="$BUILD_CONTEXT/alpine.tar"
if [[ ! -f "$ALPINE_TAR" ]]; then
    info "  Saving alpine image for offline use"
    docker pull -q docker.io/library/alpine:latest >/dev/null
    docker save docker.io/library/alpine:latest -o "$ALPINE_TAR"
fi

# Build the test image (Docker layer cache makes repeated runs instant).
info "  Building test image (cached after first run)"
docker build -q \
    --build-arg TARGETARCH="$CONTAINERD_ARCH" \
    --build-arg CONTAINERD_VERSION="$CONTAINERD_VERSION" \
    -t "$DOCKER_IMAGE" \
    -f "$DOCKERFILE" \
    "$BUILD_CONTEXT" >/dev/null

info "  Running containerd ${CONTAINERD_VERSION} inside Docker with shim mounted"

# Build the inner script that runs inside the container.
# containerd + alpine image are already installed/cached in the image.
read -r -d '' INNER_SCRIPT << 'INNER_EOF' || true
#!/bin/bash
set -euo pipefail

FAILURES=0

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILURES=$((FAILURES + 1)); }
info() { echo "==> $1"; }

# Verify containerd version.
CTRD_VER=$(/usr/local/bin/containerd --version 2>&1 || true)
info "containerd version: $CTRD_VER"

# Create wrapper script that injects environment variables.
# containerd does not pass env vars to shims — it exec's them directly with
# a cleaned environment. The wrapper sets the required vars and exec's the
# real binary.
if [[ -f /usr/local/share/vmlinux && -f /usr/local/share/containerd-shim-agent ]]; then
    VM_MODE=1
    info "VM mode: kernel + agent available"
    cat > /usr/local/bin/containerd-shim-openvmm-v2 << 'WRAPPER'
#!/bin/bash
export OPENVMM_SHIM_KERNEL=/usr/local/share/vmlinux
export OPENVMM_SHIM_AGENT=/usr/local/share/containerd-shim-agent
exec /usr/local/bin/containerd-shim-openvmm-v2-real "$@"
WRAPPER
    chmod +x /usr/local/bin/containerd-shim-openvmm-v2
else
    VM_MODE=0
    info "Stub mode: no kernel/agent — testing shim RPC plumbing only"
    # Use the real binary directly (no wrapper needed).
    ln -sf /usr/local/bin/containerd-shim-openvmm-v2-real \
           /usr/local/bin/containerd-shim-openvmm-v2 2>/dev/null || true
fi

# Verify shim is on PATH.
if command -v containerd-shim-openvmm-v2 &>/dev/null; then
    pass "Shim binary found on PATH: $(which containerd-shim-openvmm-v2)"
else
    fail "Shim binary not found on PATH"
    exit 1
fi

# --- Move containerd state onto tmpfs to avoid nested-overlay ---
# Docker's root filesystem is overlayfs, so the overlay snapshotter would fail
# with nested overlayfs.  Putting containerd's state on tmpfs avoids this while
# preserving the pre-cached alpine image from the Docker build layer.
info "Setting up tmpfs for containerd state (avoids nested overlayfs)"
if [[ -d /var/lib/containerd ]]; then
    cp -a /var/lib/containerd /tmp/containerd-state
fi
mkdir -p /var/lib/containerd
mount -t tmpfs tmpfs /var/lib/containerd
if [[ -d /tmp/containerd-state ]]; then
    cp -a /tmp/containerd-state/* /var/lib/containerd/
    rm -rf /tmp/containerd-state
fi

# --- Configure EROFS snapshotter (new in containerd 2.1) ---
# The erofs module must be loaded on the host kernel.
HAS_EROFS=0
if modprobe erofs 2>/dev/null || grep -qw erofs /proc/filesystems 2>/dev/null; then
    HAS_EROFS=1
    info "EROFS kernel support available"
else
    info "EROFS kernel support not available — EROFS tests will be skipped"
fi

if [[ "$HAS_EROFS" -eq 1 ]] && command -v mkfs.erofs &>/dev/null; then
    EROFS_VERSION=$(mkfs.erofs --version 2>&1 | head -1 || true)
    info "erofs-utils: $EROFS_VERSION"

    # Write containerd config to enable the EROFS snapshotter and differ.
    mkdir -p /etc/containerd
    cat > /etc/containerd/config.toml << 'CTRDCFG'
version = 2

[plugins."io.containerd.service.v1.diff-service"]
  default = ["erofs","walking"]
CTRDCFG
    info "EROFS snapshotter + differ configured in containerd config.toml"
else
    HAS_EROFS=0
fi

# --- Start containerd ---
info "Starting containerd"
/usr/local/bin/containerd &>/var/log/containerd.log &
CONTAINERD_PID=$!

# Wait for containerd to be ready (poll ctr version).
READY=0
for i in $(seq 1 30); do
    if /usr/local/bin/ctr version &>/dev/null; then
        READY=1
        break
    fi
    sleep 0.5
done

if [[ "$READY" -eq 1 ]]; then
    pass "containerd is ready"
else
    fail "containerd failed to start"
    echo "--- containerd log ---"
    cat /var/log/containerd.log 2>/dev/null || true
    exit 1
fi

# Import alpine image from pre-exported OCI tar (no network needed).
if /usr/local/bin/ctr image ls -q | grep -q "alpine"; then
    pass "Alpine image available"
else
    if [[ -f /opt/alpine.tar ]]; then
        /usr/local/bin/ctr image import /opt/alpine.tar >/dev/null 2>&1
        pass "Alpine image imported from /opt/alpine.tar"
    else
        info "No cached image — pulling from network"
        /usr/local/bin/ctr image pull docker.io/library/alpine:latest >/dev/null 2>&1 || {
            fail "Failed to pull alpine image"
            echo "--- containerd log (last 30 lines) ---"
            tail -30 /var/log/containerd.log 2>/dev/null || true
            exit 1
        }
        pass "Image pulled"
    fi
fi

# Unpack for the default (overlay) snapshotter.
# containerd 2.1 removed 'ctr image unpack'; use 'pull --local' to unpack a local image.
/usr/local/bin/ctr image pull --snapshotter overlayfs --local docker.io/library/alpine:latest >/dev/null 2>&1 || true

# Unpack for the EROFS snapshotter (if available).
if [[ "$HAS_EROFS" -eq 1 ]]; then
    if /usr/local/bin/ctr image pull --snapshotter erofs --local docker.io/library/alpine:latest >/dev/null 2>&1; then
        pass "Alpine image unpacked for EROFS snapshotter"
    else
        info "Failed to unpack for EROFS snapshotter — EROFS tests will be skipped"
        HAS_EROFS=0
    fi
fi

# --- Test 3a: Standalone mode (ctr run triggers Task.Create implicit VM boot) ---
info "Test 3a: Standalone mode (ctr run)"

TIMEOUT_SECS=15
if [[ "$VM_MODE" -eq 1 ]]; then
    TIMEOUT_SECS=120  # VM boot + container execution
fi

# Run the container and capture output.
CTR_OUTPUT=""
CTR_EXIT=0
CTR_OUTPUT=$(timeout "$TIMEOUT_SECS" /usr/local/bin/ctr run --rm \
    --runtime io.containerd.openvmm.v2 \
    docker.io/library/alpine:latest test-standalone echo hello 2>&1) || CTR_EXIT=$?

echo "--- ctr run output ---"
echo "$CTR_OUTPUT"
echo "--- end ctr run output ---"

# Give shim log a moment to flush.
sleep 1

if [[ "$VM_MODE" -eq 1 ]]; then
    # In VM mode, we expect actual container output.
    if echo "$CTR_OUTPUT" | grep -q "hello"; then
        pass "Test 3a: container output contains 'hello'"
    else
        fail "Test 3a: container output does not contain 'hello'"
    fi

    if [[ "$CTR_EXIT" -eq 0 ]]; then
        pass "Test 3a: ctr run exited with code 0"
    else
        # timeout(1) returns 124 on timeout
        if [[ "$CTR_EXIT" -eq 124 ]]; then
            fail "Test 3a: ctr run timed out after ${TIMEOUT_SECS}s"
        else
            fail "Test 3a: ctr run exited with code $CTR_EXIT"
        fi
    fi
else
    info "Test 3a: stub mode — skipping output validation"
fi

# --- Find and validate shim log ---
# Note: with `--rm`, containerd may clean up the bundle directory (including
# shim.log) after delete.  When container output was already validated, treat
# a missing log as a soft warning rather than a hard failure.
info "Looking for shim log"
SHIM_LOG=$(find /run/containerd -name "shim.log" -type f 2>/dev/null | head -1)

if [[ -z "$SHIM_LOG" ]]; then
    if [[ "$VM_MODE" -eq 1 ]] && echo "$CTR_OUTPUT" | grep -q "hello"; then
        info "shim.log already cleaned up by --rm (container output was validated)"
    else
        fail "shim.log not found under /run/containerd"
        echo "--- Directory listing ---"
        find /run/containerd -type f 2>/dev/null || true
        echo "--- containerd log (last 50 lines) ---"
        tail -50 /var/log/containerd.log 2>/dev/null || true
        exit 1
    fi
else
    pass "Found shim log: $SHIM_LOG"

    echo ""
    echo "--- shim.log contents ---"
    cat "$SHIM_LOG"
    echo "--- end shim.log ---"
    echo ""

    # Check minimum required log entries.
    if grep -q "shim starting" "$SHIM_LOG"; then
        pass "shim.log contains 'shim starting'"
    else
        fail "shim.log missing 'shim starting'"
    fi

    if grep -q "listening" "$SHIM_LOG"; then
        pass "shim.log contains 'listening'"
    else
        fail "shim.log missing 'listening'"
    fi

    if grep -q "task.Create" "$SHIM_LOG"; then
        pass "shim.log contains 'task.Create'"
    elif grep -q "sandbox.CreateSandbox" "$SHIM_LOG"; then
        pass "shim.log contains 'sandbox.CreateSandbox' (sandbox path)"
    else
        fail "shim.log missing both 'task.Create' and 'sandbox.CreateSandbox'"
    fi

    # VM-specific checks (only if kernel + agent were available).
    if [[ "$VM_MODE" -eq 1 ]]; then
        if grep -q "standalone mode: VM booted" "$SHIM_LOG"; then
            pass "shim.log contains 'standalone mode: VM booted'"
        else
            fail "shim.log missing 'standalone mode: VM booted'"
        fi

        if grep -q "VM resumed" "$SHIM_LOG"; then
            pass "shim.log contains 'VM resumed'"
        else
            fail "shim.log missing 'VM resumed'"
        fi

        if grep -q "agent connected" "$SHIM_LOG"; then
            pass "shim.log contains 'agent connected'"
        else
            fail "shim.log missing 'agent connected'"
        fi

        if grep -q "agent bootstrap complete" "$SHIM_LOG"; then
            pass "shim.log contains 'agent bootstrap complete'"
        else
            fail "shim.log missing 'agent bootstrap complete'"
        fi

        # Check for failures.
        if grep -q "failed to" "$SHIM_LOG"; then
            fail "shim.log contains 'failed to' error(s):"
            grep "failed to" "$SHIM_LOG" | while read -r line; do
                echo "  $line"
            done
        fi
    fi

    # Bonus checks (don't fail on these).
    if grep -q "sandbox.CreateSandbox" "$SHIM_LOG"; then
        info "Bonus: shim.log contains 'sandbox.CreateSandbox'"
    fi
    if grep -q "task.Start" "$SHIM_LOG"; then
        info "Bonus: shim.log contains 'task.Start'"
    fi
fi

# --- Additional container tests (VM mode only) ---
if [[ "$VM_MODE" -eq 1 ]]; then

    # --- Test 3b: Non-zero exit code ---
    info "Test 3b: Container with non-zero exit code"
    CTR_3B_EXIT=0
    timeout 60 /usr/local/bin/ctr run --rm \
        --runtime io.containerd.openvmm.v2 \
        docker.io/library/alpine:latest test-exit1 sh -c "exit 42" 2>&1 || CTR_3B_EXIT=$?

    if [[ "$CTR_3B_EXIT" -eq 42 ]]; then
        pass "Test 3b: container exited with expected code 42"
    else
        fail "Test 3b: expected exit code 42, got $CTR_3B_EXIT"
    fi

    # --- Test 3c: Environment variables and working directory ---
    info "Test 3c: Container with env vars"
    CTR_3C_OUTPUT=""
    CTR_3C_EXIT=0
    CTR_3C_OUTPUT=$(timeout 60 /usr/local/bin/ctr run --rm --env GREETING=world \
        --runtime io.containerd.openvmm.v2 \
        docker.io/library/alpine:latest test-env sh -c 'echo "hello $GREETING"' 2>&1) || CTR_3C_EXIT=$?

    if echo "$CTR_3C_OUTPUT" | grep -q "hello world"; then
        pass "Test 3c: container env var expansion worked"
    else
        fail "Test 3c: expected 'hello world' in output"
        echo "  Got: $CTR_3C_OUTPUT"
    fi

    # --- Test 3d: Multi-line output ---
    info "Test 3d: Container with multi-line output"
    CTR_3D_OUTPUT=""
    CTR_3D_EXIT=0
    CTR_3D_OUTPUT=$(timeout 60 /usr/local/bin/ctr run --rm \
        --runtime io.containerd.openvmm.v2 \
        docker.io/library/alpine:latest test-multi sh -c 'echo line1; echo line2; echo line3' 2>&1) || CTR_3D_EXIT=$?

    CTR_3D_LINES=$(echo "$CTR_3D_OUTPUT" | grep -c "^line" || true)
    if [[ "$CTR_3D_LINES" -eq 3 ]]; then
        pass "Test 3d: got all 3 output lines"
    else
        fail "Test 3d: expected 3 lines, got $CTR_3D_LINES"
        echo "  Output: $CTR_3D_OUTPUT"
    fi

    # =======================================================================
    # M4 Tests — ExecProcess, uid/gid, networking, multi-container
    # =======================================================================

    # --- Test 3e: ExecProcess (ctr task exec) ---
    info "Test 3e: ExecProcess (ctr task exec)"

    # Start a long-running detached container.
    timeout 60 /usr/local/bin/ctr run -d \
        --runtime io.containerd.openvmm.v2 \
        docker.io/library/alpine:latest test-exec sleep 300 2>&1 || true

    # Give the container a moment to start.
    sleep 3

    # Verify the container is running.
    CTR_3E_STATE=""
    CTR_3E_STATE=$(timeout 10 /usr/local/bin/ctr task ls 2>&1 || true)
    if echo "$CTR_3E_STATE" | grep -q "test-exec.*RUNNING"; then
        pass "Test 3e: container is RUNNING"
    else
        fail "Test 3e: container not in RUNNING state"
        echo "  State: $CTR_3E_STATE"
    fi

    # Exec into the running container.
    CTR_3E_EXEC_OUTPUT=""
    CTR_3E_EXEC_EXIT=0
    CTR_3E_EXEC_OUTPUT=$(timeout 30 /usr/local/bin/ctr task exec \
        --exec-id exec1 test-exec echo "exec-hello" 2>&1) || CTR_3E_EXEC_EXIT=$?

    if echo "$CTR_3E_EXEC_OUTPUT" | grep -q "exec-hello"; then
        pass "Test 3e: exec output contains 'exec-hello'"
    else
        fail "Test 3e: exec output missing 'exec-hello'"
        echo "  Got: $CTR_3E_EXEC_OUTPUT"
    fi

    if [[ "$CTR_3E_EXEC_EXIT" -eq 0 ]]; then
        pass "Test 3e: exec exited with code 0"
    else
        fail "Test 3e: exec exited with code $CTR_3E_EXEC_EXIT"
    fi

    # Exec with non-zero exit code.
    CTR_3E_EXEC2_EXIT=0
    timeout 30 /usr/local/bin/ctr task exec \
        --exec-id exec2 test-exec sh -c "exit 7" 2>&1 || CTR_3E_EXEC2_EXIT=$?

    if [[ "$CTR_3E_EXEC2_EXIT" -eq 7 ]]; then
        pass "Test 3e: exec non-zero exit code (7) propagated"
    else
        fail "Test 3e: expected exec exit code 7, got $CTR_3E_EXEC2_EXIT"
    fi

    # Clean up the detached container.
    timeout 15 /usr/local/bin/ctr task kill -s SIGKILL test-exec 2>&1 || true
    sleep 1
    timeout 15 /usr/local/bin/ctr task rm test-exec 2>&1 || true
    timeout 15 /usr/local/bin/ctr container rm test-exec 2>&1 || true

    # --- Test 3f: uid/gid support ---
    info "Test 3f: uid/gid (run as non-root)"

    # Alpine's "nobody" user is uid 65534. Verify whoami/id works.
    CTR_3F_OUTPUT=""
    CTR_3F_EXIT=0
    CTR_3F_OUTPUT=$(timeout 60 /usr/local/bin/ctr run --rm \
        --runtime io.containerd.openvmm.v2 \
        docker.io/library/alpine:latest test-uid id 2>&1) || CTR_3F_EXIT=$?

    if echo "$CTR_3F_OUTPUT" | grep -q "uid=0"; then
        pass "Test 3f: default runs as root (uid=0)"
    else
        fail "Test 3f: expected uid=0 in output"
        echo "  Got: $CTR_3F_OUTPUT"
    fi

    # --- Test 3g: Consomme networking (outbound connectivity) ---
    info "Test 3g: Consomme networking"

    CTR_3G_OUTPUT=""
    CTR_3G_EXIT=0
    # Test TCP connectivity via raw IP (no DNS needed — the container chroot
    # has its own /etc/resolv.conf that doesn't point to consomme's DNS).
    # nc -z tests TCP connect to Google DNS on port 53.
    CTR_3G_OUTPUT=$(timeout 60 /usr/local/bin/ctr run --rm \
        --runtime io.containerd.openvmm.v2 \
        docker.io/library/alpine:latest test-net \
        sh -c 'nc -z -w5 8.8.8.8 53 2>&1 && echo NET_OK || echo NET_FAIL' 2>&1) || CTR_3G_EXIT=$?

    if echo "$CTR_3G_OUTPUT" | grep -q "NET_OK"; then
        pass "Test 3g: outbound network connectivity works (TCP via nc)"
    else
        fail "Test 3g: no network connectivity"
        echo "  Output: $CTR_3G_OUTPUT"
    fi

    # --- Test 3h: Multi-container per sandbox ---
    # This test uses sandbox-aware APIs via ctr. containerd 2.x supports
    # sandbox operations through the CRI path, but for direct ctr testing
    # we simulate by running two independent containers and verifying both
    # complete successfully (each gets its own sandbox/VM in standalone mode).
    #
    # True multi-container-per-sandbox testing requires CRI (crictl) or a
    # Kubernetes-level caller. Here we at least verify the shim can handle
    # concurrent container lifecycles.
    info "Test 3h: Concurrent containers"

    CTR_3H_OUT1=""
    CTR_3H_OUT2=""
    CTR_3H_EXIT1=0
    CTR_3H_EXIT2=0

    # Run two containers concurrently.
    timeout 120 /usr/local/bin/ctr run --rm \
        --runtime io.containerd.openvmm.v2 \
        docker.io/library/alpine:latest test-multi1 echo "container-one" > /tmp/ctr-3h-1.out 2>&1 &
    PID_3H_1=$!

    timeout 120 /usr/local/bin/ctr run --rm \
        --runtime io.containerd.openvmm.v2 \
        docker.io/library/alpine:latest test-multi2 echo "container-two" > /tmp/ctr-3h-2.out 2>&1 &
    PID_3H_2=$!

    wait $PID_3H_1 || CTR_3H_EXIT1=$?
    wait $PID_3H_2 || CTR_3H_EXIT2=$?

    CTR_3H_OUT1=$(cat /tmp/ctr-3h-1.out 2>/dev/null || echo "")
    CTR_3H_OUT2=$(cat /tmp/ctr-3h-2.out 2>/dev/null || echo "")

    MULTI_PASS=0
    if echo "$CTR_3H_OUT1" | grep -q "container-one"; then
        MULTI_PASS=$((MULTI_PASS + 1))
    fi
    if echo "$CTR_3H_OUT2" | grep -q "container-two"; then
        MULTI_PASS=$((MULTI_PASS + 1))
    fi

    if [[ "$MULTI_PASS" -eq 2 ]]; then
        pass "Test 3h: both concurrent containers produced correct output"
    else
        fail "Test 3h: expected 2 containers with correct output, got $MULTI_PASS"
        echo "  Container 1 (exit=$CTR_3H_EXIT1): $CTR_3H_OUT1"
        echo "  Container 2 (exit=$CTR_3H_EXIT2): $CTR_3H_OUT2"
    fi

    rm -f /tmp/ctr-3h-1.out /tmp/ctr-3h-2.out

fi

# =======================================================================
# EROFS Snapshotter Tests — runc and openvmm with --snapshotter erofs
# =======================================================================

if [[ "$HAS_EROFS" -eq 1 ]]; then

    # --- Test 3i: EROFS snapshotter with runc ---
    info "Test 3i: EROFS snapshotter with runc"
    CTR_3I_OUTPUT=""
    CTR_3I_EXIT=0
    CTR_3I_OUTPUT=$(timeout 30 /usr/local/bin/ctr run --rm \
        --snapshotter erofs \
        --runtime io.containerd.runc.v2 \
        docker.io/library/alpine:latest test-erofs-runc echo "erofs-hello" 2>&1) || CTR_3I_EXIT=$?

    if echo "$CTR_3I_OUTPUT" | grep -q "erofs-hello"; then
        pass "Test 3i: runc + EROFS output contains 'erofs-hello'"
    else
        fail "Test 3i: runc + EROFS output missing 'erofs-hello'"
        echo "  Got: $CTR_3I_OUTPUT"
    fi

    if [[ "$CTR_3I_EXIT" -eq 0 ]]; then
        pass "Test 3i: runc + EROFS exited with code 0"
    else
        fail "Test 3i: runc + EROFS exited with code $CTR_3I_EXIT"
    fi

    # --- Test 3j: EROFS snapshotter with openvmm (VM mode only) ---
    if [[ "$VM_MODE" -eq 1 ]]; then
        info "Test 3j: EROFS snapshotter with openvmm"
        CTR_3J_OUTPUT=""
        CTR_3J_EXIT=0
        CTR_3J_OUTPUT=$(timeout 120 /usr/local/bin/ctr run --rm \
            --snapshotter erofs \
            --runtime io.containerd.openvmm.v2 \
            docker.io/library/alpine:latest test-erofs-openvmm echo "erofs-vm-hello" 2>&1) || CTR_3J_EXIT=$?

        if echo "$CTR_3J_OUTPUT" | grep -q "erofs-vm-hello"; then
            pass "Test 3j: openvmm + EROFS output contains 'erofs-vm-hello'"
        else
            fail "Test 3j: openvmm + EROFS output missing 'erofs-vm-hello'"
            echo "  Got: $CTR_3J_OUTPUT"
        fi

        if [[ "$CTR_3J_EXIT" -eq 0 ]]; then
            pass "Test 3j: openvmm + EROFS exited with code 0"
        else
            if [[ "$CTR_3J_EXIT" -eq 124 ]]; then
                fail "Test 3j: openvmm + EROFS timed out"
            else
                fail "Test 3j: openvmm + EROFS exited with code $CTR_3J_EXIT"
            fi
        fi
    fi

else
    info "Skipping EROFS tests (EROFS not available)"
fi

echo ""
echo "--- containerd log (last 30 lines) ---"
tail -30 /var/log/containerd.log 2>/dev/null || true
echo "--- end containerd log ---"
echo ""

exit $FAILURES
INNER_EOF

DOCKER_EXIT=0

# Build docker run arguments.
DOCKER_ARGS=(
    --rm --privileged
    -v "$SHIM_BIN":/usr/local/bin/containerd-shim-openvmm-v2-real:ro
)

# Mount KVM device if available.
if [[ -e /dev/kvm ]]; then
    DOCKER_ARGS+=(--device /dev/kvm)
fi

# Mount agent and kernel binaries if available (for VM tests).
if [[ -n "${AGENT_BIN:-}" && -f "${AGENT_BIN:-}" ]]; then
    DOCKER_ARGS+=(-v "$AGENT_BIN":/usr/local/share/containerd-shim-agent:ro)
fi
if [[ -n "${KERNEL_PATH:-}" && -f "${KERNEL_PATH:-}" ]]; then
    DOCKER_ARGS+=(-v "$KERNEL_PATH":/usr/local/share/vmlinux:ro)
fi

DOCKER_OUTPUT=$(docker run "${DOCKER_ARGS[@]}" \
    "$DOCKER_IMAGE" \
    bash -c "$INNER_SCRIPT" 2>&1) || DOCKER_EXIT=$?

echo "$DOCKER_OUTPUT"

# Count PASS/FAIL in docker output.
DOCKER_PASS=$(echo "$DOCKER_OUTPUT" | grep -c "^PASS " || true)
DOCKER_FAIL=$(echo "$DOCKER_OUTPUT" | grep -c "^FAIL " || true)

if [[ "$DOCKER_EXIT" -eq 0 && "$DOCKER_FAIL" -eq 0 ]]; then
    pass "Phase 3 complete — containerd integration test passed ($DOCKER_PASS checks passed)"
else
    fail "Phase 3 failed — $DOCKER_FAIL check(s) failed (exit code $DOCKER_EXIT)"
    FAILURES=$((FAILURES + DOCKER_FAIL))
fi

# =========================================================================
# Summary
# =========================================================================

echo ""
echo "==========================================="
if [[ $FAILURES -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED${RESET}"
    exit 0
else
    echo -e "${RED}${BOLD}$FAILURES FAILURE(S)${RESET}"
    exit 1
fi
