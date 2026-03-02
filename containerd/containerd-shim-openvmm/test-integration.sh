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

OUTPUT_2C=$("$SHIM_BIN" delete \
    -namespace default -id test-2c \
    -address /tmp/test-2c.sock \
    -publish-binary containerd \
    -bundle "$TMPDIR_2C" 2>&1) || {
    fail "Test 2c: delete command exited non-zero"
    echo "  Output: $OUTPUT_2C"
}

# Validate JSON fields.
if echo "$OUTPUT_2C" | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert 'pid' in d, 'missing pid'
assert 'exitStatus' in d, 'missing exitStatus'
assert 'exitedAt' in d, 'missing exitedAt'
" 2>/dev/null; then
    pass "Test 2c: delete JSON is valid"
else
    fail "Test 2c: delete JSON is invalid or missing fields"
    echo "  Output: $OUTPUT_2C"
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

CONTAINERD_VERSION="2.0.4"
DOCKER_IMAGE="shim-integration-test:containerd-${CONTAINERD_VERSION}"
DOCKERFILE="$REPO_ROOT/containerd/containerd-shim-openvmm/test-integration.Dockerfile"

# Build the test image (Docker layer cache makes repeated runs instant).
info "  Building test image (cached after first run)"
docker build -q \
    --build-arg TARGETARCH="$CONTAINERD_ARCH" \
    --build-arg CONTAINERD_VERSION="$CONTAINERD_VERSION" \
    -t "$DOCKER_IMAGE" \
    -f "$DOCKERFILE" \
    "$REPO_ROOT/containerd/containerd-shim-openvmm" >/dev/null

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

# Verify shim is on PATH.
if command -v containerd-shim-openvmm-v2 &>/dev/null; then
    pass "Shim binary found on PATH: $(which containerd-shim-openvmm-v2)"
else
    fail "Shim binary not found on PATH"
    exit 1
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

# Verify alpine image is available (pre-pulled during docker build).
if /usr/local/bin/ctr image ls -q | grep -q "alpine"; then
    pass "Alpine image available (cached)"
else
    info "Alpine image not cached — pulling"
    /usr/local/bin/ctr image pull docker.io/library/alpine:latest >/dev/null 2>&1 || {
        fail "Failed to pull alpine image"
        echo "--- containerd log (last 30 lines) ---"
        tail -30 /var/log/containerd.log 2>/dev/null || true
        exit 1
    }
    pass "Image pulled"
fi

# --- Run container with our runtime ---
info "Running ctr run --runtime io.containerd.openvmm.v2"
timeout 15 /usr/local/bin/ctr run \
    --runtime io.containerd.openvmm.v2 \
    docker.io/library/alpine:latest test-1 echo hello 2>&1 || true

# Give shim log a moment to flush.
sleep 1

# --- Find and validate shim log ---
info "Looking for shim log"
SHIM_LOG=$(find /run/containerd -name "shim.log" -type f 2>/dev/null | head -1)

if [[ -z "$SHIM_LOG" ]]; then
    fail "shim.log not found under /run/containerd"
    echo "--- Directory listing ---"
    find /run/containerd -type f 2>/dev/null || true
    echo "--- containerd log (last 50 lines) ---"
    tail -50 /var/log/containerd.log 2>/dev/null || true
    exit 1
fi

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

# Bonus checks (don't fail on these).
if grep -q "sandbox.CreateSandbox" "$SHIM_LOG"; then
    info "Bonus: shim.log contains 'sandbox.CreateSandbox'"
fi
if grep -q "task.Start" "$SHIM_LOG"; then
    info "Bonus: shim.log contains 'task.Start'"
fi

echo ""
echo "--- containerd log (last 30 lines) ---"
tail -30 /var/log/containerd.log 2>/dev/null || true
echo "--- end containerd log ---"
echo ""

exit $FAILURES
INNER_EOF

DOCKER_EXIT=0
DOCKER_OUTPUT=$(docker run --rm --privileged \
    -v "$SHIM_BIN":/usr/local/bin/containerd-shim-openvmm-v2:ro \
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
