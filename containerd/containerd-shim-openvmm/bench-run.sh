#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Benchmark script for containerd-shim-openvmm.
# Runs inside the bench container image. Measures end-to-end latency of
# running a hello-world container through containerd, comparing the openvmm
# shim (microVM) against runc (native).
#
# Usage (inside container):
#   bench-run.sh [OPTIONS]
#
# Options:
#   -n NUM      Number of benchmark iterations (default: 10)
#   -w NUM      Number of warmup iterations (default: 1)
#   -c CMD      Container command (default: "echo hello")
#   --no-net    Disable consomme networking (faster boot)
#   --runc-only Only benchmark runc (skip openvmm)
#   --openvmm-only  Only benchmark openvmm (skip runc)
#   --csv       Output results as CSV (machine-readable)
#   --json      Output results as JSON
#   -h/--help   Show this help

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
ITERATIONS=10
WARMUP=1
CTR_CMD="echo hello"
NETWORKING=true
OUTPUT_FORMAT="text"  # text | csv | json
BENCH_RUNC=true
BENCH_OPENVMM=true

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -n)         ITERATIONS="$2"; shift 2 ;;
        -w)         WARMUP="$2"; shift 2 ;;
        -c)         CTR_CMD="$2"; shift 2 ;;
        --no-net)   NETWORKING=false; shift ;;
        --runc-only)    BENCH_OPENVMM=false; shift ;;
        --openvmm-only) BENCH_RUNC=false; shift ;;
        --csv)      OUTPUT_FORMAT="csv"; shift ;;
        --json)     OUTPUT_FORMAT="json"; shift ;;
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
info() { echo "==> $1" >&2; }

# Returns wall-clock milliseconds for a command.
time_ms() {
    local start end
    start=$(date +%s%N)
    "$@"
    end=$(date +%s%N)
    echo $(( (end - start) / 1000000 ))
}

# Compute stats from a newline-separated list of numbers on stdin.
# Outputs: count min max avg p50 p95 (space-separated).
compute_stats() {
    sort -n | awk '
    {
        a[NR] = $1
        sum += $1
    }
    END {
        n = NR
        if (n == 0) { print "0 0 0 0 0 0"; exit }
        min = a[1]
        max = a[n]
        avg = sum / n

        # p50
        idx = int(n * 0.50)
        if (idx < 1) idx = 1
        p50 = a[idx]

        # p95
        idx = int(n * 0.95)
        if (idx < 1) idx = 1
        p95 = a[idx]

        printf "%d %d %d %.1f %d %d\n", n, min, max, avg, p50, p95
    }'
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
info "Pre-flight checks"

if [[ "$BENCH_OPENVMM" == "true" ]]; then
    if [[ ! -e /dev/kvm ]]; then
        echo "ERROR: /dev/kvm not available. Run with --device /dev/kvm" >&2
        exit 1
    fi

    if [[ ! -f /usr/local/share/vmlinux ]]; then
        echo "ERROR: kernel not found at /usr/local/share/vmlinux" >&2
        exit 1
    fi

    if [[ ! -f /usr/local/share/containerd-shim-agent ]]; then
        echo "ERROR: agent not found at /usr/local/share/containerd-shim-agent" >&2
        exit 1
    fi
fi

# Configure networking env var for the shim wrapper.
if [[ "$NETWORKING" == "false" ]]; then
    # Patch the wrapper to disable networking.
    cat > /usr/local/bin/containerd-shim-openvmm-v2 << 'EOF'
#!/bin/bash
export OPENVMM_SHIM_KERNEL=/usr/local/share/vmlinux
export OPENVMM_SHIM_AGENT=/usr/local/share/containerd-shim-agent
export OPENVMM_SHIM_NETWORKING=false
exec /usr/local/bin/containerd-shim-openvmm-v2-real "$@"
EOF
    chmod +x /usr/local/bin/containerd-shim-openvmm-v2
fi

# ---------------------------------------------------------------------------
# Start containerd
# ---------------------------------------------------------------------------
info "Starting containerd"
/usr/local/bin/containerd &>/var/log/containerd.log &
CONTAINERD_PID=$!
trap "kill $CONTAINERD_PID 2>/dev/null; wait $CONTAINERD_PID 2>/dev/null" EXIT

READY=0
for i in $(seq 1 30); do
    if /usr/local/bin/ctr version &>/dev/null; then
        READY=1
        break
    fi
    sleep 0.5
done

if [[ "$READY" -ne 1 ]]; then
    echo "ERROR: containerd failed to start" >&2
    cat /var/log/containerd.log >&2
    exit 1
fi
info "containerd ready"

# Pull the alpine image if not already present.
if ! /usr/local/bin/ctr image ls -q 2>/dev/null | grep -q "alpine"; then
    info "Pulling alpine image..."
    /usr/local/bin/ctr image pull docker.io/library/alpine:latest >/dev/null 2>&1 || {
        echo "ERROR: failed to pull alpine image" >&2
        exit 1
    }
fi

# Unpack for native snapshotter (needed inside Docker where overlay isn't available).
/usr/local/bin/ctr image unpack --snapshotter native docker.io/library/alpine:latest >/dev/null 2>&1 || true
info "alpine image ready"

# ---------------------------------------------------------------------------
# Run a single container and return its wall-clock time in ms.
# Args: <runtime> <container-id> <command...>
#   runtime: "openvmm" or "runc"
# ---------------------------------------------------------------------------
run_one() {
    local runtime="$1"; shift
    local cid="$1"; shift
    local runtime_flag
    if [[ "$runtime" == "openvmm" ]]; then
        runtime_flag="io.containerd.openvmm.v2"
    else
        runtime_flag="io.containerd.runc.v2"
    fi
    local ms
    ms=$(time_ms /usr/local/bin/ctr run --rm \
        --snapshotter native \
        --runtime "$runtime_flag" \
        docker.io/library/alpine:latest "$cid" "$@")
    echo "$ms"
}

# ---------------------------------------------------------------------------
# Benchmark a single runtime. Sets RESULTS_* vars.
# Args: <runtime-name> <label>
# ---------------------------------------------------------------------------
bench_runtime() {
    local runtime="$1"
    local label="$2"

    info "--- $label ---"

    # Warmup
    if [[ "$WARMUP" -gt 0 ]]; then
        info "Warmup: $WARMUP iteration(s)"
        for i in $(seq 1 "$WARMUP"); do
            ms=$(run_one "$runtime" "${runtime}-warmup-$i" $CTR_CMD 2>&1 | tail -1)
            info "  warmup $i: ${ms} ms"
        done
    fi

    # Benchmark
    info "Benchmark: $ITERATIONS iteration(s) — cmd: $CTR_CMD"
    local results=()
    for i in $(seq 1 "$ITERATIONS"); do
        ms=$(run_one "$runtime" "${runtime}-bench-$i" $CTR_CMD 2>&1 | tail -1)
        results+=("$ms")
        info "  run $i: ${ms} ms"
    done

    # Compute stats
    local stats
    stats=$(printf '%s\n' "${results[@]}" | compute_stats)
    local count min max avg p50 p95
    read -r count min max avg p50 p95 <<< "$stats"

    # Export results via global associative arrays
    BENCH_LABEL["$runtime"]="$label"
    BENCH_COUNT["$runtime"]=$count
    BENCH_MIN["$runtime"]=$min
    BENCH_MAX["$runtime"]=$max
    BENCH_AVG["$runtime"]=$avg
    BENCH_P50["$runtime"]=$p50
    BENCH_P95["$runtime"]=$p95
    BENCH_INDIVIDUAL["$runtime"]=$(IFS=,; echo "${results[*]}")
}

# ---------------------------------------------------------------------------
# Run benchmarks
# ---------------------------------------------------------------------------
declare -A BENCH_LABEL BENCH_COUNT BENCH_MIN BENCH_MAX BENCH_AVG BENCH_P50 BENCH_P95 BENCH_INDIVIDUAL
BENCH_ORDER=()

if [[ "$BENCH_RUNC" == "true" ]]; then
    bench_runtime "runc" "runc (native)"
    BENCH_ORDER+=("runc")
fi

if [[ "$BENCH_OPENVMM" == "true" ]]; then
    bench_runtime "openvmm" "openvmm (microVM)"
    BENCH_ORDER+=("openvmm")
fi

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
case "$OUTPUT_FORMAT" in
    text)
        echo ""
        echo "========================================"
        echo "  containerd shim benchmark"
        echo "========================================"
        echo "  command:    $CTR_CMD"
        echo "  networking: $NETWORKING"
        echo ""
        printf "  %-20s %8s %8s %8s %8s %8s %8s\n" "runtime" "n" "min" "max" "avg" "p50" "p95"
        printf "  %-20s %8s %8s %8s %8s %8s %8s\n" "-------" "---" "---" "---" "---" "---" "---"
        for rt in "${BENCH_ORDER[@]}"; do
            printf "  %-20s %8s %7s %7s %7s %7s %7s\n" \
                "${BENCH_LABEL[$rt]}" \
                "${BENCH_COUNT[$rt]}" \
                "${BENCH_MIN[$rt]} ms" \
                "${BENCH_MAX[$rt]} ms" \
                "${BENCH_AVG[$rt]} ms" \
                "${BENCH_P50[$rt]} ms" \
                "${BENCH_P95[$rt]} ms"
        done
        # Show speedup ratio if both runtimes were benchmarked.
        if [[ -n "${BENCH_AVG[runc]:-}" && -n "${BENCH_AVG[openvmm]:-}" ]]; then
            RATIO=$(echo "${BENCH_AVG[openvmm]} / ${BENCH_AVG[runc]}" | bc -l 2>/dev/null || echo "?")
            printf "\n  openvmm/runc ratio: %.1fx\n" "$RATIO"
        fi
        echo "========================================"
        ;;
    csv)
        echo "runtime,command,iterations,networking,min_ms,max_ms,avg_ms,p50_ms,p95_ms"
        for rt in "${BENCH_ORDER[@]}"; do
            echo "\"${BENCH_LABEL[$rt]}\",\"$CTR_CMD\",${BENCH_COUNT[$rt]},$NETWORKING,${BENCH_MIN[$rt]},${BENCH_MAX[$rt]},${BENCH_AVG[$rt]},${BENCH_P50[$rt]},${BENCH_P95[$rt]}"
        done
        ;;
    json)
        echo "{"
        echo "  \"command\": \"$CTR_CMD\","
        echo "  \"networking\": $NETWORKING,"
        echo "  \"results\": ["
        local_comma=""
        for rt in "${BENCH_ORDER[@]}"; do
            echo "$local_comma    {"
            echo "      \"runtime\": \"${BENCH_LABEL[$rt]}\","
            echo "      \"iterations\": ${BENCH_COUNT[$rt]},"
            echo "      \"individual_ms\": [${BENCH_INDIVIDUAL[$rt]}],"
            echo "      \"min_ms\": ${BENCH_MIN[$rt]},"
            echo "      \"max_ms\": ${BENCH_MAX[$rt]},"
            echo "      \"avg_ms\": ${BENCH_AVG[$rt]},"
            echo "      \"p50_ms\": ${BENCH_P50[$rt]},"
            echo "      \"p95_ms\": ${BENCH_P95[$rt]}"
            echo -n "    }"
            local_comma=","
        done
        echo ""
        echo "  ]"
        echo "}"
        ;;
esac
