#!/usr/bin/env bash
#
# Launch a GPU AFL fuzzing campaign with master/secondary topology.
#
# Detects available GPUs via nvidia-smi and launches 2 instances per GPU:
# one AFL master (GPU 0) and the rest as secondaries, each pinned to a GPU
# via CUDA_VISIBLE_DEVICES using round-robin assignment.
#
# All instances share a single sync directory so cross-instance sync propagates
# findings automatically.
#
# Usage:
#   ./run_gpu.sh                          # auto-detect GPUs, 24h
#   ./run_gpu.sh --duration-seconds 3600  # 1-hour run
#   ./run_gpu.sh --compute-secondary 5    # force secondary count (overrides 2*NUM_GPUS-1)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Defaults ───────────────────────────────────────────────────────────────
CORPUS_DIR="$SCRIPT_DIR/corpus"
SYNC_DIR="$SCRIPT_DIR/sync_dir"
# Also set in .github/workflows/gpu_fuzzing.yml
DURATION_SECONDS=86400  # 24 hours
# Which instances keep a per-instance log: all | masters | none.
LOG_MODE=masters
# Empty = derive from 2*NUM_GPUS-1; an explicit value pins the count.
COMPUTE_SECONDARY=""

# ── Parse arguments ────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Sizing options:"
    echo "  --compute-secondary N    Force secondary count (default: 2*NUM_GPUS-1)"
    echo ""
    echo "Other options:"
    echo "  --corpus-dir DIR         Initial corpus directory (default: $SCRIPT_DIR/corpus)"
    echo "  --sync-dir DIR           AFL sync/output directory (default: $SCRIPT_DIR/sync_dir)"
    echo "  --duration-seconds N     Campaign duration in seconds (default: $DURATION_SECONDS)"
    echo "  --logs MODE              Per-instance logs: all|masters|none (default: $LOG_MODE)"
    echo "  -h, --help               Show this help message"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpus-dir)        CORPUS_DIR="$2"; shift 2 ;;
        --sync-dir)          SYNC_DIR="$2"; shift 2 ;;
        --duration-seconds)  DURATION_SECONDS="$2"; shift 2 ;;
        --logs)              LOG_MODE="$2"; shift 2 ;;
        --compute-secondary) COMPUTE_SECONDARY="$2"; shift 2 ;;
        -h|--help)           usage; exit 0 ;;
        *)                   echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

TARGET_DIR="$(cargo metadata --format-version=1 --no-deps --manifest-path "$REPO_ROOT/Cargo.toml" \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["target_directory"])')"

# ── Validate ───────────────────────────────────────────────────────────────
CUDA_BIN="$TARGET_DIR/release/harness-cuda-compute"

if [[ ! -x "$CUDA_BIN" ]]; then
    echo "ERROR: $CUDA_BIN not found. Run: cd utils/fuzz && ./build.sh --gpu" >&2
    exit 1
fi

if [[ ! -d "$CORPUS_DIR" ]] || [[ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]]; then
    echo "ERROR: Corpus directory '$CORPUS_DIR' is missing or empty." >&2
    echo "       Run: make fuzz_gpu_precampaign" >&2
    exit 1
fi

case "$LOG_MODE" in
    all|masters|none) ;;
    *) echo "ERROR: --logs must be one of all|masters|none; got '$LOG_MODE'" >&2; exit 1 ;;
esac

# ── Detect GPUs ────────────────────────────────────────────────────────────
NUM_GPUS=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l) || true
if (( NUM_GPUS == 0 )); then
    echo "ERROR: No GPUs detected (nvidia-smi returned nothing)." >&2
    exit 1
fi

COMPUTE_SECONDARY="${COMPUTE_SECONDARY:-$(( 2 * NUM_GPUS - 1 ))}"
TOTAL=$(( 1 + COMPUTE_SECONDARY ))

LOGS_DIR="$SYNC_DIR/_logs"
mkdir -p "$LOGS_DIR"

# Destination for an instance's stdout+stderr, honouring $LOG_MODE. Masters are
# the instances whose name ends in _m.
instance_log() {
    if [[ "$LOG_MODE" == all ]] || [[ "$LOG_MODE" == masters && "$1" == *_m ]]; then
        echo "$LOGS_DIR/$1.log"
    else
        echo /dev/null
    fi
}

echo "==> Launching GPU campaign: $TOTAL instances across $NUM_GPUS GPU(s) (duration: ${DURATION_SECONDS}s)"
echo "    cuda_compute: 1 master + $COMPUTE_SECONDARY secondary"
echo "    sync_dir: $SYNC_DIR"
case "$LOG_MODE" in
    all)     echo "    per-instance logs: $LOGS_DIR/<instance>.log (all $TOTAL instances)" ;;
    masters) echo "    per-instance logs: $LOGS_DIR/cuda_compute_m.log (master only)" ;;
    none)    echo "    per-instance logs: discarded (--logs none)" ;;
esac
echo ""

# ── Environment ────────────────────────────────────────────────────────────
export AFL_NO_UI=1
export AFL_QUIET=1
export AFL_SKIP_CPUFREQ=1
export RAYON_NUM_THREADS=1

PIDS=()

cleanup() {
    echo ""
    echo "==> Sending SIGINT to all AFL instances..."

    for pid in "${PIDS[@]}"; do
        kill -INT "-$pid" 2>/dev/null || true
    done
    # Give the groups up to 15s to flush fuzzer_stats and exit cleanly.
    # `kill -0` is used as a liveness check
    for _ in $(seq 1 15); do
        local alive=0
        for pid in "${PIDS[@]}"; do
            if kill -0 "-$pid" 2>/dev/null; then alive=1; break; fi
        done
        (( alive == 0 )) && break
        sleep 1
    done
    # Force-kill any group still alive: better to lose a few inflight queue entries than hang.
    for pid in "${PIDS[@]}"; do
        if kill -0 "-$pid" 2>/dev/null; then
            echo "==> Group -$pid did not exit cleanly; sending SIGKILL." >&2
            kill -KILL "-$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo "==> All instances stopped."
}

trap cleanup EXIT

# Each instance runs under `setsid` so we can kill spawned subprocesses as a group.
# GPU 0 hosts the AFL master; secondaries are distributed across GPUs round-robin.
#
# ── Master ─────────────────────────────────────────────────────────────────
CUDA_VISIBLE_DEVICES=0 setsid cargo afl fuzz -M cuda_compute_m \
    -t 100000 -i "$CORPUS_DIR" -o "$SYNC_DIR" "$CUDA_BIN" \
    > "$(instance_log cuda_compute_m)" 2>&1 &
PIDS+=($!)

# ── Secondaries ───────────────────────────────────────────────────────────
for i in $(seq 1 "$COMPUTE_SECONDARY"); do
    g=$(( i % NUM_GPUS ))
    CUDA_VISIBLE_DEVICES=$g setsid cargo afl fuzz -S "cuda_compute_s$i" -c - \
        -t 100000 -i "$CORPUS_DIR" -o "$SYNC_DIR" "$CUDA_BIN" \
        > "$(instance_log "cuda_compute_s$i")" 2>&1 &
    PIDS+=($!)
done

# ── Wait for campaign duration ─────────────────────────────────────────────
echo "==> Campaign running. Will stop after ${DURATION_SECONDS}s ($(date -d "+${DURATION_SECONDS} seconds" 2>/dev/null || echo "N/A"))."
echo "    Press Ctrl-C to stop early."
sleep "$DURATION_SECONDS"
