#!/usr/bin/env bash
#
# Launch an AFL fuzzing campaign (CPU or GPU) with master/secondary topology.
#
# All instances share a single sync directory so cross-sync propagates
# findings between harnesses automatically.
#
# Usage (CPU, default):
#   ./run.sh                          # auto-size to nproc, 24h
#   ./run.sh --duration-seconds 3600  # 1-hour run
#   ./run.sh --deser-secondary 5      # force the number of secondaries for harness-deser
#   ./run.sh --total-cores 16         # simulate a 16-core machine
#
# Usage (GPU):
#   ./run.sh --gpu                         # auto-detect GPUs, 24h
#   ./run.sh --gpu --duration-seconds 3600 # 1-hour GPU run
#   ./run.sh --gpu --compute-secondary 5   # force secondary count (overrides 2*NUM_GPUS-1)
#
# CPU sizing model:
#   3 masters (one per harness: deser, verify, compute), nproc-3 secondaries
#   split by harness weight.  Default ratio deser:verify:compute = 1:3:8 reflects
#   per-exec cost (compute is slowest and gets the largest share).  This ratio can
#   be improved over time based on campaign reports.
#
# GPU sizing model:
#   1 master + (2*NUM_GPUS-1) secondaries for the cuda_compute harness.
#   Instances are pinned to GPUs via CUDA_VISIBLE_DEVICES (round-robin).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Shared defaults ─────────────────────────────────────────────────────────
CORPUS_DIR="$SCRIPT_DIR/corpus"
SYNC_DIR="$SCRIPT_DIR/sync_dir"
# Also set in .github/workflows/fuzzing.yml and .github/workflows/gpu_fuzzing.yml
DURATION_SECONDS=86400  # 24 hours
# Which instances keep a per-instance log: all | masters | none.
#
# 'masters' can be used to debug a deterministic issue that will affect all the instances identically.
# Use 'all' to debug an intermittent issue. But beware that it may consume a lot of disk space in
# real-life campaigns.
LOG_MODE=masters
GPU_MODE=0

# ── CPU-specific defaults ────────────────────────────────────────────────────
TOTAL_CORES=""  # empty = auto-detect via nproc
DESER_WEIGHT=1
VERIFY_WEIGHT=3
COMPUTE_WEIGHT=8
# Empty means "derive from cores * weight / sum_weights"; an explicit value pins that harness.
DESER_SECONDARY=""
VERIFY_SECONDARY=""
COMPUTE_SECONDARY=""

# ── Parse arguments ────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Mode:"
    echo "  --gpu                    GPU mode: fuzz the cuda_compute harness (default: CPU)"
    echo ""
    echo "CPU sizing options (ignored in --gpu mode):"
    echo "  --total-cores N          Override auto-detected core count (default: nproc)"
    echo "  --deser-weight N         Weight for deser secondaries (default: 1)"
    echo "  --verify-weight N        Weight for verify secondaries (default: 3)"
    echo "  --compute-weight N       Weight for compute secondaries (default: 8)"
    echo "  --deser-secondary N      Force deser secondaries count (overrides derivation)"
    echo "  --verify-secondary N     Force verify secondaries count (overrides derivation)"
    echo ""
    echo "Sizing options (both modes):"
    echo "  --compute-secondary N    Force compute/cuda_compute secondaries count"
    echo "                           CPU default: derived from weights; GPU default: 2*NUM_GPUS-1"
    echo ""
    echo "Other options:"
    echo "  --corpus-dir DIR         Initial corpus directory (default: $SCRIPT_DIR/corpus)"
    echo "  --sync-dir DIR           AFL sync/output directory (default: $SCRIPT_DIR/sync_dir)"
    echo "  --duration-seconds N     Campaign duration in seconds (default: $DURATION_SECONDS)"
    echo "  --logs MODE              Per-instance logs: all|masters|none (default: $LOG_MODE)"
    echo "                           'all' costs ~8 G/h of AFL status text at 192 instances"
    echo "  -h, --help               Show this help message"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gpu)               GPU_MODE=1; shift ;;
        --corpus-dir)        CORPUS_DIR="$2"; shift 2 ;;
        --sync-dir)          SYNC_DIR="$2"; shift 2 ;;
        --duration-seconds)  DURATION_SECONDS="$2"; shift 2 ;;
        --logs)              LOG_MODE="$2"; shift 2 ;;
        --total-cores)       TOTAL_CORES="$2"; shift 2 ;;
        --deser-weight)      DESER_WEIGHT="$2"; shift 2 ;;
        --verify-weight)     VERIFY_WEIGHT="$2"; shift 2 ;;
        --compute-weight)    COMPUTE_WEIGHT="$2"; shift 2 ;;
        --deser-secondary)   DESER_SECONDARY="$2"; shift 2 ;;
        --verify-secondary)  VERIFY_SECONDARY="$2"; shift 2 ;;
        --compute-secondary) COMPUTE_SECONDARY="$2"; shift 2 ;;
        -h|--help)           usage; exit 0 ;;
        *)                   echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

TARGET_DIR="$(cargo metadata --format-version=1 --no-deps --manifest-path "$REPO_ROOT/Cargo.toml" \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["target_directory"])')"

# ── Mode-specific sizing and harness list ───────────────────────────────────
# HARNESS_NAMES:     logical names; binary path is harness-${name//_/-} under release/.
# HARNESS_SECONDARY: parallel array of secondary counts (one entry per harness).
# EXTRA_AFL_FLAGS:   extra flags forwarded to every `cargo afl fuzz` invocation.
# NUM_GPUS:          0 on CPU (device id is always 0 and ignored); actual count on GPU.
HARNESS_NAMES=()
HARNESS_SECONDARY=()
EXTRA_AFL_FLAGS=()
NUM_GPUS=0

if [[ "$GPU_MODE" == 1 ]]; then
    NUM_GPUS=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l) || true
    if (( NUM_GPUS == 0 )); then
        echo "ERROR: No GPUs detected (nvidia-smi returned nothing)." >&2
        exit 1
    fi
    COMPUTE_SECONDARY="${COMPUTE_SECONDARY:-$(( 2 * NUM_GPUS - 1 ))}"
    HARNESS_NAMES=(cuda_compute)
    HARNESS_SECONDARY=("$COMPUTE_SECONDARY")
    EXTRA_AFL_FLAGS=(-t 100000)
else
    [[ -z "$TOTAL_CORES" ]] && TOTAL_CORES="$(nproc)"
    if (( TOTAL_CORES < 3 )); then
        echo "ERROR: need at least 3 cores (one master per harness); got $TOTAL_CORES" >&2
        exit 1
    fi
    sum_weights=$(( DESER_WEIGHT + VERIFY_WEIGHT + COMPUTE_WEIGHT ))
    if (( sum_weights <= 0 )); then
        echo "ERROR: sum of --*-weight must be > 0; got $sum_weights" >&2
        exit 1
    fi
    # 3 masters consume 3 cores; the rest is the secondaries budget.
    budget=$(( TOTAL_CORES - 3 ))
    default_deser=$(( budget * DESER_WEIGHT / sum_weights ))
    default_verify=$(( budget * VERIFY_WEIGHT / sum_weights ))
    # Compute absorbs the floor-division remainder (it's the slowest harness, so an extra worker
    # there has the biggest impact on coverage rate).
    default_compute=$(( budget - default_deser - default_verify ))
    DESER_SECONDARY="${DESER_SECONDARY:-$default_deser}"
    VERIFY_SECONDARY="${VERIFY_SECONDARY:-$default_verify}"
    COMPUTE_SECONDARY="${COMPUTE_SECONDARY:-$default_compute}"
    HARNESS_NAMES=(deser verify compute)
    HARNESS_SECONDARY=("$DESER_SECONDARY" "$VERIFY_SECONDARY" "$COMPUTE_SECONDARY")
fi

# ── Validate ───────────────────────────────────────────────────────────────
case "$LOG_MODE" in
    all|masters|none) ;;
    *) echo "ERROR: --logs must be one of all|masters|none; got '$LOG_MODE'" >&2; exit 1 ;;
esac

for name in "${HARNESS_NAMES[@]}"; do
    bin="$TARGET_DIR/release/harness-${name//_/-}"
    if [[ ! -x "$bin" ]]; then
        if [[ "$GPU_MODE" == 1 ]]; then
            echo "ERROR: $bin not found. Run: cd utils/fuzz && ./build.sh --gpu" >&2
        else
            echo "ERROR: $bin not found. Run build.sh first." >&2
        fi
        exit 1
    fi
done

if [[ ! -d "$CORPUS_DIR" ]] || [[ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]]; then
    echo "ERROR: Corpus directory '$CORPUS_DIR' is missing or empty." >&2
    if [[ "$GPU_MODE" == 1 ]]; then
        echo "       Run: make fuzz_gpu_precampaign" >&2
    else
        echo "       Run: build.sh --corpusgen" >&2
    fi
    exit 1
fi

# ── Summary ────────────────────────────────────────────────────────────────
TOTAL=0
for secondary in "${HARNESS_SECONDARY[@]}"; do
    TOTAL=$(( TOTAL + 1 + secondary ))
done

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

if [[ "$GPU_MODE" == 1 ]]; then
    echo "==> Launching GPU campaign: $TOTAL instances across $NUM_GPUS GPU(s) (duration: ${DURATION_SECONDS}s)"
else
    echo "==> Launching $TOTAL AFL instances (duration: ${DURATION_SECONDS}s)"
fi
for idx in "${!HARNESS_NAMES[@]}"; do
    echo "    ${HARNESS_NAMES[$idx]}: 1 master + ${HARNESS_SECONDARY[$idx]} secondary"
done
echo "    sync_dir: $SYNC_DIR"
case "$LOG_MODE" in
    all)     echo "    per-instance logs: $LOGS_DIR/<instance>.log (all $TOTAL instances)" ;;
    masters) echo "    per-instance logs: $LOGS_DIR/<harness>_m.log (masters only, secondaries discarded)" ;;
    none)    echo "    per-instance logs: discarded (--logs none)" ;;
esac
echo ""

# ── Environment ────────────────────────────────────────────────────────────
export AFL_NO_UI=1       # disable curses TUI
export AFL_QUIET=1       # suppress AFL's startup banner
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
# Args: <-M|-S> <instance-name> <binary> <device-id>
#   device-id is forwarded as CUDA_VISIBLE_DEVICES; always 0 on CPU (ignored there).
fuzz_instance() {
    local flag="$1" iname="$2" bin="$3" device="$4"

    CUDA_VISIBLE_DEVICES="$device" setsid cargo afl fuzz "$flag" "$iname" \
        "${EXTRA_AFL_FLAGS[@]}" -i "$CORPUS_DIR" -o "$SYNC_DIR" "$bin" \
        > "$(instance_log "$iname")" 2>&1 &
    PIDS+=($!)
}

# ── Launch instances ───────────────────────────────────────────────────────
# Masters always get device 0.  Secondaries are distributed round-robin across GPUs;
# on CPU NUM_GPUS=0 so device is always 0 (ignored anyway).
for idx in "${!HARNESS_NAMES[@]}"; do
    name="${HARNESS_NAMES[$idx]}"
    bin="$TARGET_DIR/release/harness-${name//_/-}"
    secondary="${HARNESS_SECONDARY[$idx]}"

    fuzz_instance -M "${name}_m" "$bin" 0

    for i in $(seq 1 "$secondary"); do
        fuzz_instance -S "${name}_s$i" "$bin" "$(( NUM_GPUS > 0 ? i % NUM_GPUS : 0 ))"
    done
done

# ── Wait for campaign duration ─────────────────────────────────────────────
echo "==> Campaign running. Will stop after ${DURATION_SECONDS}s ($(date -d "+${DURATION_SECONDS} seconds" 2>/dev/null || echo "N/A"))."
echo "    Press Ctrl-C to stop early."
sleep "$DURATION_SECONDS"
