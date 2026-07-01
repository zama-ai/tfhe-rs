#!/usr/bin/env bash
#
# Launch an AFL fuzzing campaign with master/secondary topology.
#
# All instances share a single sync directory so cross-sync propagates
# findings between harnesses automatically.
#
# Usage:
#   ./run.sh                          # defaults: auto-size to nproc, 4h
#   ./run.sh --duration-seconds 3600  # 1-hour run
#   ./run.sh --deser-secondary 5      # force the number of secondaries for harness-deser
#   ./run.sh --total-cores 16         # simulate a 16-core machine
#
# Sizing model:
#   3 masters (one per harness), nproc-3 secondaries split by harness weight.
#   Default ratio deser:verify:compute = 1:3:8 reflects the per-exec cost of each
#   harness (compute is slowest and gets the largest share). This ratio can be improved
#   over time based on the campaign reports.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Defaults ───────────────────────────────────────────────────────────────
CORPUS_DIR="$SCRIPT_DIR/corpus"
SYNC_DIR="$SCRIPT_DIR/sync_dir"
# Also set in .github/workflows/fuzzing.yml and utils/fuzzing/README.md
DURATION_SECONDS=14400  # 4 hours
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
    echo "Sizing options:"
    echo "  --total-cores N          Override auto-detected core count (default: nproc)"
    echo "  --deser-weight N         Weight for deser secondaries (default: 1)"
    echo "  --verify-weight N        Weight for verify secondaries (default: 3)"
    echo "  --compute-weight N       Weight for compute secondaries (default: 8)"
    echo "  --deser-secondary N      Force deser secondaries count (overrides derivation)"
    echo "  --verify-secondary N     Force verify secondaries count (overrides derivation)"
    echo "  --compute-secondary N    Force compute secondaries count (overrides derivation)"
    echo ""
    echo "Other options:"
    echo "  --corpus-dir DIR         Initial corpus directory (default: $SCRIPT_DIR/corpus)"
    echo "  --sync-dir DIR           AFL sync/output directory (default: $SCRIPT_DIR/sync_dir)"
    echo "  --duration-seconds N     Campaign duration in seconds (default: $DURATION_SECONDS)"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpus-dir)        CORPUS_DIR="$2"; shift 2 ;;
        --sync-dir)          SYNC_DIR="$2"; shift 2 ;;
        --duration-seconds)  DURATION_SECONDS="$2"; shift 2 ;;
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

# ── Derive per-harness instance counts from cores + weights ────────────────
[[ -z "$TOTAL_CORES" ]] && TOTAL_CORES="$(nproc)"
if (( TOTAL_CORES < 3 )); then
    echo "ERROR: need at least 3 cores (one master per harness); got $TOTAL_CORES" >&2
    exit 1
fi
sum_weights=$((DESER_WEIGHT + VERIFY_WEIGHT + COMPUTE_WEIGHT))
if (( sum_weights <= 0 )); then
    echo "ERROR: sum of --*-weight must be > 0; got $sum_weights" >&2
    exit 1
fi
# 3 masters consume 3 cores; the rest is the secondaries budget.
budget=$((TOTAL_CORES - 3))
default_deser=$((budget * DESER_WEIGHT / sum_weights))
default_verify=$((budget * VERIFY_WEIGHT / sum_weights))
# Compute absorbs the floor-division remainder (it's the slowest harness, so an extra worker
# there has the biggest impact on coverage rate).
default_compute=$((budget - default_deser - default_verify))
DESER_SECONDARY="${DESER_SECONDARY:-$default_deser}"
VERIFY_SECONDARY="${VERIFY_SECONDARY:-$default_verify}"
COMPUTE_SECONDARY="${COMPUTE_SECONDARY:-$default_compute}"

# ── Validate ───────────────────────────────────────────────────────────────
TARGET_DIR="$(cargo metadata --format-version=1 --no-deps --manifest-path "$REPO_ROOT/Cargo.toml" \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["target_directory"])')"
DESER_BIN="$TARGET_DIR/release/harness-deser"
VERIFY_BIN="$TARGET_DIR/release/harness-verify"
COMPUTE_BIN="$TARGET_DIR/release/harness-compute"

for bin in "$DESER_BIN" "$VERIFY_BIN" "$COMPUTE_BIN"; do
    if [[ ! -x "$bin" ]]; then
        echo "ERROR: $bin not found. Run build.sh first."
        exit 1
    fi
done

if [[ ! -d "$CORPUS_DIR" ]] || [[ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]]; then
    echo "ERROR: Corpus directory '$CORPUS_DIR' is missing or empty."
    echo "       Run: build.sh --corpusgen"
    exit 1
fi

TOTAL=$((3 + DESER_SECONDARY + VERIFY_SECONDARY + COMPUTE_SECONDARY))
# Per-instance stdout/stderr is redirected here so the terminal stays quiet during the run.
# Cleaned along with sync_dir by `make fuzz_clean`.
LOGS_DIR="$SYNC_DIR/_logs"
mkdir -p "$LOGS_DIR"
echo "==> Launching $TOTAL AFL instances (duration: ${DURATION_SECONDS}s)"
echo "    deser:   1 master + $DESER_SECONDARY secondary"
echo "    verify:  1 master + $VERIFY_SECONDARY secondary"
echo "    compute: 1 master + $COMPUTE_SECONDARY secondary"
echo "    sync_dir: $SYNC_DIR"
echo "    per-instance logs: $LOGS_DIR/<instance>.log"
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

# Each instance runs under `setsid`, so that we can easily clean any spawned subprocess.
# Each instance's stdout+stderr goes to its own log under $LOGS_DIR.
#
# ── Master instances ──────────────────────────────────────────────────────
setsid cargo afl fuzz -M deser_m   -i "$CORPUS_DIR" -o "$SYNC_DIR" "$DESER_BIN" \
    > "$LOGS_DIR/deser_m.log" 2>&1 &
PIDS+=($!)

setsid cargo afl fuzz -M verify_m  -i "$CORPUS_DIR" -o "$SYNC_DIR" "$VERIFY_BIN" \
    > "$LOGS_DIR/verify_m.log" 2>&1 &
PIDS+=($!)

setsid cargo afl fuzz -M compute_m -i "$CORPUS_DIR" -o "$SYNC_DIR" "$COMPUTE_BIN" \
    > "$LOGS_DIR/compute_m.log" 2>&1 &
PIDS+=($!)

# ── Secondaries ───────────────────────────────────────────────────────────
# `-c -` explicitly disables CMPLOG on secondaries. In the current setup, harnesses are not compiled
# for cmplog anyway but it is harmless and would be necessary if we enable it later.
for i in $(seq 1 "$DESER_SECONDARY"); do
    setsid cargo afl fuzz -S "deser_s$i" -c - -i "$CORPUS_DIR" -o "$SYNC_DIR" "$DESER_BIN" \
        > "$LOGS_DIR/deser_s$i.log" 2>&1 &
    PIDS+=($!)
done

for i in $(seq 1 "$VERIFY_SECONDARY"); do
    setsid cargo afl fuzz -S "verify_s$i" -c - -i "$CORPUS_DIR" -o "$SYNC_DIR" "$VERIFY_BIN" \
        > "$LOGS_DIR/verify_s$i.log" 2>&1 &
    PIDS+=($!)
done

for i in $(seq 1 "$COMPUTE_SECONDARY"); do
    setsid cargo afl fuzz -S "compute_s$i" -c - -i "$CORPUS_DIR" -o "$SYNC_DIR" "$COMPUTE_BIN" \
        > "$LOGS_DIR/compute_s$i.log" 2>&1 &
    PIDS+=($!)
done

# ── Wait for campaign duration ─────────────────────────────────────────────
echo "==> Campaign running. Will stop after ${DURATION_SECONDS}s ($(date -d "+${DURATION_SECONDS} seconds" 2>/dev/null || echo "N/A"))."
echo "    Press Ctrl-C to stop early."
sleep "$DURATION_SECONDS"
