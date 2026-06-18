#!/usr/bin/env bash
#
# Launch an AFL fuzzing campaign with master/secondary topology.
#
# All instances share a single sync directory so cross-sync propagates
# findings between harnesses automatically.
#
# Usage:
#   ./run.sh                          # defaults: 16 cores, 24h
#   ./run.sh --duration 3600          # 1-hour run
#   ./run.sh --deser-secondary 5      # more deser secondaries
#
# Environment:
#   RAYON_NUM_THREADS is forced to 1 (see doc for rationale).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Defaults (matching doc: 16-core layout) ────────────────────────────────
CORPUS_DIR="$SCRIPT_DIR/corpus"
SYNC_DIR="$SCRIPT_DIR/sync_dir"
DESER_SECONDARY=3
VERIFY_SECONDARY=3
COMPUTE_SECONDARY=5
DURATION=86400  # 24 hours

# ── Parse arguments ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpus-dir)       CORPUS_DIR="$2";       shift 2 ;;
        --sync-dir)         SYNC_DIR="$2";         shift 2 ;;
        --deser-secondary)  DESER_SECONDARY="$2";  shift 2 ;;
        --verify-secondary) VERIFY_SECONDARY="$2"; shift 2 ;;
        --compute-secondary) COMPUTE_SECONDARY="$2"; shift 2 ;;
        --duration)         DURATION="$2";         shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --corpus-dir DIR         Initial corpus directory (default: $SCRIPT_DIR/corpus)"
            echo "  --sync-dir DIR           AFL sync/output directory (default: $SCRIPT_DIR/sync_dir)"
            echo "  --deser-secondary N      Number of deser secondaries (default: 3)"
            echo "  --verify-secondary N     Number of verify secondaries (default: 3)"
            echo "  --compute-secondary N    Number of compute secondaries (default: 5)"
            echo "  --duration SECONDS       Campaign duration in seconds (default: 86400)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Validate ───────────────────────────────────────────────────────────────
DESER_BIN="$REPO_ROOT/target/release/harness-deser"
VERIFY_BIN="$REPO_ROOT/target/release/harness-verify"
COMPUTE_BIN="$REPO_ROOT/target/release/harness-compute"

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
echo "==> Launching $TOTAL AFL instances (duration: ${DURATION}s)"
echo "    deser:   1 master + $DESER_SECONDARY secondary"
echo "    verify:  1 master + $VERIFY_SECONDARY secondary"
echo "    compute: 1 master + $COMPUTE_SECONDARY secondary"
echo "    sync_dir: $SYNC_DIR"
echo ""

# ── Environment ────────────────────────────────────────────────────────────
export AFL_NO_UI=1
export AFL_SKIP_CPUFREQ=1
export RAYON_NUM_THREADS=1

PIDS=()

cleanup() {
    echo ""
    echo "==> Sending SIGINT to all AFL instances..."
    for pid in "${PIDS[@]}"; do
        kill -INT "$pid" 2>/dev/null || true
    done
    wait
    echo "==> All instances stopped."
}

trap cleanup EXIT

# ── Master instances (CMPLOG enabled by default) ──────────────────────────
cargo afl fuzz -M deser_m   -i "$CORPUS_DIR" -o "$SYNC_DIR" "$DESER_BIN" &
PIDS+=($!)

cargo afl fuzz -M verify_m  -i "$CORPUS_DIR" -o "$SYNC_DIR" "$VERIFY_BIN" &
PIDS+=($!)

cargo afl fuzz -M compute_m -i "$CORPUS_DIR" -o "$SYNC_DIR" "$COMPUTE_BIN" &
PIDS+=($!)

# ── Secondaries (CMPLOG disabled with -c -) ───────────────────────────────
for i in $(seq 1 "$DESER_SECONDARY"); do
    cargo afl fuzz -S "deser_s$i" -c - -i "$CORPUS_DIR" -o "$SYNC_DIR" "$DESER_BIN" &
    PIDS+=($!)
done

for i in $(seq 1 "$VERIFY_SECONDARY"); do
    cargo afl fuzz -S "verify_s$i" -c - -i "$CORPUS_DIR" -o "$SYNC_DIR" "$VERIFY_BIN" &
    PIDS+=($!)
done

for i in $(seq 1 "$COMPUTE_SECONDARY"); do
    cargo afl fuzz -S "compute_s$i" -c - -i "$CORPUS_DIR" -o "$SYNC_DIR" "$COMPUTE_BIN" &
    PIDS+=($!)
done

# ── Wait for campaign duration ─────────────────────────────────────────────
echo "==> Campaign running. Will stop after ${DURATION}s ($(date -d "+${DURATION} seconds" 2>/dev/null || echo "N/A"))."
echo "    Press Ctrl-C to stop early."
sleep "$DURATION"
