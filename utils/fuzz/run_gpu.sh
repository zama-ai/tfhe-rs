#!/usr/bin/env bash
#
# Launch a GPU AFL fuzzing campaign (single cuda_compute_m master).
#
# Usage:
#   ./run_gpu.sh                          # defaults: 24h
#   ./run_gpu.sh --duration-seconds 1200  # 20-minute run
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Defaults ───────────────────────────────────────────────────────────────
CORPUS_DIR="$SCRIPT_DIR/corpus"
SYNC_DIR="$SCRIPT_DIR/sync_dir"
DURATION_SECONDS=86400  # 24 hours

# ── Parse arguments ────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "  --corpus-dir DIR        Initial corpus directory (default: $SCRIPT_DIR/corpus)"
    echo "  --sync-dir DIR          AFL sync/output directory (default: $SCRIPT_DIR/sync_dir)"
    echo "  --duration-seconds N    Campaign duration in seconds (default: $DURATION_SECONDS)"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpus-dir)       CORPUS_DIR="$2"; shift 2 ;;
        --sync-dir)         SYNC_DIR="$2"; shift 2 ;;
        --duration-seconds) DURATION_SECONDS="$2"; shift 2 ;;
        -h|--help)          usage; exit 0 ;;
        *)                  echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

# ── Validate ───────────────────────────────────────────────────────────────
TARGET_DIR="$(cargo metadata --format-version=1 --no-deps --manifest-path "$REPO_ROOT/Cargo.toml" \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["target_directory"])')"
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

mkdir -p "$SYNC_DIR"

echo "==> Launching GPU campaign: cuda_compute_m (duration: ${DURATION_SECONDS}s)"
echo "    sync_dir: $SYNC_DIR"
echo ""

# ── Environment ────────────────────────────────────────────────────────────
export AFL_NO_UI=1
export AFL_SKIP_CPUFREQ=1
export RAYON_NUM_THREADS=1

# ── Launch (foreground — output goes directly to terminal) ─────────────────
exec cargo afl fuzz -M cuda_compute_m \
    -t 100000 \
    -V "$DURATION_SECONDS" \
    -i "$CORPUS_DIR" \
    -o "$SYNC_DIR" \
    "$CUDA_BIN"
