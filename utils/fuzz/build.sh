#!/usr/bin/env bash
#
# Build fuzz harnesses with AFL instrumentation.
#
# Usage:
#   ./build.sh              # build CPU harnesses only
#   ./build.sh --corpusgen  # also run corpusgen to generate corpus + aux data
#   ./build.sh --gpu        # build GPU harness only (requires CUDA + afl++)
#   ./build.sh --gpu --corpusgen  # build GPU harness + generate GPU corpus
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Parse arguments ────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build all fuzz harnesses with AFL instrumentation."
    echo ""
    echo "Options:"
    echo "  --corpusgen    Also run corpusgen to (re)generate corpus + aux data"
    echo "  --gpu          Build GPU harness only (harness-cuda-compute); requires CUDA + afl++"
    echo "                 Combined with --corpusgen: also runs gpu-corpusgen (CPU-only)"
    echo "  -h, --help     Show this help message"
}

CORPUSGEN=0
GPU=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpusgen) CORPUSGEN=1; shift ;;
        --gpu)       GPU=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

cd "$REPO_ROOT"

TARGET_DIR="$(cargo metadata --format-version=1 --no-deps \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["target_directory"])')"

# ── Step 0: optionally (re)generate corpus + aux data ──────────────────────
if [[ "$GPU" == "1" ]]; then
    if [[ "$CORPUSGEN" == "1" ]]; then
        echo "==> Building and running gpu-corpusgen"
        cargo run --release -p corpusgen --bin gpu-corpusgen
        echo "    GPU corpus and aux_data written"
    fi
    HARNESSES=(harness-cuda-compute)
else
    if [[ "$CORPUSGEN" == "1" ]]; then
        echo "==> Building and running corpusgen"
        cargo run --release -p corpusgen --bin corpusgen
        echo "    corpus and aux_data written"
    fi
    HARNESSES=(harness-deser harness-verify harness-compute)
fi

for harness in "${HARNESSES[@]}"; do
    echo "==> Building $harness"
    if [[ "$harness" == "harness-cuda-compute" ]]; then
        # Instrument host-side C++ via AFL's clang wrappers so NVCC uses them as -ccbin.
        AFL_CXX=afl-clang-fast++ cargo afl build -vv --release -j16 -p "$harness"
    else
        cargo afl build --release -p "$harness"
    fi
done

echo "==> All harnesses built successfully"
for harness in "${HARNESSES[@]}"; do
    echo "    $TARGET_DIR/release/$harness"
done
