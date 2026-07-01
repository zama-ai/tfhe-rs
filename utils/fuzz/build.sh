#!/usr/bin/env bash
#
# Build all fuzz harnesses with AFL instrumentation.
#
# Usage:
#   ./build.sh              # build harnesses only
#   ./build.sh --corpusgen  # also run corpusgen to generate corpus + aux data
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
    echo "  -h, --help     Show this help message"
}

CORPUSGEN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpusgen) CORPUSGEN=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

cd "$REPO_ROOT"

TARGET_DIR="$(cargo metadata --format-version=1 --no-deps \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["target_directory"])')"

HARNESSES=(harness-deser harness-verify harness-compute)

# ── Step 0: optionally (re)generate corpus + aux data ──────────────────────
if [[ "$CORPUSGEN" == "1" ]]; then
    echo "==> Building and running corpusgen"
    cargo run --release -p corpusgen
    echo "    corpus and aux_data written"
fi

# ── Build all three harnesses with full AFL instrumentation ────────────────
for harness in "${HARNESSES[@]}"; do
    echo "==> Building $harness"
    cargo afl build --release -p "$harness"
done

echo "==> All harnesses built successfully"
for harness in "${HARNESSES[@]}"; do
    echo "    $TARGET_DIR/release/$harness"
done
