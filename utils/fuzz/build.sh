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
DENYLIST="$SCRIPT_DIR/denylist_deep.txt"

# ── Parse arguments ────────────────────────────────────────────────────────
CORPUSGEN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpusgen) CORPUSGEN=1; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Build all fuzz harnesses with AFL instrumentation."
            echo ""
            echo "Options:"
            echo "  --corpusgen    Also run corpusgen to (re)generate corpus + aux data"
            echo "  -h, --help     Show this help message"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

cd "$REPO_ROOT"

# ── Step 0: optionally (re)generate corpus + aux data ──────────────────────
if [[ "$CORPUSGEN" == "1" ]]; then
    echo "==> Building and running corpusgen"
    cargo run --release -p corpusgen
    echo "    corpus and aux_data written"
fi

# ── Step 1: build deser harness (full instrumentation, no denylist) ────────
echo "==> Building harness-deser (full instrumentation)"
cargo afl build --release -p harness-deser

# ── Step 2: build verify + compute harnesses (denylist skips deser code) ───
echo "==> Building harness-verify (denylist: deser/conformance)"
AFL_LLVM_DENYLIST="$DENYLIST" cargo afl build --release -p harness-verify

echo "==> Building harness-compute (denylist: deser/conformance)"
AFL_LLVM_DENYLIST="$DENYLIST" cargo afl build --release -p harness-compute

echo "==> All harnesses built successfully"
echo "    target/release/harness-deser"
echo "    target/release/harness-verify"
echo "    target/release/harness-compute"
