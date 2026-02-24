#!/usr/bin/env bash

set -euo pipefail

SNAPSHOT_DIR="utils/tfhe-lints/snapshots"

mismatch=0
for head_file in "${SNAPSHOT_DIR}"/head/lint_enum_snapshots_*.json; do
    base_name=$(basename "$head_file")
    base_file="${SNAPSHOT_DIR}/${base_name}"
    if [ ! -f "$base_file" ]; then
        echo "::error::Missing base snapshot: $base_file"
        mismatch=1
        continue
    fi
    if ! diff -q "$base_file" "$head_file" >/dev/null 2>&1; then
        echo "::error::Snapshot mismatch: $base_name"
        diff "$base_file" "$head_file" || true
        mismatch=1
    fi
done

if [ "$mismatch" -ne 0 ]; then
    echo "::error::Snapshots are inconsistent — run 'make backward-snapshot-base' and commit."
    exit 1
fi

echo "All snapshots are consistent."
