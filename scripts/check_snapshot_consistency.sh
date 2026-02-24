#!/usr/bin/env bash

set -euo pipefail

SNAPSHOT_DIR="utils/tfhe-lints/snapshots"

mismatch=0

head_count=$(find "${SNAPSHOT_DIR}/head" -name 'lint_enum_snapshots_*.json' | wc -l)
base_count=$(find "${SNAPSHOT_DIR}" -maxdepth 1 -name 'lint_enum_snapshots_*.json' | wc -l)

if [ "$head_count" -ne "$base_count" ]; then
    echo "::error::File count mismatch: $base_count base file(s) vs $head_count head file(s)"
    mismatch=1
fi

# Check each head file has a matching base file with identical content
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

# Check each base file has a matching head file
for base_file in "${SNAPSHOT_DIR}"/lint_enum_snapshots_*.json; do
    base_name=$(basename "$base_file")
    head_file="${SNAPSHOT_DIR}/head/${base_name}"
    if [ ! -f "$head_file" ]; then
        echo "::error::Stale base snapshot (no matching head): $base_file"
        mismatch=1
    fi
done

if [ "$mismatch" -ne 0 ]; then
    echo "::error::Snapshots are inconsistent — run 'make backward-snapshot-base' and commit."
    exit 1
fi

echo "All snapshots are consistent."
