#!/usr/bin/env bash

set -euo pipefail

if [[ -z "${GITHUB_BASE_REF:-}" ]]; then
    echo "ERROR: this script must run inside a pull_request workflow (GITHUB_BASE_REF is not set)."
    exit 1
fi

# Each entry: crate_name:crate_dir:cargo_toml
CRATES=(
    "tfhe-cuda-common:backends/tfhe-cuda-common:backends/tfhe-cuda-common/Cargo.toml"
    "tfhe-cuda-backend:backends/tfhe-cuda-backend:backends/tfhe-cuda-backend/Cargo.toml"
    "zk-cuda-backend:backends/zk-cuda-backend:backends/zk-cuda-backend/Cargo.toml"
)

CRATES_IO_API="https://crates.io/api/v1/crates"
USER_AGENT="tfhe-rs-ci (https://github.com/zama-ai/tfhe-rs)"

# actions/checkout produces a merge commit whose first parent is the base
# branch. Compare against that so we only flag changes introduced by the PR.
base_ref="HEAD^1"
echo "Comparing PR changes against base branch (${GITHUB_BASE_REF})"

failed=0

for crate_info in "${CRATES[@]}"; do
    IFS=':' read -r crate_name crate_dir cargo_toml <<< "$crate_info"

    if git diff --quiet "$base_ref" HEAD -- "$crate_dir"; then
        echo "[OK] ${crate_name}: no changes in this PR"
        continue
    fi

    current_version=$(cargo metadata --format-version 1 --no-deps --manifest-path Cargo.toml \
        | jq -r "first(.packages[] | select(.name == \"${crate_name}\")) | .version")

    published_version=$(curl -s -H "User-Agent: ${USER_AGENT}" \
        "${CRATES_IO_API}/${crate_name}" \
        | jq -r '.crate.max_stable_version // .crate.max_version // empty')

    if [[ -z "$published_version" ]]; then
        echo "[SKIP] ${crate_name}: not found on crates.io, skipping"
        continue
    fi

    if [[ "$current_version" == "$published_version" ]]; then
        echo "[FAIL] ${crate_name}: has changes but version is still ${current_version} (published on crates.io)"
        echo "       Please bump the version in ${cargo_toml}"
        echo "       Changed files:"
        git diff "$base_ref" HEAD -- "$crate_dir" --stat | sed 's/^/         /'
        failed=1
    else
        echo "[OK] ${crate_name}: version ${current_version} is ahead of published ${published_version}"
    fi
done

echo ""

if [[ $failed -ne 0 ]]; then
    echo "ERROR: Some CUDA backend crates have changes since their last release without a version bump."
    echo "Please update the version in the affected Cargo.toml file(s)."
    exit 1
fi

echo "All CUDA backend version checks passed."
