#!/usr/bin/env bash

set -euo pipefail

# Each entry: tag_prefix:crate_dir:cargo_toml
CRATES=(
    "tfhe-cuda-common:backends/tfhe-cuda-common:backends/tfhe-cuda-common/Cargo.toml"
    "tfhe-cuda-backend:backends/tfhe-cuda-backend:backends/tfhe-cuda-backend/Cargo.toml"
    "zk-cuda-backend:backends/zk-cuda-backend:backends/zk-cuda-backend/Cargo.toml"
)

# In pull_request CI, actions/checkout produces a merge commit whose first
# parent is the base branch. Compare against that so we only flag changes
# introduced by the PR, not pre-existing unreleased changes on main.
if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    base_ref="HEAD^1"
    echo "PR context: comparing against base branch (${GITHUB_BASE_REF})"
else
    base_ref=""
    echo "Non-PR context: comparing against latest release tags"
fi

failed=0

for crate_info in "${CRATES[@]}"; do
    IFS=':' read -r tag_prefix crate_dir cargo_toml <<< "$crate_info"

    current_version=$(cargo metadata --format-version 1 --no-deps --manifest-path Cargo.toml \
        | jq -r "first(.packages[] | select(.name == \"${tag_prefix}\")) | .version")

    if [[ -n "$base_ref" ]]; then
        # PR context: check only changes introduced by this PR
        if git diff --quiet "$base_ref" HEAD -- "$crate_dir"; then
            echo "[OK] ${tag_prefix}: no changes in this PR"
            continue
        fi

        base_version=$(git show "${base_ref}:${cargo_toml}" 2>/dev/null \
            | grep '^version' | head -1 | sed 's/.*"\(.*\)".*/\1/' || echo "")

        if [[ "$current_version" == "${base_version}" ]]; then
            echo "[FAIL] ${tag_prefix}: files changed in this PR but version is still ${current_version}"
            echo "       Please bump the version in ${cargo_toml}"
            echo "       Changed files:"
            git diff "$base_ref" HEAD -- "$crate_dir" | sed 's/^/         /'
            failed=1
        else
            echo "[OK] ${tag_prefix}: version bumped from ${base_version} to ${current_version}"
        fi
    else
        # Non-PR context: compare against latest release tag
        latest_tag=$(git tag --list "${tag_prefix}-*" --sort=-v:refname \
            | grep -vE -- '-(alpha|beta|rc)\.' \
            | head -1)

        if [[ -z "$latest_tag" ]]; then
            echo "[SKIP] ${tag_prefix}: no release tag found, skipping"
            continue
        fi

        tag_version="${latest_tag#"${tag_prefix}-"}"

        if git diff --quiet "$latest_tag" HEAD -- "$crate_dir"; then
            echo "[OK] ${tag_prefix}: no changes since ${latest_tag}"
            continue
        fi

        if [[ "$current_version" == "$tag_version" ]]; then
            echo "[FAIL] ${tag_prefix}: files changed since ${latest_tag} but version is still ${current_version}"
            echo "       Please bump the version in ${cargo_toml}"
            echo "       Changed files:"
            git diff "$latest_tag" HEAD -- "$crate_dir" | sed 's/^/         /'
            failed=1
        else
            echo "[OK] ${tag_prefix}: version bumped from ${tag_version} to ${current_version}"
        fi
    fi
done

echo ""

if [[ $failed -ne 0 ]]; then
    echo "ERROR: Some CUDA backend crates have changes since their last release without a version bump."
    echo "Please update the version in the affected Cargo.toml file(s)."
    exit 1
fi

echo "All CUDA backend version checks passed."
