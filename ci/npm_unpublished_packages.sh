#!/usr/bin/env bash
# Print, as a JSON list, the npm packages that do not have a given version on
# the registry yet: the ones a release still has to build and publish.
#
# Usage: ci/npm_unpublished_packages.sh <version> <package>...
#
# A package the registry cannot be asked about counts as not published: at
# worst it is built for nothing, publishing a version twice being refused.

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <version> <package>..." >&2
    exit 2
fi
VERSION="$1"
shift

unpublished=()
for package in "$@"; do
    # Prints the version when it is published, nothing when only other
    # versions are, and fails for a package that does not exist.
    if published="$(npm view "${package}@${VERSION}" version 2> /dev/null)" &&
        [[ "${published}" == "${VERSION}" ]]; then
        echo "${package}@${VERSION} is published" >&2
    else
        echo "${package}@${VERSION} is not published" >&2
        unpublished+=("${package}")
    fi
done

# Expanded this way for bash versions taking an empty array for an unset variable.
jq --compact-output --null-input '$ARGS.positional' \
    --args ${unpublished[@]+"${unpublished[@]}"}
