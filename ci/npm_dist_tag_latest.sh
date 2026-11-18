#!/usr/bin/env bash
# Point the "latest" dist-tag of npm packages to the version being released,
# when that version is the newest stable one published for the package.
#
# Usage: ci/npm_dist_tag_latest.sh [--dry-run] <version> [<package>...]
#
# - Pre-releases (e.g. 1.4.0-alpha.1) never become "latest".
# - A version older than what is already published (a backport) is left alone.
# - Packages are handled independently: a package missing a previous release
#   still gets the tag if the version is its newest stable one.
#
# Tags are set with npm trusted publishing (OIDC). It requires npm >= 11.21.0
# and the "Allow npm dist-tag" permission on the trusted publisher
# configuration of each package on npmjs.com.

set -euo pipefail

# Stable version: three numbers, no pre-release suffix.
STABLE_VERSION_REGEX='^[0-9]+\.[0-9]+\.[0-9]+$'

usage() {
    echo "Usage: $0 [--dry-run] <version> [<package>...]" >&2
    exit 2
}

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    shift
fi

[[ $# -ge 1 ]] || usage
VERSION="$1"
shift

if [[ ! "${VERSION}" =~ ${STABLE_VERSION_REGEX} ]]; then
    echo "${VERSION} is a pre-release: 'latest' is left untouched"
    exit 0
fi

# Print the newest stable version published for a package, nothing if the
# package has no stable version or does not exist yet.
newest_published_stable() {
    local package="$1" versions
    if ! versions="$(npm view "${package}" versions --json 2> /dev/null)"; then
        # With --json, npm reports errors as JSON on stdout.
        if jq -e '.error.code == "E404"' <<< "${versions}" > /dev/null 2>&1; then
            return 0
        fi
        echo "Failed to fetch the versions of ${package} from the registry:" >&2
        echo "${versions}" >&2
        return 1
    fi
    # npm returns a bare string instead of an array for a single version.
    jq -r 'if type == "array" then .[] else . end' <<< "${versions}" |
        { grep -E "${STABLE_VERSION_REGEX}" || true; } |
        sort -V |
        tail -n 1
}

for package in "$@"; do
    published="$(newest_published_stable "${package}")"
    # Stable versions are plain numbers: version sort orders them like semver.
    newest="$(printf '%s\n' "${VERSION}" "${published}" | sort -V | tail -n 1)"
    if [[ "${newest}" != "${VERSION}" ]]; then
        echo "${package}@${VERSION} is older than ${published}: 'latest' is left untouched"
        continue
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        echo "[dry-run] would tag ${package}@${VERSION} as latest (newest published: ${published:-none})"
    else
        npm dist-tag add "${package}@${VERSION}" latest
    fi
done
