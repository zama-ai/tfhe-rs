#!/usr/bin/env bash

set -e

function usage() {
    echo "$0: check minimum cargo version"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to check the version for with leading"
    echo "--min-rust-version        Check toolchain version is >= to this version, default is 1.65"
    echo
}

RUST_TOOLCHAIN=""
# We set the default rust version 1.65 which is the minimum version required for stable GATs
MIN_RUST_VERSION="1.65"

while [ -n "$1" ]
do
   case "$1" in
        "--help" | "-h" )
            usage
            exit 0
            ;;

        "--rust-toolchain" )
            shift
            RUST_TOOLCHAIN="$1"
            ;;

        "--min-rust-version" )
            shift
            MIN_RUST_VERSION="$1"
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
   esac
   shift
done

if [[ "${RUST_TOOLCHAIN::1}" != "+" ]]; then
    RUST_TOOLCHAIN="+${RUST_TOOLCHAIN}"
fi

ver_string="$(cargo ${RUST_TOOLCHAIN:+"${RUST_TOOLCHAIN}"} --version | \
    cut -d ' ' -f 2 | cut -d '-' -f 1)"
ver_major="$(echo "${ver_string}" | cut -d '.' -f 1)"
ver_minor="$(echo "${ver_string}" | cut -d '.' -f 2)"

min_ver_major="$(echo "${MIN_RUST_VERSION}" | cut -d '.' -f 1)"
min_ver_minor="$(echo "${MIN_RUST_VERSION}" | cut -d '.' -f 2)"

if [[ "${ver_major}" -ge "${min_ver_major}" ]] && [[ "${ver_minor}" -ge "${min_ver_minor}" ]]; then
    exit 0
fi

exit 1
