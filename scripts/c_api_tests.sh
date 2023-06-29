#!/usr/bin/env bash

set -e

function usage() {
    echo "$0: build and/or run the C API tests"
    echo
    echo "--help                    Print this message"
    echo "--build-only              Pass to only build the tests without running them"
    echo
}

BUILD_ONLY=0

while [ -n "$1" ]
do
   case "$1" in
        "--help" | "-h" )
            usage
            exit 0
            ;;

        "--build-only" )
            BUILD_ONLY=1
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
   esac
   shift
done

CURR_DIR="$(dirname "$0")"
REPO_ROOT="${CURR_DIR}/.."
TFHE_BUILD_DIR="${REPO_ROOT}/tfhe/build/"

mkdir -p "${TFHE_BUILD_DIR}"

cd "${TFHE_BUILD_DIR}"

cmake .. -DCMAKE_BUILD_TYPE=RELEASE -DCARGO_PROFILE="${CARGO_PROFILE}"

make -j

if [[ "${BUILD_ONLY}" == "1" ]]; then
    exit 0
fi

nproc_bin=nproc

# macOS detects CPUs differently
if [[ $(uname) == "Darwin" ]]; then
    nproc_bin="sysctl -n hw.logicalcpu"
fi

# Let's go parallel
ARGS="-j$(${nproc_bin})" make test
