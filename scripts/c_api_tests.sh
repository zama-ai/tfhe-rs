#!/usr/bin/env bash

set -e

function usage() {
    echo "$0: build and/or run the C API tests"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to check the version for with leading"
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

        "--rust-toolchain" )
            shift
            RUST_TOOLCHAIN="$1"
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
ARCH_FEATURE="$("${CURR_DIR}/get_arch_feature.sh")"
REPO_ROOT="${CURR_DIR}/.."
TFHE_BUILD_DIR="${REPO_ROOT}/tfhe/build/"

mkdir -p "${TFHE_BUILD_DIR}"

cd "${TFHE_BUILD_DIR}"

cmake .. -DCMAKE_BUILD_TYPE=RELEASE

RUSTFLAGS="-C target-cpu=native" cargo ${RUST_TOOLCHAIN:+"${RUST_TOOLCHAIN}"} build \
--release --features="${ARCH_FEATURE}",boolean-c-api,shortint-c-api -p tfhe

make -j

if [[ "${BUILD_ONLY}" == "1" ]]; then
    exit 0
fi

make "test"
