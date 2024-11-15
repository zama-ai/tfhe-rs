#!/usr/bin/env bash

set -e

function usage() {
    echo "$0: build and/or run the C API tests"
    echo
    echo "--help                    Print this message"
    echo "--build-only              Pass to only build the tests without running them"
    echo "--gpu                     Enable GPU support"
    echo "--cargo-profile           The profile used to build TFHE-rs, release by default"
    echo
}

BUILD_ONLY=0
WITH_FEATURE_GPU="OFF"
CARGO_PROFILE="release"
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

        "--gpu" )
            WITH_FEATURE_GPU="ON"
            ;;

        "--cargo-profile" )
            shift
            CARGO_PROFILE="$1"
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
CPU_COUNT="$("${CURR_DIR}"/cpu_count.sh)"



LINKING_CPU_COUNT=4

# On linux
if [[ $(uname) != "Darwin" ]]; then
    mem_in_gb="$(free -g | awk '/Mem:/ {print $2}')"

    # If there is more than 100GB on the system,
    # use all available cores for linking
    # Otherwise, only use 4, to avoid OOM when linking
    if [ 100 -lt "$mem_in_gb" ]; then
        LINKING_CPU_COUNT="${CPU_COUNT}"
    fi
fi

mkdir -p "${TFHE_BUILD_DIR}"

cd "${TFHE_BUILD_DIR}"

cmake .. -DCMAKE_BUILD_TYPE=RELEASE -DCARGO_PROFILE="${CARGO_PROFILE}" -DWITH_FEATURE_GPU="${WITH_FEATURE_GPU}"

make -j "${LINKING_CPU_COUNT}"

if [[ "${BUILD_ONLY}" == "1" ]]; then
    exit 0
fi



if [ "${WITH_FEATURE_GPU}" == "ON" ]; then
    ctest --output-on-failure --test-dir "." --parallel "${CPU_COUNT}" --tests-regex ".*cuda.*"
else
    ctest --output-on-failure --test-dir "." --parallel "${CPU_COUNT}" --exclude-regex ".*cuda.*"
fi
