#!/usr/bin/env bash

set -e

CURR_DIR="$(dirname "$0")"
ARCH_FEATURE="$("${CURR_DIR}/get_arch_feature.sh")"
REPO_ROOT="${CURR_DIR}/.."
TFHE_BUILD_DIR="${REPO_ROOT}/tfhe/build/"

mkdir -p "${TFHE_BUILD_DIR}"

cd "${TFHE_BUILD_DIR}"

cmake .. -DCMAKE_BUILD_TYPE=RELEASE

RUSTFLAGS="-C target-cpu=native" cargo build \
--release --features="${ARCH_FEATURE}",booleans-c-api,shortints-c-api -p tfhe

make -j
make "test"
