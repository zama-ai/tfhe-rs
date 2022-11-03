#!/usr/bin/env bash

set -e

nproc_bin=nproc

arch_feature=x86_64-unix

# macOS detects CPUs differently
if [[ $(uname) == "Darwin" ]]; then
    nproc_bin="sysctl -n hw.logicalcpu"
fi

n_threads="$(${nproc_bin})"

if uname -a | grep "arm64"; then
    arch_feature=aarch64-unix
fi


CURR_DIR="$(dirname "$0")"
REPO_ROOT="${CURR_DIR}/.."
TFHE_BUILD_DIR="${REPO_ROOT}/tfhe/build/"

mkdir -p "${TFHE_BUILD_DIR}"

cd "${TFHE_BUILD_DIR}"

cmake .. -DCMAKE_BUILD_TYPE=RELEASE

RUSTFLAGS="-C target-cpu=native" cargo build \
--release --features="${arch_feature}",booleans-c-api,shortints-c-api -p tfhe

make -j "${n_threads}"
make "test"
