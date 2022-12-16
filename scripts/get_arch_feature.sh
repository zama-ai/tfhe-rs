#!/usr/bin/env bash

set -e

ARCH_FEATURE=x86_64

IS_AARCH64="$( (uname -a | grep -c "arm64\|aarch64") || true)"

if [[ "${IS_AARCH64}" != "0" ]]; then
    ARCH_FEATURE=aarch64
fi

UNAME="$(uname)"

if [[ "${UNAME}" == "Linux" || "${UNAME}" == "Darwin" ]]; then
    ARCH_FEATURE="${ARCH_FEATURE}-unix"
fi

echo "${ARCH_FEATURE}"
