#!/bin/bash

CUDA_VERSION="${1}"

NVCC_PATH=$(find /usr/local /usr/bin -executable -name "nvcc" -print -quit 2>/dev/null)
if [ -z "$NVCC_PATH" ]; then
  echo "nvcc not found, CUDA does not appear to be installed" >&2
  exit 1
fi

DETECTED_VERSION=$("$NVCC_PATH" --version | sed -n 's/.*release \([0-9]*\.[0-9]*\).*/\1/p')
if [ "$DETECTED_VERSION" != "${CUDA_VERSION}" ]; then
  echo "Expected CUDA ${CUDA_VERSION} but detected ${DETECTED_VERSION}" >&2
  exit 1
fi

echo "$NVCC_PATH"
