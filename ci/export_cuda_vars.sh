#!/bin/bash

CUDA_VERSION="${1}"
GITHUB_ENV="${2}"
GITHUB_PATH="${3}"

NVCC_PATH=$(bash "$(dirname "$0")/detect_cuda.sh" "${CUDA_VERSION}")

CUDA_PATH=$(dirname "$(dirname "$NVCC_PATH")")
{
  echo "CUDA_PATH=$CUDA_PATH"
  echo "CUDACXX=$NVCC_PATH"
  echo "LD_LIBRARY_PATH=$CUDA_PATH/lib64:$LD_LIBRARY_PATH"
  echo "CUDA_MODULE_LOADER=EAGER"
  echo "PATH=$PATH:$CUDA_PATH/bin"
} >> "${GITHUB_ENV}"
{
  echo "PATH=$PATH:$CUDA_PATH/bin"
} >> "${GITHUB_PATH}"
