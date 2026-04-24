#!/usr/bin/env bash

set -x
set -u

# This can exit with 1 but we want to ignore the error (permission denied)
NVCC_PATH=$(find /usr/local /usr/bin -executable -name "nvcc" -print -quit 2>/dev/null)

# Now we stop ignoring errors
set -eo pipefail

if [ -z "$NVCC_PATH" ]; then
  echo "nvcc not found, CUDA does not appear to be installed" >&2
  echo "Contents of /usr/local:" >&2
  ls /usr/local >&2 2>/dev/null || echo "(ls /usr/local failed)" >&2
  echo "Searching for nvcc under /usr and /usr/local:" >&2
  find /usr /usr/local -name "nvcc" 2>/dev/null >&2 || echo "(find returned nothing)" >&2
  exit 1
fi

DETECTED_VERSION=$("$NVCC_PATH" --version | sed -n 's/.*release \([0-9]*\.[0-9]*\).*/\1/p')

for CUDA_VERSION in "$@"; do
  if [ "$DETECTED_VERSION" = "${CUDA_VERSION}" ]; then
    echo "$NVCC_PATH"
    exit 0
  fi
done

echo "Expected one of CUDA version(s): $* but detected ${DETECTED_VERSION}" >&2
echo "Contents of /usr/local:" >&2
ls /usr/local >&2 2>/dev/null || echo "(ls /usr/local failed)" >&2
echo "Searching for nvcc under /usr and /usr/local:" >&2
find /usr/bin /usr/local -executable -name "nvcc" >&2 || echo "(find returned nothing)" >&2

exit 1
