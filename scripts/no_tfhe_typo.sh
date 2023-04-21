#!/usr/bin/env bash

set -e

THIS_SCRIPT_NAME="$(basename "$0")"

TMP_FILE="$(mktemp)"

COUNT="$(git grep -rniI "thfe\|tfhr\|thfr" . | grep -v "${THIS_SCRIPT_NAME}" | \
    tee "${TMP_FILE}" | wc -l | tr -d '[:space:]')"

cat "${TMP_FILE}"
rm -rf "${TMP_FILE}"

if [[ "${COUNT}" == "0" ]]; then
    exit 0
else
    echo "tfhe typo detected, see output log above"
    exit 1
fi
