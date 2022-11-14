#!/usr/bin/env bash

set -e

CURR_DIR="$(dirname "$0")"
TFHE_DIR="${_TFHE_DOCKER_WORKDIR:-"${CURR_DIR}/../tfhe"}"

cd "${TFHE_DIR}"

wasm-pack build --release --target=nodejs \
--features=boolean-client-js-wasm-api,shortint-client-js-wasm-api

node --test js_on_wasm_tests
