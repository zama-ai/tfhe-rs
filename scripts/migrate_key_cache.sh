#!/usr/bin/env bash

files=$(find keys/ -type f -iname "*.bin")

for file in $files; do
    RUSTFLAGS="-C target-cpu=native" \
    cargo run --profile release --example key_management \
    --features=x86_64-unix,shortint -- "${file}" &
done
wait
