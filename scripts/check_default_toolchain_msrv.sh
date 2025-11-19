#!/bin/bash

# Check that the toolchain in `rust-toolchain.toml` matches the MSRV

set -e

echo "Checking Rust version consistency..."

CARGO_TOML="Cargo.toml"
TOOLCHAIN_TOML="rust-toolchain.toml"

MSRV=$(grep "^rust-version" "$CARGO_TOML" | cut -d '=' -f2 | xargs)

if [ -z "$MSRV" ]; then
    echo "Error: Missing MSRV in $CARGO_TOML."
    exit 1
fi

CHANNEL=$(grep "^channel" "$TOOLCHAIN_TOML" | cut -d '=' -f2 | xargs)

if [ -z "$CHANNEL" ]; then
    echo "Error: 'channel' not found in $TOOLCHAIN_TOML."
    exit 1
fi

echo "Cargo.toml MSRV: $MSRV"
echo "rust-toolchain channel: $CHANNEL"

if [ "$MSRV" == "$CHANNEL" ]; then
    echo "SUCCESS: Versions match!"
    exit 0
else
    echo "FAILURE: Versions do not match."
    exit 1
fi
