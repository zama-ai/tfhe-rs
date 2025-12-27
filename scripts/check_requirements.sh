#!/usr/bin/env bash
set -euo pipefail

# Ensures that Rust and required tools are installed and up to date.

REQUIRED_RUST_VERSION="1.74.0"

if ! command -v rustc >/dev/null 2>&1; then
  echo "rustc is not installed. Install via rustup: https://rustup.rs/"
  exit 1
fi

rust_version=$(rustc --version | awk '{print $2}')
if [ "$rust_version" != "$REQUIRED_RUST_VERSION" ]; then
  echo "Warning: expected rustc $REQUIRED_RUST_VERSION but found $rust_version"
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is not installed. Install via rustup."
  exit 1
fi

echo "All required tools appear to be installed."
