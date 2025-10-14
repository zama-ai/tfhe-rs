#!/usr/bin/env bash

# This script generates backward compatibility data, with an optional version argument.
# If no argument is provided, it will re-generate all data.
# If a version (e.g., "1.2") is provided, it will only generate data for this version.

set -e

WORKSPACE_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
VERSION_ARG=$1

DATA_DIR=$WORKSPACE_DIR/data

show_help() {
  echo "Usage: $0 [version]"
  echo
  echo "Generate backward compatibility data."
  echo
  echo "[version] specifies a TFHE-rs version to generate data for."
  echo "This should be provided in 'major.minor' format (e.g., '1.4')."
  echo
  echo "If no argument is provided, the script will generate data for all supported versions."
}

cd $WORKSPACE_DIR

# If no argument is provided, generate all data
if [ -z "$VERSION_ARG" ]; then
  echo "No version provided."
  echo "Re-generating all data"
  (set -x; cargo run --release -- --data-path $DATA_DIR)
  exit
fi

# Display help if argument is -h or --help
if [[ "$VERSION_ARG" == "-h" ]] || [[ "$VERSION_ARG" == "--help" ]]; then
  show_help
  exit 0
fi

# Check that the provided version is X.Y
if [[ ! "$VERSION_ARG" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Invalid version format." >&2
    echo "Please use the format 'major.minor', for example: '1.4' or '0.8'." >&2
    echo
    show_help
    exit 1
fi

PACKAGE_VERSION=$(echo "$VERSION_ARG" | tr '.' '_')

if [[ ! -d "crates/generate_$PACKAGE_VERSION" ]]; then
    echo "Error: Data generation code for TFHE-rs $VERSION_ARG not found." >&2
    echo "Please TODO GENERATE FROM TEMPLATE." >&2
    exit 1
fi

echo "Generating data for TFHE-rs $VERSION_ARG"
# print the command and run it
(set -x; cargo run --manifest-path crates/generate_$PACKAGE_VERSION/Cargo.toml  --release -- --data-path $DATA_DIR)
