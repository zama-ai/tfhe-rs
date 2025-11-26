#!/usr/bin/env bash

# This script generates or checks the SHA256 for the test vectors in `apps/test-vectors`

set -e

MODE="$1"
TARGET_DIR="$2"
CHECKSUM_FILE="checksums.sha256"

if [ -z "$(uname -a | grep x86)" ]; then
	 echo "Wrong architecture for test vectors, only x86 is supported"
	 exit 1
fi

if [ -z "$MODE" ] || [ -z "$TARGET_DIR" ]; then
    echo "Usage: $0 <mode> <target dir>"
    echo "Modes:"
    echo "  generate   Generate the vectors and update the checksum file"
    echo "  check      Generate the vectors and compare their content with the checksum file"
    exit 1
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Directory '$TARGET_DIR' not found."
    exit 1
fi

checksum () {
    find data -name '*.cbor' -type f -exec sha256sum {} + | sort
}

# Generate the test vectors
echo "Generating test-vectors in $TARGET_DIR..."
cd $TARGET_DIR
cargo run --release

if [ "$MODE" == "generate" ]; then
    echo "Generating hashes in $TARGET_DIR/$CHECKSUM_FILE..."
    checksum > "$CHECKSUM_FILE"
    echo "Done."

elif [ "$MODE" == "check" ]; then
    echo "Checking vectors integrity against $TARGET_DIR/$CHECKSUM_FILE..."

    if [ ! -f "$CHECKSUM_FILE" ]; then
        echo "Error: Checksum file $CHECKSUM_FILE not found."
        echo "Run 'generate' mode first."
        exit 1
    fi

    diffs=$(comm -3 checksums.sha256 <(checksum))
    if [ -n "$diffs" ]; then
       echo "Error: Checksum file and generated vectors do not match."
       echo $diffs
       exit 1
    fi
    echo "Done."

else
    echo "Error: Invalid mode '$MODE'."
    echo "Mode must be 'generate' or 'check'."
    exit 1
fi
