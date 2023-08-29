#!/usr/bin/env bash

set -e

mkdir -p sts_testing
cd sts_testing

if [[ ! -f sts-2_1_2.zip ]]; then
    wget "https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip"
    echo "0238d2f1d26e120e3cc748ed2d4c674cdc636de37fc4027c76cc2a394fff9157  sts-2_1_2.zip" > checksum
    shasum -a 256 -c checksum
fi

# q: quiet, o: overwrite
unzip -q -o sts-2_1_2.zip

cd sts-2.1.2/sts-2.1.2/

make clean
make -j GCCFLAGS="-c -Wall -O3"

rm -rf bytes.bin

echo "Generating bytes..."

# 1_000_000 bits = 125_000 bytes
# recommended number of bit streams = 200
# 125_000 * 200 = 25_000_000
RUSTFLAGS="-C target-cpu=native" cargo run --profile release \
--example generate --features=x86_64-unix -p concrete-csprng -- \
--bytes_total 125000000 >> bytes.bin

echo "Running analysis... this may take a while"

# Loop if we get this shit: "igamc: UNDERFLOW"
set +e # assess may return non 0 in case we get something wonky going on
for retry in {1..10}; do
    # 0: use input file
    # Input file name
    # 1: Run all tests on sequences
    # 0: Confirm
    # 200: number of bit streams
    # 1: binary input mode (we wrote bytes to the bin file)
    printf "0\nbytes.bin\n1\n0\n1000\n1\n" | ./assess 1000000 > sts_run.log

    cat sts_run.log

    if ! grep -q -i 'underflow' sts_run.log; then
        # did not find any underflow, break out of retrying
        break
    fi

    echo "Underflow detected in attempt ${retry}, retrying..."
done
# re-enable errors
set -e

# Let's have a nice output
cat experiments/AlgorithmTesting/finalAnalysisReport.txt

# Reports indicate failed tests with a * which does not appear in a report where everything worked
# -F indicates we want to match the fixed string * (and not a regex)
if ! grep -q -F '*' experiments/AlgorithmTesting/finalAnalysisReport.txt; then
    # Exit code was != 0 which means * was not found
    printf "\n\nStatistical tests passed!\n"
    exit 0
else
    # * found, some tests failed
    printf "\n\nStatistical tests failed!\n"
    exit 1
fi
