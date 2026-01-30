#!/usr/bin/env bash
set -x
set -euo pipefail

RUN_VALGRIND=0
RUN_COMPUTE_SANITIZER=0

while [ -n "${1:-}" ]; do
   case "$1" in
        "--cpu" )
            RUN_VALGRIND=1
            ;;

        "--gpu" )
            RUN_COMPUTE_SANITIZER=1
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
   esac
   shift
done

if [[ "${RUN_VALGRIND}" == "0" && "${RUN_COMPUTE_SANITIZER}" == "0" ]]; then
  echo "Usage: check_memory_errors.sh [--gpu] [--cpu]"
  exit 1
fi

# Array to collect error messages for final summary
ERROR_MESSAGES=()

# List the tests into a temporary file
RUSTFLAGS="$RUSTFLAGS" cargo nextest list --cargo-profile "${CARGO_PROFILE}" \
          --features=integer,internal-keycache,gpu-debug,zk-pok -p tfhe &> /tmp/test_list.txt

if [[ "${RUN_VALGRIND}" == "1" ]]; then
  # The tests are filtered using grep (to keep only HL) GPU tests.
  # Since, when output is directed to a file, nextest outputs a list of `<executable name> <test name>` the `grep -o '[^ ]\+$'` filter
  # will keep only the test name and the `tfhe` executable is assumed. To sanitize tests from another
  # executable changes might be needed
  TESTS_TO_RUN=$(sed -e $'s/\x1b\[[0-9;]*m//g' < /tmp/test_list.txt | grep -E 'high_level_api::.*gpu.*' | grep -v 'array' | grep -v 'flip' | grep -o '[^ ]\+$')

  # Build the tests but don't run them
  RUSTFLAGS="$RUSTFLAGS" cargo test --no-run --profile "${CARGO_PROFILE}" \
    --features=integer,internal-keycache,gpu-debug,zk-pok -p tfhe

  # Find the test executable -> last one to have been modified
  EXECUTABLE=target/release/deps/$(find target/release/deps/ -type f -executable -name "tfhe-*" -printf "%T@ %f\n" |sort -nr|sed 's/^.* //; q;')

  RESULT=0
  while read -r t; do
        [ -z "$t" ] && continue
        echo "Running valgrind on: $t"

        VALGRIND_EXIT=0
        valgrind --leak-check=full \
            --show-leak-kinds=definite,indirect \
            --errors-for-leak-kinds=definite,indirect \
            --error-exitcode=1 \
            "$EXECUTABLE" -- "$t" 2>&1 | tee /tmp/valgrind_output.log || VALGRIND_EXIT=$?

        # Fail if the test crashed (non-zero exit code from valgrind)
        if [[ $VALGRIND_EXIT -ne 0 ]]; then
            ERROR_MESSAGES+=("Test crashed or valgrind returned error for test: $t")
            RESULT=1
        fi

        # Also fail if memory errors reference tfhe/cuda code (not system libraries)
        if grep -E "definitely lost|indirectly lost|Invalid read|Invalid write|Invalid free|Mismatched free" /tmp/valgrind_output.log | \
           grep -q "tfhe\|cuda"; then
            ERROR_MESSAGES+=("Memory error detected in tfhe/cuda code for test: $t")
            RESULT=1
        fi
  done <<< "$TESTS_TO_RUN"
fi

if [[ "${RUN_COMPUTE_SANITIZER}" == "1" ]]; then
  # The tests are filtered using grep (to keep only HL / corecrypto) GPU tests.
  # Since, when output is directed to a file, nextest outputs a list of `<executable name> <test name>` the `grep -o '[^ ]\+$'` filter
  # will keep only the test name and the `tfhe` executable is assumed. To sanitize tests from another
  # executable changes might be needed
  TESTS_TO_RUN=$(sed -e $'s/\x1b\[[0-9;]*m//g' < /tmp/test_list.txt | grep -E 'high_level_api::.*gpu.*|core_crypto::.*gpu.*' | grep -v 'array' | grep -v 'modulus_switch' | grep -v '3_3' | grep -v 'noise_distribution' | grep -v 'flip' | grep -o '[^ ]\+$')
  # Build the tests but don't run them
  RUSTFLAGS="$RUSTFLAGS" cargo test --no-run --profile "${CARGO_PROFILE}" \
    --features=integer,internal-keycache,gpu,zk-pok -p tfhe

  # Find the test executable -> last one to have been modified
  EXECUTABLE=target/release/deps/$(find target/release/deps/ -type f -executable -name "tfhe-*" -printf "%T@ %f\n" |sort -nr|sed 's/^.* //; q;')

  RESULT=0
  while read -r t; do
        [ -z "$t" ] && continue
        echo "Running compute-sanitizer on: $t"
        CS_EXIT=0
        compute-sanitizer --tool memcheck --leak-check=full \
            --error-exitcode=1 --target-processes=all \
            "$EXECUTABLE" -- "$t" || CS_EXIT=$?
        if [[ $CS_EXIT -ne 0 ]]; then
            ERROR_MESSAGES+=("Compute-sanitizer detected error for test: $t")
            RESULT=1
        fi
    done <<< "$TESTS_TO_RUN"
fi

# Print summary of errors if any were encountered
if [[ ${#ERROR_MESSAGES[@]} -gt 0 ]]; then
    echo ""
    echo "========================================"
    echo "MEMORY ERROR SUMMARY"
    echo "========================================"
    for msg in "${ERROR_MESSAGES[@]}"; do
        echo "  - $msg"
    done
    echo "========================================"
fi

exit $RESULT
