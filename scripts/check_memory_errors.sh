#!/usr/bin/env bash
set -x
set -euo pipefail

RUN_VALGRIND=0
RUN_MEMCHECK=0
RUN_RACECHECK=0

while [ -n "${1:-}" ]; do
   case "$1" in
        "--cpu" )
            RUN_VALGRIND=1
            ;;

        "--gpu" )
            RUN_MEMCHECK=1
            RUN_RACECHECK=1
            ;;

        "--memcheck" )
            RUN_MEMCHECK=1
            ;;

        "--racecheck" )
            RUN_RACECHECK=1
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
   esac
   shift
done

if [[ "${RUN_VALGRIND}" == "0" && "${RUN_MEMCHECK}" == "0" && "${RUN_RACECHECK}" == "0" ]]; then
  echo "Usage: check_memory_errors.sh [--gpu] [--memcheck] [--racecheck] [--cpu]"
  exit 1
fi

# Parameters (overridable via env vars) — defaults preserve the historical
# tfhe-cuda-backend invocation.
SANITIZER_CARGO_PACKAGE="${SANITIZER_CARGO_PACKAGE:-tfhe}"
SANITIZER_CARGO_FEATURES_GPU_DEBUG="${SANITIZER_CARGO_FEATURES_GPU_DEBUG:-integer,internal-keycache,gpu-debug-fake-multi-gpu,zk-pok}"
SANITIZER_CARGO_FEATURES_GPU="${SANITIZER_CARGO_FEATURES_GPU:-integer,internal-keycache,gpu,zk-pok}"
SANITIZER_TEST_FILTER_CPU="${SANITIZER_TEST_FILTER_CPU:-high_level_api::.*gpu.*}"
SANITIZER_TEST_EXCLUDES_CPU="${SANITIZER_TEST_EXCLUDES_CPU:-test_uniformity|array|flip}"
SANITIZER_TEST_FILTER_GPU="${SANITIZER_TEST_FILTER_GPU:-high_level_api::.*gpu.*|core_crypto::.*gpu.*}"
SANITIZER_TEST_EXCLUDES_GPU="${SANITIZER_TEST_EXCLUDES_GPU:-array|modulus_switch|3_3|noise_distribution|flip|test_uniformity}"
# Racecheck runs only the two u128 PBS tests — they use is_sanitizer_run() to limit to 2 iterations
SANITIZER_TEST_FILTER_GPU_RACECHECK="${SANITIZER_TEST_FILTER_GPU_RACECHECK:-test_bootstrap_u128_with_squashing|test_multibit_bootstrap_u128_with_squashing|test_compressed_ct_list_gpu_many_sizes}"
SANITIZER_TEST_EXCLUDES_GPU_RACECHECK="${SANITIZER_TEST_EXCLUDES_GPU_RACECHECK:-}"
SANITIZER_TEST_EXE_GLOB="${SANITIZER_TEST_EXE_GLOB:-tfhe-*}"
SANITIZER_TEST_TIMEOUT="${SANITIZER_TEST_TIMEOUT:-1800}"
SANITIZER_LAUNCH_TIMEOUT="${SANITIZER_LAUNCH_TIMEOUT:-600}"
# GTest binary built from tfhe-cuda-backend; if unset, the GTest section is skipped
SANITIZER_GTEST_EXE="${SANITIZER_GTEST_EXE:-}"
# classical PBS + multi-bit PBS + keyswitch; concurrent PBS excluded (too many iterations)
SANITIZER_GTEST_FILTER="${SANITIZER_GTEST_FILTER:-ClassicalProgrammableBootstrapInstantiation*:MultiBitProgrammableBootstrapInstantiation*:KeyswitchInstantiation*}"

# Array to collect error messages for final summary
ERROR_MESSAGES=()
RESULT=0

if [[ "${RUN_VALGRIND}" == "1" ]]; then
  # List the tests into a temporary file using the GPU debug feature set
  # CPU code is compiled in debug but kernels are in release
  RUSTFLAGS="$RUSTFLAGS" cargo nextest list --cargo-profile "${CARGO_PROFILE}" \
            --features="${SANITIZER_CARGO_FEATURES_GPU_DEBUG}" -p "${SANITIZER_CARGO_PACKAGE}" &> /tmp/test_list.txt

  # The tests are filtered using grep. Since, when output is directed to a file, nextest
  # outputs a list of `<executable name> <test name>` the `grep -o '[^ ]\+$'` filter will
  # keep only the test name. The executable glob is controlled by SANITIZER_TEST_EXE_GLOB.
  TESTS_TO_RUN=$(sed -e $'s/\x1b\[[0-9;]*m//g' < /tmp/test_list.txt \
      | grep -E "${SANITIZER_TEST_FILTER_CPU}" \
      | grep -vE "${SANITIZER_TEST_EXCLUDES_CPU}" \
      | grep -o '[^ ]\+$')

  # Build the tests but don't run them
  RUSTFLAGS="$RUSTFLAGS" cargo test --no-run --profile "${CARGO_PROFILE}" \
    --features="${SANITIZER_CARGO_FEATURES_GPU_DEBUG}" -p "${SANITIZER_CARGO_PACKAGE}"

  # Find the test executable -> last one to have been modified
  EXECUTABLE=target/release/deps/$(find target/release/deps/ -type f -executable -name "${SANITIZER_TEST_EXE_GLOB}" -printf "%T@ %f\n" |sort -nr|sed 's/^.* //; q;')

  TOTAL=$(grep -cE '\S' <<< "$TESTS_TO_RUN" || true)
  IDX=0
  while read -r t; do
        [ -z "$t" ] && continue
        IDX=$((IDX + 1))
        echo "Running valgrind on [${IDX}/${TOTAL}] $(date '+%Y-%m-%d %H:%M:%S'): $t"

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

run_compute_sanitizer_tool() {
  local CS_TOOL="$1"
  export TFHE_RS_COMPUTE_SANITIZER=1

  # Select the right filter: racecheck uses a narrower set (only u128 PBS tests)
  local TEST_FILTER="${SANITIZER_TEST_FILTER_GPU}"
  local TEST_EXCLUDES="${SANITIZER_TEST_EXCLUDES_GPU}"
  if [[ "${CS_TOOL}" == "racecheck" ]]; then
    TEST_FILTER="${SANITIZER_TEST_FILTER_GPU_RACECHECK}"
    TEST_EXCLUDES="${SANITIZER_TEST_EXCLUDES_GPU_RACECHECK}"
  fi

  # List the tests into a temporary file using the GPU feature set
  RUSTFLAGS="$RUSTFLAGS" cargo nextest list --cargo-profile "${CARGO_PROFILE}" \
            --features="${SANITIZER_CARGO_FEATURES_GPU}" -p "${SANITIZER_CARGO_PACKAGE}" &> /tmp/test_list.txt

  TESTS_TO_RUN=$(sed -e $'s/\x1b\[[0-9;]*m//g' < /tmp/test_list.txt \
      | grep -E "${TEST_FILTER}" \
      | { if [[ -n "${TEST_EXCLUDES}" ]]; then grep -vE "${TEST_EXCLUDES}"; else cat; fi; } \
      | grep -o '[^ ]\+$')
  # Build the tests but don't run them
  RUSTFLAGS="$RUSTFLAGS" cargo test --no-run --profile "${CARGO_PROFILE}" \
    --features="${SANITIZER_CARGO_FEATURES_GPU}" -p "${SANITIZER_CARGO_PACKAGE}"

  # Find the test executable -> last one to have been modified
  EXECUTABLE=target/release/deps/$(find target/release/deps/ -type f -executable -name "${SANITIZER_TEST_EXE_GLOB}" -printf "%T@ %f\n" |sort -nr|sed 's/^.* //; q;')

  TOTAL=$(grep -cE '\S' <<< "$TESTS_TO_RUN" || true)
  echo "========================================"
  echo "compute-sanitizer --tool ${CS_TOOL} (${TOTAL} tests)"
  echo "========================================"
  IDX=0
  while read -r t; do
        [ -z "$t" ] && continue
        IDX=$((IDX + 1))
        echo "Running compute-sanitizer (${CS_TOOL}) on [${IDX}/${TOTAL}] $(date '+%Y-%m-%d %H:%M:%S'): $t"
        CS_EXIT=0

        # memcheck supports --leak-check; racecheck does not
        CS_EXTRA_ARGS=""
        if [[ "${CS_TOOL}" == "memcheck" ]]; then
          CS_EXTRA_ARGS="--leak-check=full"
        fi

        # shellcheck disable=SC2086
        timeout -k 30 "${SANITIZER_TEST_TIMEOUT}" \
            compute-sanitizer --tool "${CS_TOOL}" ${CS_EXTRA_ARGS} \
            --error-exitcode=1 --launch-timeout "${SANITIZER_LAUNCH_TIMEOUT}" \
            --target-processes=all \
            "$EXECUTABLE" --exact "$t" > /tmp/sanitizer_output.log 2>&1 || CS_EXIT=$?
        cat /tmp/sanitizer_output.log
        if [[ $CS_EXIT -ne 0 ]]; then
            ERROR_MESSAGES+=("Compute-sanitizer (${CS_TOOL}) detected error for test: $t")
            RESULT=1
        fi
    done <<< "$TESTS_TO_RUN"
}

run_compute_sanitizer_gtest() {
  local CS_TOOL="$1"
  export TFHE_RS_COMPUTE_SANITIZER=1

  if [[ -z "${SANITIZER_GTEST_EXE}" ]]; then
    echo "[gtest] SANITIZER_GTEST_EXE not set — skipping GTest ${CS_TOOL} run"
    return
  fi
  if [[ ! -x "${SANITIZER_GTEST_EXE}" ]]; then
    echo "[gtest] ${SANITIZER_GTEST_EXE} is not executable — skipping GTest ${CS_TOOL} run"
    return
  fi

  # List individual GTest cases so we can run each under its own sanitizer invocation
  # (prevents a failing test from hiding subsequent ones)
  GTEST_TESTS=$(TFHE_RS_COMPUTE_SANITIZER=1 "${SANITIZER_GTEST_EXE}" \
      --gtest_list_tests --gtest_filter="${SANITIZER_GTEST_FILTER}" 2>/dev/null \
      | awk '/^[^ \t]/ {suite=$1} /^[[:space:]]/ {print suite $1}')

  TOTAL=$(grep -cE '\S' <<< "$GTEST_TESTS" || true)
  echo "========================================"
  echo "compute-sanitizer --tool ${CS_TOOL} GTest (${TOTAL} cases)"
  echo "========================================"
  IDX=0
  while read -r t; do
    [ -z "$t" ] && continue
    IDX=$((IDX + 1))
    echo "Running compute-sanitizer (${CS_TOOL}) on GTest [${IDX}/${TOTAL}] $(date '+%Y-%m-%d %H:%M:%S'): $t"
    CS_EXIT=0

    timeout -k 30 "${SANITIZER_TEST_TIMEOUT}" \
        compute-sanitizer --tool "${CS_TOOL}" \
        --error-exitcode=1 --launch-timeout "${SANITIZER_LAUNCH_TIMEOUT}" \
        --target-processes=all \
        "${SANITIZER_GTEST_EXE}" "--gtest_filter=${t}" > /tmp/sanitizer_output.log 2>&1 || CS_EXIT=$?
    cat /tmp/sanitizer_output.log
    if [[ $CS_EXIT -ne 0 ]]; then
      ERROR_MESSAGES+=("Compute-sanitizer (${CS_TOOL}) detected error in GTest: $t")
      RESULT=1
    fi
  done <<< "$GTEST_TESTS"
}

if [[ "${RUN_MEMCHECK}" == "1" ]]; then
  run_compute_sanitizer_tool memcheck
fi

if [[ "${RUN_RACECHECK}" == "1" ]]; then
  run_compute_sanitizer_tool racecheck
  run_compute_sanitizer_gtest racecheck
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
