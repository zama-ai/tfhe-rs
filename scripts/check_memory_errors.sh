#!/usr/bin/env bash

RUN_VALGRIND=0
RUN_COMPUTE_SANITIZER=0

while [ -n "$1" ]
do
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

# List the tests into a temporary file
RUSTFLAGS="$RUSTFLAGS" cargo "${CARGO_RS_BUILD_TOOLCHAIN}" nextest list --cargo-profile "${CARGO_PROFILE}" \
          --features=integer,internal-keycache,gpu-debug,zk-pok -p "${TFHE_SPEC}" &> /tmp/test_list.txt

# Filter the tests to get only the HL ones
TESTS_HL=$(sed -e $'s/\x1b\[[0-9;]*m//g' <  /tmp/test_list.txt | grep 'high_level_api::.*gpu.*' )

if [[ "${RUN_VALGRIND}" == "1" ]]; then
  # Build the tests but don't run them
  RUSTFLAGS="$RUSTFLAGS" cargo "${CARGO_RS_BUILD_TOOLCHAIN}" test --no-run --profile "${CARGO_PROFILE}" \
    --features=integer,internal-keycache,gpu-debug,zk-pok -p "${TFHE_SPEC}"

  # Find the test executable -> last one to have been modified
  EXECUTABLE=target/release/deps/$(find target/release/deps/ -type f -executable -name "tfhe-*" -printf "%T@ %f\n" |sort -nr|sed 's/^.* //; q;')

  # shellcheck disable=SC2181
  RESULT=0 && \
  while read -r t; do \
    echo valgrind --leak-check=full  --show-leak-kinds=definite "$(pwd)"/"${EXECUTABLE}" -- "${t}" && \
    valgrind --leak-check=full  --show-leak-kinds=definite "$(pwd)"/"${EXECUTABLE}" -- "${t}" && \
    if [[ $? != "0" ]]; then \
        RESULT=1; \
    fi; \
  done <<< "${TESTS_HL}"

  if [ $RESULT -ne 0 ]; then \
    exit $RESULT; \
  fi;
fi

TESTS_HL=$(sed -e $'s/\x1b\[[0-9;]*m//g' <  /tmp/test_list.txt | grep 'high_level_api::.*gpu.*' )

if [[ "${RUN_COMPUTE_SANITIZER}" == "1" ]]; then
  # Build the tests but don't run them
  RUSTFLAGS="$RUSTFLAGS" cargo "${CARGO_RS_BUILD_TOOLCHAIN}" test --no-run --profile "${CARGO_PROFILE}" \
    --features=integer,internal-keycache,gpu,zk-pok -p "${TFHE_SPEC}"

  # Find the test executable -> last one to have been modified
  EXECUTABLE=target/release/deps/$(find target/release/deps/ -type f -executable -name "tfhe-*" -printf "%T@ %f\n" |sort -nr|sed 's/^.* //; q;')

  # Run compute sanitizer on each test individually
  # shellcheck disable=SC2181
  RESULT=0 && \
  while read -r t; do \
    echo compute-sanitizer --tool memcheck --target-processes=all "$(pwd)"/"${EXECUTABLE}" -- "${t}" && \
    compute-sanitizer --tool memcheck --leak-check=full --error-exitcode=1 --target-processes=all "$(pwd)"/"${EXECUTABLE}" -- "${t}" && \
    if [[ $? != "0" ]]; then \
        RESULT=1; \
    fi; \
  done <<< "${TESTS_HL}"

  if [ $RESULT -ne 0 ]; then \
    exit $RESULT; \
  fi;
fi

exit 0
