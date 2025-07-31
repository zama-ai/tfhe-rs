#!/usr/bin/env bash
# Build the tests but don't run them
RUSTFLAGS="$RUSTFLAGS" cargo "${CARGO_RS_BUILD_TOOLCHAIN}" test --no-run --profile "${CARGO_PROFILE}" \
  --features=integer,internal-keycache,gpu,zk-pok -p "${TFHE_SPEC}"

# Find the test executable -> last one to have been modified
EXECUTABLE=target/release/deps/$(find target/release/deps/ -type f -executable -name "tfhe-*" -printf "%T@ %f\n" |sort -nr|sed 's/^.* //; q;')

# List the tests into a temporary file
RUSTFLAGS="$RUSTFLAGS" cargo "${CARGO_RS_BUILD_TOOLCHAIN}" nextest list --cargo-profile "${CARGO_PROFILE}" \
          --features=integer,internal-keycache,gpu,zk-pok -p "${TFHE_SPEC}" &> /tmp/test_list.txt

# Filter the tests to get only the HL ones
TESTS_HL=$(sed -e $'s/\x1b\[[0-9;]*m//g' <  /tmp/test_list.txt | grep 'high_level_api::.*gpu.*')

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

# Run compute sanitizer on each test individually
# shellcheck disable=SC2181
RESULT=0 && \
while read -r t; do \
  echo compute-sanitizer --target-processes=all "$(pwd)"/"${EXECUTABLE}" -- "${t}" && \
  compute-sanitizer --leak-check=full --error-exitcode=1 --target-processes=all "$(pwd)"/"${EXECUTABLE}" -- "${t}" && \
  if [[ $? != "0" ]]; then \
      RESULT=1; \
  fi; \
done <<< "${TESTS_HL}"

if [ $RESULT -ne 0 ]; then \
  exit $RESULT; \
fi;

exit 0