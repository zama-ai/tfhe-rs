#!/usr/bin/env bash

# dieharder does not support running a subset of its tests, so we'll check which ones are not good
# and ignore the output from those tests in the final log

set -e

DIEHARDER_RUN_LOG_FILE="dieharder_run.log"

bad_tests="$(dieharder -l | \
# select lines with the -d
grep -w '\-d' | \
# forget about the good tests
grep -v -i 'good' | \
# get the test id
cut -d ' ' -f 4 | \
# nice formatting
xargs)"


bad_test_filter=""
for bad_test in ${bad_tests}; do
    bad_test_filter="${bad_test_filter:+${bad_test_filter}|}$(dieharder -d "${bad_test}" -t 1 -p 1 -D test_name | xargs)"
done

echo "The following tests will be ignored as they are marked as either 'suspect' or 'do not use': "
echo ""
echo "${bad_test_filter}"
echo ""

# by default we may have no pv just forward the input
pv="cat"
if which pv > /dev/null; then
    pv="pv -t -a -b"
fi

rm -f "${DIEHARDER_RUN_LOG_FILE}"

# ignore potential errors and parse the log afterwards
set +e

# We are writing in both cases
# shellcheck disable=SC2094
./target/release/examples/generate 2>"${DIEHARDER_RUN_LOG_FILE}" | \
$pv | \
# -a: all tests
# -g 200: get random bytes from input
# -Y 1: disambiguate results, i.e. if a weak result appear check if it's a random failure/weakness
# -k 2: better maths formulas to determine some test statistics
dieharder -a -g 200 -Y 1 -k 2 | \
tee -a "${DIEHARDER_RUN_LOG_FILE}"
set -e

printf "\n\n"

cat "${DIEHARDER_RUN_LOG_FILE}"

if ! grep -q -i "failed" < "${DIEHARDER_RUN_LOG_FILE}"; then
    echo "All tests passed!"
    exit 0
fi

printf "\n\n"

failed_tests="$(grep -i "failed" < "${DIEHARDER_RUN_LOG_FILE}")"
true_failed_test="$(grep -i "failed" < "${DIEHARDER_RUN_LOG_FILE}" | { grep -v -E "${bad_test_filter}" || true; } | sed -z '$ s/\n$//')"

if [[ "${true_failed_test}" == "" ]]; then
    echo "There were test failures, but the tests were either marked as 'suspect' or 'do not use'"
    echo "${failed_tests}"
    exit 0
fi

echo "The following tests failed:"
echo "${true_failed_test}"

exit 1
