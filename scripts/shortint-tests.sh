#!/bin/bash

set -e

CURR_DIR="$(dirname "$0")"
ARCH_FEATURE="$("${CURR_DIR}/get_arch_feature.sh")"

nproc_bin=nproc

# macOS detects CPUs differently
if [[ $(uname) == "Darwin" ]]; then
    nproc_bin="sysctl -n hw.logicalcpu"
fi

n_threads_small="$(${nproc_bin})"
n_threads_big="${n_threads_small}"

# TODO: automate thread selection by measuring host machine ram and loading the key sizes from the
# 'keys' cache directory keeping a safety margin for test execution

if uname -a | grep "arm64"; then
    if [[ $(uname) == "Darwin" ]]; then
        # Keys are 2 gigs at max, CI M1 macs only has 8 gigs of RAM so a bit conservative here
        n_threads_small=3
        # Keys are 4.7 gigs at max, CI M1 macs only has 8 gigs of RAM
        n_threads_big=1
    fi
else
    # Keys are 4.7 gigs at max, test machine has 64 gigs of RAM
    n_threads_big=13
fi

if [[ "${BIG_TESTS_INSTANCE}" != TRUE ]]; then
    filter_expression_small_params=''\
'('\
'   test(/^shortint::.*_param_message_1_carry_1$/)'\
'or test(/^shortint::.*_param_message_1_carry_2$/)'\
'or test(/^shortint::.*_param_message_1_carry_3$/)'\
'or test(/^shortint::.*_param_message_1_carry_4$/)'\
'or test(/^shortint::.*_param_message_1_carry_5$/)'\
'or test(/^shortint::.*_param_message_1_carry_6$/)'\
'or test(/^shortint::.*_param_message_2_carry_1$/)'\
'or test(/^shortint::.*_param_message_2_carry_2$/)'\
'or test(/^shortint::.*_param_message_2_carry_3$/)'\
'or test(/^shortint::.*_param_message_3_carry_1$/)'\
'or test(/^shortint::.*_param_message_3_carry_2$/)'\
'or test(/^shortint::.*_param_message_3_carry_3$/)'\
')'\
'and not test(~smart_add_and_mul)' # This test is too slow

    # Run tests only no examples or benches with small params and more threads
    cargo ${1:+"${1}"} nextest run \
        --tests \
        --release \
        --package tfhe \
        --profile ci \
        --features="${ARCH_FEATURE}",shortint,internal-keycache \
        --test-threads "${n_threads_small}" \
        -E "${filter_expression_small_params}"

    filter_expression_big_params=''\
'('\
'   test(/^shortint::.*_param_message_4_carry_4$/)'\
')'\
'and not test(~smart_add_and_mul)'

    # Run tests only no examples or benches with big params and less threads
    cargo ${1:+"${1}"} nextest run \
        --tests \
        --release \
        --package tfhe \
        --profile ci \
        --features="${ARCH_FEATURE}",shortint,internal-keycache \
        --test-threads "${n_threads_big}" \
        -E "${filter_expression_big_params}"

    cargo ${1:+"${1}"} test \
        --release \
        --package tfhe \
        --features="${ARCH_FEATURE}",shortint,internal-keycache \
        --doc \
        shortint::
else
    filter_expression=''\
'('\
'   test(/^shortint::.*_param_message_1_carry_1$/)'\
'or test(/^shortint::.*_param_message_1_carry_2$/)'\
'or test(/^shortint::.*_param_message_1_carry_3$/)'\
'or test(/^shortint::.*_param_message_1_carry_4$/)'\
'or test(/^shortint::.*_param_message_1_carry_5$/)'\
'or test(/^shortint::.*_param_message_1_carry_6$/)'\
'or test(/^shortint::.*_param_message_2_carry_1$/)'\
'or test(/^shortint::.*_param_message_2_carry_2$/)'\
'or test(/^shortint::.*_param_message_2_carry_3$/)'\
'or test(/^shortint::.*_param_message_3_carry_1$/)'\
'or test(/^shortint::.*_param_message_3_carry_2$/)'\
'or test(/^shortint::.*_param_message_3_carry_3$/)'\
'or test(/^shortint::.*_param_message_4_carry_4$/)'\
')'\
'and not test(~smart_add_and_mul)' # This test is too slow

    # Run tests only no examples or benches with small params and more threads
    cargo ${1:+"${1}"} nextest run \
        --tests \
        --release \
        --package tfhe \
        --profile ci \
        --features="${ARCH_FEATURE}",shortint,internal-keycache \
        --test-threads "$(${nproc_bin})" \
        -E "${filter_expression}"

    cargo ${1:+"${1}"} test \
        --release \
        --package tfhe \
        --features="${ARCH_FEATURE}",shortint,internal-keycache \
        --doc \
        shortint:: -- --test-threads="$(${nproc_bin})"
fi

echo "Test ran in $SECONDS seconds"
