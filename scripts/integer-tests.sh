#!/bin/bash

set -e

CURR_DIR="$(dirname "$0")"
ARCH_FEATURE="$("${CURR_DIR}/get_arch_feature.sh")"

nproc_bin=nproc

# macOS detects CPUs differently
if [[ $(uname) == "Darwin" ]]; then
    nproc_bin="sysctl -n hw.logicalcpu"
fi

n_threads="$(${nproc_bin})"

if uname -a | grep "arm64"; then
    if [[ $(uname) == "Darwin" ]]; then
        # Keys are 4.7 gigs at max, CI M1 macs only has 8 gigs of RAM
        n_threads=1
    fi
else
    # Keys are 4.7 gigs at max, test machine has 32 gigs of RAM
    n_threads=6
fi

if [[ "${BIG_TESTS_INSTANCE}" != TRUE ]]; then
    # block pbs are too slow for high params
    # mul_crt_4_4 is extremely flaky (~80% failure)
    # test_wopbs_bivariate_crt_wopbs_param_message generate tables that are too big at the moment
    # test_integer_smart_mul_param_message_4_carry_4 is too slow
    filter_expression=''\
'test(/^integer::.*$/)'\
'and not test(/.*_block_pbs(_base)?_param_message_[34]_carry_[34]$/)'\
'and not test(~mul_crt_param_message_4_carry_4)'\
'and not test(/.*test_wopbs_bivariate_crt_wopbs_param_message_[34]_carry_[34]$/)'\
'and not test(/.*test_integer_smart_mul_param_message_4_carry_4$/)'

    cargo ${1:+"${1}"} nextest run \
        --tests \
        --release \
        --package tfhe \
        --profile ci \
        --features="${ARCH_FEATURE}",integer,internal-keycache \
        --test-threads "${n_threads}" \
        -E "$filter_expression"

    cargo ${1:+"${1}"} test \
        --release \
        --package tfhe \
        --features="${ARCH_FEATURE}",integer,internal-keycache \
        --doc \
        integer::
else
    # block pbs are too slow for high params
    # mul_crt_4_4 is extremely flaky (~80% failure)
    # test_wopbs_bivariate_crt_wopbs_param_message generate tables that are too big at the moment
    # test_integer_smart_mul_param_message_4_carry_4 is too slow
    filter_expression=''\
'test(/^integer::.*$/)'\
'and not test(/.*_block_pbs(_base)?_param_message_[34]_carry_[34]$/)'\
'and not test(~mul_crt_param_message_4_carry_4)'\
'and not test(/.*test_wopbs_bivariate_crt_wopbs_param_message_[34]_carry_[34]$/)'\
'and not test(/.*test_integer_smart_mul_param_message_4_carry_4$/)'

    cargo ${1:+"${1}"} nextest run \
        --tests \
        --release \
        --package tfhe \
        --profile ci \
        --features="${ARCH_FEATURE}",integer,internal-keycache \
        --test-threads "$(${nproc_bin})" \
        -E "$filter_expression"

    cargo ${1:+"${1}"} test \
        --release \
        --package tfhe \
        --features="${ARCH_FEATURE}",integer,internal-keycache \
        --doc \
        integer:: -- --test-threads="$(${nproc_bin})"
fi

echo "Test ran in $SECONDS seconds"
