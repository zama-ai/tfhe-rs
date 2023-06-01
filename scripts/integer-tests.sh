#!/bin/bash

set -e

function usage() {
    echo "$0: shortint test runner"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to run the tests with default: stable"
    echo "--multi-bit               Run multi-bit tests only: default off"
    echo
}

RUST_TOOLCHAIN="+stable"
multi_bit=""
not_multi_bit="_multi_bit"

while [ -n "$1" ]
do
   case "$1" in
        "--help" | "-h" )
            usage
            exit 0
            ;;

        "--rust-toolchain" )
            shift
            RUST_TOOLCHAIN="$1"
            ;;

        "--multi-bit" )
            multi_bit="_multi_bit"
            not_multi_bit=""
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
   esac
   shift
done

if [[ "${RUST_TOOLCHAIN::1}" != "+" ]]; then
    RUST_TOOLCHAIN="+${RUST_TOOLCHAIN}"
fi

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
    filter_expression="""\
test(/^integer::.*${multi_bit}/) \
${not_multi_bit:+"and not test(~${not_multi_bit})"} \
and not test(/.*_block_pbs(_base)?_param_message_[34]_carry_[34]$/) \
and not test(~mul_crt_param_message_4_carry_4) \
and not test(/.*test_wopbs_bivariate_crt_wopbs_param_message_[34]_carry_[34]$/) \
and not test(/.*test_integer_smart_mul_param_message_4_carry_4$/)"""

    cargo "${RUST_TOOLCHAIN}" nextest run \
        --tests \
        --release \
        --package tfhe \
        --profile ci \
        --features="${ARCH_FEATURE}",integer,internal-keycache \
        --test-threads "${n_threads}" \
        -E "$filter_expression"

    if [[ "${multi_bit}" == "" ]]; then
        cargo "${RUST_TOOLCHAIN}" test \
            --release \
            --package tfhe \
            --features="${ARCH_FEATURE}",integer,internal-keycache \
            --doc \
            integer::
    fi
else
    # block pbs are too slow for high params
    # mul_crt_4_4 is extremely flaky (~80% failure)
    # test_wopbs_bivariate_crt_wopbs_param_message generate tables that are too big at the moment
    # test_integer_smart_mul_param_message_4_carry_4 is too slow
    filter_expression="""\
test(/^integer::.*${multi_bit}/) \
${not_multi_bit:+"and not test(~${not_multi_bit})"} \
and not test(/.*_block_pbs(_base)?_param_message_[34]_carry_[34]$/) \
and not test(~mul_crt_param_message_4_carry_4) \
and not test(/.*test_wopbs_bivariate_crt_wopbs_param_message_[34]_carry_[34]$/) \
and not test(/.*test_integer_smart_mul_param_message_4_carry_4$/)"""

    num_cpu_threads="$(${nproc_bin})"
    num_threads=$((num_cpu_threads * 2 / 3))
    cargo "${RUST_TOOLCHAIN}" nextest run \
        --tests \
        --release \
        --package tfhe \
        --profile ci \
        --features="${ARCH_FEATURE}",integer,internal-keycache \
        --test-threads $num_threads \
        -E "$filter_expression"

    if [[ "${multi_bit}" == "" ]]; then
        cargo "${RUST_TOOLCHAIN}" test \
            --release \
            --package tfhe \
            --features="${ARCH_FEATURE}",integer,internal-keycache \
            --doc \
            integer:: -- --test-threads="$(${nproc_bin})"
    fi
fi

echo "Test ran in $SECONDS seconds"
