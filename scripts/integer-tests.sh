#!/bin/bash

set -e

function usage() {
    echo "$0: shortint test runner"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to run the tests with default: stable"
    echo "--multi-bit               Run multi-bit tests only: default off"
    echo "--unsigned-only           Run only unsigned integer tests, by default both signed and unsigned tests are run"
    echo "--signed-only             Run only signed integer tests, by default both signed and unsigned tests are run"
    echo "--cargo-profile           The cargo profile used to build tests"
    echo "--avx512-support          Set to ON to enable avx512"
    echo
}

RUST_TOOLCHAIN="+stable"
multi_bit=""
not_multi_bit="_multi_bit"
# Run signed test by default
signed=""
not_signed=""
cargo_profile="release"
avx512_feature=""

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

        "--unsigned-only" )
            signed=""
            not_signed="_signed"
            ;;

        "--signed-only" )
            signed="_signed"
            not_signed=""
            ;;

        "--cargo-profile" )
            shift
            cargo_profile="$1"
            ;;

        "--avx512-support" )
            shift
            if [[ "$1" == "ON" ]]; then
                avx512_feature=nightly-avx512
            fi
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

# TODO autodetect/have a finer CPU count depending on memory
num_cpu_threads="$(${nproc_bin})"

if uname -a | grep "arm64"; then
    if [[ $(uname) == "Darwin" ]]; then
        # Keys are 4.7 gigs at max, CI M1 macs only has 8 gigs of RAM
        small_instance_n_threads=1
    fi
else
    # Keys are 4.7 gigs at max, test machine has 32 gigs of RAM
    small_instance_n_threads=6
fi

if [[ "${BIG_TESTS_INSTANCE}" == TRUE ]]; then
    test_threads="$((num_cpu_threads * 1 / 2))"
    doctest_threads="${num_cpu_threads}"
else
    test_threads="${small_instance_n_threads}"
    doctest_threads="${num_cpu_threads}"
fi

# block pbs are too slow for high params
# mul_crt_4_4 is extremely flaky (~80% failure)
# test_wopbs_bivariate_crt_wopbs_param_message generate tables that are too big at the moment
# test_integer_smart_mul_param_message_4_carry_4_ks_pbs is too slow
# so is test_integer_default_add_sequence_multi_thread_param_message_4_carry_4_ks_pbs
# we skip smart_div, smart_rem which are already covered by the smar_div_rem test
# we similarly skip default_div, default_rem which are covered by default_div_rem
full_test_filter_expression="""\
test(/^integer::.*${multi_bit}/) \
${signed:+"and test(/^integer::.*${signed}/)"} \
${not_multi_bit:+"and not test(~${not_multi_bit})"} \
${not_signed:+"and not test(~${not_signed})"} \
and not test(/.*integer_smart_div_param/) \
and not test(/.*integer_smart_rem_param/) \
and not test(/.*integer_default_div_param/) \
and not test(/.*integer_default_rem_param/) \
and not test(/.*_block_pbs(_base)?_param_message_[34]_carry_[34]_ks_pbs$/) \
and not test(~mul_crt_param_message_4_carry_4_ks_pbs) \
and not test(/.*test_wopbs_bivariate_crt_wopbs_param_message_[34]_carry_[34]_ks_pbs$/) \
and not test(/.*test_integer_smart_mul_param_message_4_carry_4_ks_pbs$/) \
and not test(/.*test_integer_default_add_sequence_multi_thread_param_message_4_carry_4_ks_pbs$/)"""

# test only fast default operations with only two set of parameters
# we skip default_div, default_rem which are covered by default_div_rem
fast_test_filter_expression="""\
test(/^integer::.*${multi_bit}/) \
${signed:+"and test(/^integer::.*${signed}/)"} \
${not_multi_bit:+"and not test(~${not_multi_bit})"} \
${not_signed:+"and not test(~${not_signed})"} \
and test(/.*_default_.*?_param${multi_bit}_message_[2-3]_carry_[2-3]${multi_bit:+"_group_2"}_ks_pbs/) \
and not test(/.*integer_default_div_param/) \
and not test(/.*integer_default_rem_param/) \
and not test(/.*_param_message_[14]_carry_[14]_ks_pbs$/) \
and not test(/.*default_add_sequence_multi_thread_param_message_3_carry_3_ks_pbs$/)"""

if [[ "${FAST_TESTS}" == "TRUE" ]]; then
    echo "Running 'fast' test set'"
    filter_expression="${fast_test_filter_expression}"
else
    echo "Running 'slow' test set"
    filter_expression="${full_test_filter_expression}"
fi

cargo "${RUST_TOOLCHAIN}" nextest run \
    --tests \
    --cargo-profile "${cargo_profile}" \
    --package tfhe \
    --profile ci \
    --features="${ARCH_FEATURE}",integer,internal-keycache,"${avx512_feature}" \
    --test-threads "${test_threads}" \
    -E "$filter_expression"

if [[ "${multi_bit}" == "" ]]; then
    cargo "${RUST_TOOLCHAIN}" test \
        --profile "${cargo_profile}" \
        --package tfhe \
        --features="${ARCH_FEATURE}",integer,internal-keycache,"${avx512_feature}" \
        --doc \
        -- --test-threads="${doctest_threads}" integer::
fi

echo "Test ran in $SECONDS seconds"
