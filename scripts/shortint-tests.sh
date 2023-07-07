#!/bin/bash

set -e

function usage() {
    echo "$0: shortint test runner"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to run the tests with default: stable"
    echo "--multi-bit               Run multi-bit tests only: default off"
    echo "--cargo-profile           The cargo profile used to build tests"
    echo
}

RUST_TOOLCHAIN="+stable"
multi_bit=""
cargo_profile="release"

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
            ;;

        "--cargo-profile" )
            shift
            cargo_profile="$1"
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
    if [[ "${FAST_TESTS}" != TRUE ]]; then
       filter_expression_small_params="""\
(\
   test(/^shortint::.*_param${multi_bit}_message_1_carry_1${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_1_carry_2${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_1_carry_3${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_1_carry_4${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_1_carry_5${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_1_carry_6${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_2_carry_1${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_2_carry_2${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_2_carry_3${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_3_carry_1${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_3_carry_2${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_3_carry_3${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
)\
and not test(~smart_add_and_mul)""" # This test is too slow
    else
        filter_expression_small_params="""\
(\
   test(/^shortint::.*_param${multi_bit}_message_2_carry_1${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_2_carry_2${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_2_carry_3${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
)\
and not test(~smart_add_and_mul)""" # This test is too slow
    fi

    # Run tests only no examples or benches with small params and more threads
    cargo "${RUST_TOOLCHAIN}" nextest run \
        --tests \
        --cargo-profile "${cargo_profile}" \
        --package tfhe \
        --profile ci \
        --features="${ARCH_FEATURE}",shortint,internal-keycache \
        --test-threads "${n_threads_small}" \
        -E "${filter_expression_small_params}"

    if [[ "${FAST_TESTS}" != TRUE ]]; then
        filter_expression_big_params="""\
(\
   test(/^shortint::.*_param${multi_bit}_message_4_carry_4${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
) \
and not test(~smart_add_and_mul)"""

    # Run tests only no examples or benches with big params and less threads
    cargo "${RUST_TOOLCHAIN}" nextest run \
        --tests \
        --cargo-profile "${cargo_profile}" \
        --package tfhe \
        --profile ci \
        --features="${ARCH_FEATURE}",shortint,internal-keycache \
        --test-threads "${n_threads_big}" \
        -E "${filter_expression_big_params}"

        if [[ "${multi_bit}" == "" ]]; then
            cargo "${RUST_TOOLCHAIN}" test \
                --profile "${cargo_profile}" \
                --package tfhe \
                --features="${ARCH_FEATURE}",shortint,internal-keycache \
                --doc \
                -- shortint::
        fi
    fi
else
    if [[ "${FAST_TESTS}" != TRUE ]]; then
        filter_expression="""\
(\
   test(/^shortint::.*_param${multi_bit}_message_1_carry_1${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_1_carry_2${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_1_carry_3${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_1_carry_4${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_1_carry_5${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_1_carry_6${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_2_carry_1${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_2_carry_2${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_2_carry_3${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_3_carry_1${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_3_carry_2${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_3_carry_3${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_4_carry_4${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
)\
and not test(~smart_add_and_mul)""" # This test is too slow
    else
        filter_expression="""\
(\
   test(/^shortint::.*_param${multi_bit}_message_2_carry_1${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_2_carry_2${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
or test(/^shortint::.*_param${multi_bit}_message_2_carry_3${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
)\
and not test(~smart_add_and_mul)""" # This test is too slow
    fi

    # Run tests only no examples or benches with small params and more threads
    cargo "${RUST_TOOLCHAIN}" nextest run \
        --tests \
        --cargo-profile "${cargo_profile}" \
        --package tfhe \
        --profile ci \
        --features="${ARCH_FEATURE}",shortint,internal-keycache \
        --test-threads "$(${nproc_bin})" \
        -E "${filter_expression}"

    if [[ "${multi_bit}" == "" ]]; then
        cargo "${RUST_TOOLCHAIN}" test \
            --profile "${cargo_profile}" \
            --package tfhe \
            --features="${ARCH_FEATURE}",shortint,internal-keycache \
            --doc \
            -- --test-threads="$(${nproc_bin})" shortint::
    fi
fi

echo "Test ran in $SECONDS seconds"
