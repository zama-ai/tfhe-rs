#!/usr/bin/env bash

set -e

function usage() {
    echo "$0: shortint test runner"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to run the tests with default: stable"
    echo "--multi-bit               Run multi-bit tests only: default off"
    echo "--run-prod-only           Run only the tests using the prod parameters"
    echo "--cargo-profile           The cargo profile used to build tests"
    echo "--tfhe-package            The package spec like tfhe@0.4.2, default=tfhe"
    echo
}

RUST_TOOLCHAIN=""
multi_bit=""
multi_bit_argument=
fast_tests_argument=
cargo_profile="release"
tfhe_package="tfhe"
prod_param_argument=

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
            multi_bit_argument=--multi-bit
            ;;

        "--run-prod-only")
          prod_param_argument="--run-prod-only"
          ;;
        "--cargo-profile" )
            shift
            cargo_profile="$1"
            ;;

        "--tfhe-package" )
            shift
            tfhe_package="$1"
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
    esac
   shift
done

if [[ "${RUST_TOOLCHAIN::1}" != "+" ]]; then
    RUST_TOOLCHAIN=${RUST_TOOLCHAIN:+"+${RUST_TOOLCHAIN}"}
fi

if [[ "${FAST_TESTS}" == TRUE ]]; then
    fast_tests_argument=--fast-tests
fi

CURR_DIR="$(dirname "$0")"

n_threads_small="$("${CURR_DIR}"/cpu_count.sh)"
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
    # Keys are 4.7 gigs at max, test machine has 512 gigs of RAM, keep some headroom
    n_threads_big=100
fi

if [[ "${BIG_TESTS_INSTANCE}" != TRUE ]]; then
    filter_expression_small_params=$(/usr/bin/python3 scripts/test_filtering.py --layer shortint ${fast_tests_argument} ${multi_bit_argument} ${prod_param_argument})

    # Run tests only no examples or benches with small params and more threads
    cargo ${RUST_TOOLCHAIN:+"$RUST_TOOLCHAIN"} nextest run \
        --tests \
        --cargo-profile "${cargo_profile}" \
        --package "${tfhe_package}" \
        --profile ci \
        --features=shortint,internal-keycache,zk-pok,experimental \
        --test-threads "${n_threads_small}" \
        -E "${filter_expression_small_params}"

    if [[ "${FAST_TESTS}" != TRUE ]]; then
        filter_expression_big_params="""\
(\
   test(/^shortint::.*_param${multi_bit}_message_4_carry_4${multi_bit:+"_group_[0-9]"}(_compact_pk)?_ks_pbs/) \
) \
and not test(~smart_add_and_mul)"""

    # Run tests only no examples or benches with big params and less threads
    cargo ${RUST_TOOLCHAIN:+"$RUST_TOOLCHAIN"} nextest run \
        --tests \
        --cargo-profile "${cargo_profile}" \
        --package "${tfhe_package}" \
        --profile ci \
        --features=shortint,internal-keycache,zk-pok,experimental \
        --test-threads "${n_threads_big}" \
        --no-tests=warn \
        -E "${filter_expression_big_params}"

        if [[ "${multi_bit}" == "" ]]; then
             cargo ${RUST_TOOLCHAIN:+"$RUST_TOOLCHAIN"} test \
                --profile "${cargo_profile}" \
                --package "${tfhe_package}" \
                --features=shortint,internal-keycache,zk-pok,experimental \
                --doc \
                -- shortint::
        fi
    fi
else
    filter_expression=$(/usr/bin/python3 scripts/test_filtering.py --layer shortint --big-instance ${fast_tests_argument} ${multi_bit_argument} ${prod_param_argument})

    # Run tests only no examples or benches with small params and more threads
    cargo ${RUST_TOOLCHAIN:+"$RUST_TOOLCHAIN"} nextest run \
        --tests \
        --cargo-profile "${cargo_profile}" \
        --package "${tfhe_package}" \
        --profile ci \
        --features=shortint,internal-keycache,experimental \
        --test-threads "${n_threads_big}" \
        -E "$filter_expression"

    if [[ "${multi_bit}" == "" ]]; then
        cargo ${RUST_TOOLCHAIN:+"$RUST_TOOLCHAIN"} test \
            --profile "${cargo_profile}" \
            --package "${tfhe_package}" \
            --features=shortint,internal-keycache,experimental \
            --doc \
            -- --test-threads="${n_threads_big}" shortint::
    fi
fi

echo "Test ran in $SECONDS seconds"
