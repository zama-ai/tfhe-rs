#!/usr/bin/env bash

set -e

function usage() {
    echo "$0: integer test runner"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to run the tests with default: stable"
    echo "--multi-bit               Run multi-bit tests only: default off"
    echo "--unsigned-only           Run only unsigned integer tests, by default both signed and unsigned tests are run"
    echo "--signed-only             Run only signed integer tests, by default both signed and unsigned tests are run"
    echo "--nightly-tests           Run integer tests configured for nightly runs (3_3 params)"
    echo "--fast-tests              Run integer set but skip a subset of longer tests"
    echo "--long-tests              Run only long run integer tests"
    echo "--cargo-profile           The cargo profile used to build tests"
    echo "--backend                 Backend to use with tfhe-rs"
    echo "--avx512-support          Set to ON to enable avx512"
    echo "--tfhe-package            The package spec like tfhe@0.4.2, default=tfhe"
    echo
}

RUST_TOOLCHAIN="+stable"
multi_bit_argument=
sign_argument=
fast_tests_argument=
long_tests_argument=
nightly_tests_argument=
no_big_params_argument=
cargo_profile="release"
backend="cpu"
gpu_feature=""
avx512_feature=""
tfhe_package="tfhe"

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
            multi_bit_argument=--multi-bit
            ;;

        "--unsigned-only" )
            sign_argument=--unsigned-only
            ;;

        "--signed-only" )
            sign_argument=--signed-only
            ;;

        "--cargo-profile" )
            shift
            cargo_profile="$1"
            ;;

        "--backend" )
            shift
            backend="$1"
            ;;
        "--avx512-support" )
            shift
            if [[ "$1" == "ON" ]]; then
                avx512_feature=nightly-avx512
            fi
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
    RUST_TOOLCHAIN="+${RUST_TOOLCHAIN}"
fi

if [[ "${FAST_TESTS}" == TRUE ]]; then
    fast_tests_argument=--fast-tests
fi

if [[ "${LONG_TESTS}" == TRUE ]]; then
    long_tests_argument=--long-tests
fi

if [[ "${NIGHTLY_TESTS}" == TRUE ]]; then
    nightly_tests_argument=--nightly-tests
fi

if [[ "${NO_BIG_PARAMS}" == TRUE ]]; then
    no_big_params_argument=--no-big-params
fi

if [[ "${backend}" == "gpu" ]]; then
    gpu_feature="gpu"
fi

CURR_DIR="$(dirname "$0")"

# TODO autodetect/have a finer CPU count depending on memory
num_cpu_threads="$("${CURR_DIR}"/cpu_count.sh)"

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
    test_threads="$((num_cpu_threads * 1 / 4))"
    doctest_threads="${num_cpu_threads}"
else
    test_threads="${small_instance_n_threads}"
    doctest_threads="${num_cpu_threads}"
fi

# Override test-threads number to avoid Out-of-memory issues on GPU instances
if [[ "${backend}" == "gpu" ]]; then
    if [[ "${BIG_TESTS_INSTANCE}" == TRUE ]]; then
        test_threads=8
        doctest_threads=8
    else
        test_threads=3
        doctest_threads=3
    fi
fi

filter_expression=$(/usr/bin/python3 scripts/test_filtering.py --layer integer --backend "${backend}" ${fast_tests_argument} ${long_tests_argument} ${nightly_tests_argument} ${multi_bit_argument} ${sign_argument} ${no_big_params_argument})

if [[ "${FAST_TESTS}" == "TRUE" ]]; then
    echo "Running 'fast' test set"
elif [[ "${LONG_TESTS}" == "FALSE" ]]; then
    echo "Running 'slow' test set"
fi

if [[ "${LONG_TESTS}" == "TRUE" ]]; then
    echo "Running 'long run' test set"
fi

if [[ "${NIGHTLY_TESTS}" == "TRUE" ]]; then
    echo "Running 'nightly' test set"
fi

echo "${filter_expression}"

cargo "${RUST_TOOLCHAIN}" nextest run \
    --tests \
    --cargo-profile "${cargo_profile}" \
    --package "${tfhe_package}" \
    --profile ci \
    --features=integer,internal-keycache,zk-pok,experimental,"${avx512_feature}","${gpu_feature}" \
    --test-threads "${test_threads}" \
    -E "$filter_expression"

if [[ -z ${multi_bit_argument} && -z ${long_tests_argument} ]]; then
    cargo "${RUST_TOOLCHAIN}" test \
        --profile "${cargo_profile}" \
        --package "${tfhe_package}" \
        --features=integer,internal-keycache,experimental,"${avx512_feature}","${gpu_feature}" \
        --doc \
        -- --test-threads="${doctest_threads}" integer::"${gpu_feature}"
fi

echo "Test ran in $SECONDS seconds"
