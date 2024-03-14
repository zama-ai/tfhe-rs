#!/usr/bin/env bash

set -e

function usage() {
    echo "$0: symlink C libs to names without the variable fingerprint part"
    echo
    echo "--help                    Print this message"
    echo "--cargo-profile           The cargo profile used"
    echo "--lib-name                The lib name without the lib prefix, '-' will be converted to '_'"
    echo
}

CARGO_PROFILE=""
LIBNAME=""

while [ -n "$1" ]
do
    case "$1" in
        "--help" | "-h" )
            usage
            exit 0
            ;;

        "--cargo-profile" )
            shift
            CARGO_PROFILE="$1"
            ;;

        "--lib-name" )
            shift
            LIBNAME="$1"
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
    esac
   shift
done

if [[ "${CARGO_PROFILE}" == "" ]]; then
    echo "CARGO_PROFILE is not set, aborting."
    exit 1
fi

UNAME="$(uname)"
if [[ "${UNAME}" != "Linux" && "${UNAME}" != "Darwin" ]]; then
    echo "This script is compatible with Linux and macOS and may not work for your system"
fi

# Add the lib prefix
LIB_OF_INTEREST="lib${LIBNAME}"
LIB_OF_INTEREST_UNDERSCORE="${LIB_OF_INTEREST//-/_}"

CURR_DIR="$(dirname "$0")"
REPO_DIR="${CURR_DIR}/.."
OUTPUT_TARGET_DIR="${REPO_DIR}/target/${CARGO_PROFILE}"
OUTPUT_DEPS_DIR="${OUTPUT_TARGET_DIR}/deps"

cd "${OUTPUT_DEPS_DIR}"
echo "In ${PWD}"
# Find most recent file with similar name
MAYBE_STATIC_LIB="$(find . -maxdepth 1 -type f -name "${LIB_OF_INTEREST_UNDERSCORE}*.a")"
if [[ "${MAYBE_STATIC_LIB}" != "" ]]; then
    STATIC_LIB="$(find . -maxdepth 1 -type f -name "${LIB_OF_INTEREST_UNDERSCORE}*.a" -print0 \
        | xargs -0 ls -t | head -n 1)"
    echo "Symlinking ${STATIC_LIB} to ${LIB_OF_INTEREST_UNDERSCORE}.a"
    ln -snf "${STATIC_LIB}" "${LIB_OF_INTEREST_UNDERSCORE}.a"
else
    echo "Could not find static lib that might correspond to $1, is there a typo in the lib name?"
fi

DYNAMIC_LIB_EXT="so"
if [[ "${UNAME}" == "Darwin" ]]; then
    DYNAMIC_LIB_EXT="dylib"
fi

DYNAMIC_LIB_PATTERN="${LIB_OF_INTEREST_UNDERSCORE}*.${DYNAMIC_LIB_EXT}"

MAYBE_DYNAMIC_LIB="$(find . -maxdepth 1 -type f -name "${DYNAMIC_LIB_PATTERN}")"
if [[ "${MAYBE_DYNAMIC_LIB}" != "" ]]; then
    DYNAMIC_LIB="$(find . -maxdepth 1 -type f -name "${DYNAMIC_LIB_PATTERN}" -print0 \
        | xargs -0 ls -t | head -n 1)"
    echo "Symlinking ${DYNAMIC_LIB} to ${LIB_OF_INTEREST_UNDERSCORE}.${DYNAMIC_LIB_EXT}"
    ln -snf "${DYNAMIC_LIB}" "${LIB_OF_INTEREST_UNDERSCORE}.${DYNAMIC_LIB_EXT}"
else
    echo "Could not find dynamic lib that might correspond to $1, is there a typo in the lib name?"
fi
