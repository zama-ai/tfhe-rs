#!/usr/bin/env bash

set -e

rust_toolchain=""
required_typos_version=""

function usage() {
    echo "$0: install zizmor"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to use"
    echo "--zizmor-version          Version of zizmor to install"
    echo
}

while [ -n "$1" ]
do
    case "$1" in
        "--rust-toolchain" )
            shift
            rust_toolchain="$1"
            ;;

        "--zizmor-version" )
            shift
            required_zizmor_version="$1"
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
    esac
    shift
done

if [[ "${rust_toolchain::1}" != "+" ]]; then
    rust_toolchain="+${rust_toolchain}"
fi

if ! which zizmor ; then
    cargo "${rust_toolchain}" install --locked zizmor --version ~"${required_zizmor_version}" || \
    ( echo "Unable to install zizmor, unknown error." && exit 1 )

    exit 0
fi

ver_string="$(zizmor --version | cut -d ' ' -f 2)"

ver_major="$(echo "${ver_string}" | cut -d '.' -f 1)"
ver_minor="$(echo "${ver_string}" | cut -d '.' -f 2)"

min_ver_major="$(echo "${required_zizmor_version}" | cut -d '.' -f 1)"
min_ver_minor="$(echo "${required_zizmor_version}" | cut -d '.' -f 2)"

if [[ "${ver_major}" -gt "${min_ver_major}" ]]; then
    exit 0
elif [[ "${ver_major}" -eq "${min_ver_major}" ]] && [[ "${ver_minor}" -ge "${min_ver_minor}" ]]; then
    exit 0
else
    cargo "${rust_toolchain}" install --locked zizmor --version ~"${required_zizmor_version}" || \
    ( echo "Unable to install zizmor, unknown error." && exit 1 )
fi
