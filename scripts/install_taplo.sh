#!/usr/bin/env bash

set -e

rust_toolchain=""
required_typos_version=""

function usage() {
    echo "$0: install taplo"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to use"
    echo "--taplo-version          Version of taplo to install"
    echo
}

while [ -n "$1" ]
do
    case "$1" in
        "--rust-toolchain" )
            shift
            rust_toolchain="$1"
            ;;

        "--taplo-version" )
            shift
            required_taplo_version="$1"
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
    esac
    shift
done

if [[ "${rust_toolchain::1}" != "+" ]]; then
    rust_toolchain=${rust_toolchain:+"+$rust_toolchain"}
fi

if ! which taplo ; then
    cargo  ${rust_toolchain:+"$rust_toolchain"} install --locked taplo-cli --version ~"${required_taplo_version}" || \
    ( echo "Unable to install taplo, unknown error." && exit 1 )

    exit 0
fi

ver_string="$(taplo --version | cut -d ' ' -f 2)"

ver_major="$(echo "${ver_string}" | cut -d '.' -f 1)"
ver_minor="$(echo "${ver_string}" | cut -d '.' -f 2)"

min_ver_major="$(echo "${required_taplo_version}" | cut -d '.' -f 1)"
min_ver_minor="$(echo "${required_taplo_version}" | cut -d '.' -f 2)"

if [[ "${ver_major}" -gt "${min_ver_major}" ]]; then
    exit 0
elif [[ "${ver_major}" -eq "${min_ver_major}" ]] && [[ "${ver_minor}" -ge "${min_ver_minor}" ]]; then
    exit 0
else
    cargo ${rust_toolchain:+"$rust_toolchain"} install --locked taplo-cli --version ~"${required_taplo_version}" || \
    ( echo "Unable to install taplo, unknown error." && exit 1 )
fi
