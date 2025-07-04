#!/usr/bin/env bash

set -e

if [ $# -lt 1 ]; then
		echo "invalid arguments, usage:\n"
		echo "$0 <data_path>"
		exit 1
fi

if ! git lfs env 2>/dev/null >/dev/null; then
		echo "git lfs is not installed, please install it and try again"
		exit 1
fi

git lfs pull --include="$1/*" --exclude=""
