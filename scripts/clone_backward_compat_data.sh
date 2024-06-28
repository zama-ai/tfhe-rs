#!/usr/bin/env bash

set -e

if [ $# -lt 3 ]; then
		echo "$0 git_url branch dest_path"
		exit 1
fi

if ! git lfs env 2>/dev/null >/dev/null; then
		echo "git lfs is not installed, please install it and try again"
		exit 1
fi

if [ -d $2 ]; then
		cd $2 && git fetch --depth 1 && git reset --hard origin/$2 && git clean -dfx

else
		git clone $1 -b $2 --depth 1
fi
