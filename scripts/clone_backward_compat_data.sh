#!/usr/bin/env bash

set -e

if [ $# -lt 2 ]; then
		echo "$0 git_url dest_path"
		exit 1
fi

if ! git lfs env 2>/dev/null >/dev/null; then
		echo "git lfs is not installed, please install it and try again"
		exit 1
fi

if [ -d $2 ]; then
		cd $2 && git pull
else
		git clone $1 $2
fi
