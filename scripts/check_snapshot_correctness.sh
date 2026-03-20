#!/usr/bin/env bash

REF=$1
BASE_DIR=base
PATH_TO_SNAPSHOTS=utils/tfhe-lints/snapshots

rm -rf $BASE_DIR
mkdir $BASE_DIR

mapfile -t files < <(git ls-tree --name-only "$REF:$PATH_TO_SNAPSHOTS")

if [ ${#files[@]} -eq 0 ]; then
	echo "No files found in the snapshot directory at ref $REF"
	exit 1
fi

for file in "${files[@]}"; do
	git show "$REF:$PATH_TO_SNAPSHOTS/$file" >"$BASE_DIR/$file"
done

make backward_snapshot_check BASE_SNAPSHOT_DIR=$BASE_DIR HEAD_SNAPSHOT_DIR=utils/tfhe-lints/snapshots

rm -rf $BASE_DIR
