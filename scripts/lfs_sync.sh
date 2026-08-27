#!/usr/bin/env bash

# This script tries to:
# List all LFS objects reachable from the given branch and all tags on a source remote
#   (FULL history, not just the trees of the tip commits)
# List all LFS objects reachable from the same branch and all tags on a destination remote
# Verify which LFS objects are missing in the destination remote
# Fetch ONLY the missing LFS objects from the source remote
# Push ONLY the missing LFS objects to the destination repo

set -euo pipefail

# 1. Handle Command-Line Arguments
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <src_remote> <destination_remote> <branch>"
    echo "Example: $0 origin upstream main"
    exit 1
fi

SRC_REMOTE="$1"
DST_REMOTE="$2"
BRANCH="$3"

# 2. Create and manage the temporary directory
# mktemp creates a uniquely named directory in your system's tmp folder
if [[ $(uname) == "Darwin" ]]; then
    # macOS is always a bit different...
    # https://unix.stackexchange.com/questions/30091/fix-or-alternative-for-mktemp-in-os-x
    TMP_DIR=$(mktemp -d -t 'lfs-sync')
else
    TMP_DIR=$(mktemp -d -t 'lfs-sync-XXXXXX')
fi

# The trap ensures this directory is deleted upon script exit, success, or interruption
trap 'echo "Cleaning up temporary directory: $TMP_DIR"; rm -rf "$TMP_DIR"' EXIT

# 3. Dynamically detect CPU cores for xargs
CORES=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)

# Prints "oid size" (one per line, deduplicated) for every LFS pointer reachable
# from the given refs/commits. Unlike `git lfs ls-files <ref>`, which only looks
# at the tree of the tip commit, this walks EVERY commit reachable from the refs,
# so previous versions of files (overwritten or deleted in later commits) are
# included. --ignore-missing quietly skips refs whose commits we don't have
# locally (e.g. destination-only tags).
inventory_lfs_objects() {
    git rev-list --objects --ignore-missing "$@" -- | \
        awk 'NF {print $1}' | \
        git cat-file --batch-check='%(objectname) %(objecttype) %(objectsize)' | \
        awk '$2 == "blob" && $3 <= 1024 {print $1}' | \
        git cat-file --batch | \
        awk '
            # Blob header from cat-file: "<sha> blob <bytes>". An LFS pointer must
            # then follow as three lines, in order: version, oid, size.
            NF == 3 && $2 == "blob" && $1 ~ /^[0-9a-f]+$/ && length($1) >= 40 { expect = "version"; next }
            expect == "version" && /^version https:\/\/git-lfs/ { expect = "oid"; next }
            expect == "oid" && /^oid sha256:[0-9a-f]+$/ { oid = substr($2, 8); expect = "size"; next }
            expect == "size" && /^size [0-9]+$/ { print oid, $2 }
            { expect = "" }
        ' | sort -u
}

echo "Starting LFS sync from '$SRC_REMOTE' to '$DST_REMOTE' for branch '$BRANCH' and all tags..."
echo "Using temporary directory: $TMP_DIR"

echo "1. Fetching Git metadata for $BRANCH and tags from source..."
git fetch "$SRC_REMOTE" "$BRANCH" --tags
echo "   Fetching Git metadata for $BRANCH from destination..."
git fetch "$DST_REMOTE" "$BRANCH"

echo "2. Inventorying LFS objects for Source ($BRANCH + Tags, full history)..."
# The tag shas are hex strings, so unquoted word splitting is safe here
# shellcheck disable=SC2046
inventory_lfs_objects "$SRC_REMOTE/$BRANCH" \
    $(git ls-remote --tags --refs "$SRC_REMOTE" | awk '{print $1}' | sort -u) \
    > "$TMP_DIR/src_oids_sizes.txt"

echo "3. Inventorying LFS objects for Destination ($BRANCH + Tags, full history)..."
# shellcheck disable=SC2046
inventory_lfs_objects "$DST_REMOTE/$BRANCH" \
    $(git ls-remote --tags --refs "$DST_REMOTE" | awk '{print $1}' | sort -u) \
    > "$TMP_DIR/dst_oids_sizes.txt"

echo "4. Comparing to find missing LFS objects..."
comm -23 <(awk '{print $1}' "$TMP_DIR/src_oids_sizes.txt" | sort -u) \
         <(awk '{print $1}' "$TMP_DIR/dst_oids_sizes.txt" | sort -u) > "$TMP_DIR/missing_oids.txt"

if [ ! -s "$TMP_DIR/missing_oids.txt" ]; then
    echo "No missing LFS objects found for $BRANCH and tags. Destination is up to date."
    exit 0
fi

MISSING_COUNT=$(wc -l < "$TMP_DIR/missing_oids.txt")
echo "Found $MISSING_COUNT missing LFS objects. Extracting sizes..."

# -F: patterns are fixed strings, -w: match whole word, -f: get them from the file
grep -F -w -f "$TMP_DIR/missing_oids.txt" "$TMP_DIR/src_oids_sizes.txt" | \
    sort -u > "$TMP_DIR/missing_oids_sizes.txt"

echo "5. Fetching ONLY missing LFS objects from source..."
# An LFS pointer is nothing more than "version + oid + size", so we can rebuild
# it and let `git lfs smudge` download the object into .git/lfs/objects.
# Unlike `git show <ref>:<path>`, this also works for historical versions of a
# file that no longer exist in any tip tree.
# The script passed to bash -c (to be able to use pipes) has variables like "$2" which won't expand
# using the current context, this is on purpose and so we disable shellcheck's warning
# shellcheck disable=SC2016
xargs -d '\n' -I {} -P "$CORES" bash -c '
        oid="${1%% *}"
        size="${1#* }"
        printf "version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %s\n" "$oid" "$size" | \
        GIT_LFS_SKIP_SMUDGE=0 \
        git -c lfs.fetchinclude="*" \
        -c lfs.fetchexclude="" \
        -c lfs.defaultremote="$2" lfs smudge > /dev/null
    ' _ "{}" "$SRC_REMOTE" < "$TMP_DIR/missing_oids_sizes.txt"

echo "6. Pushing ONLY the missing LFS objects to destination..."
# Pipe directly into xargs to prevent "Argument list too long" errors. Batches of 100 objects.
awk '{print $1}' "$TMP_DIR/missing_oids_sizes.txt" | \
    xargs -n 100 -P "$CORES" git lfs push --object-id "$DST_REMOTE"

echo "LFS Sync complete!"
