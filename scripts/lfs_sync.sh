#!/bin/bash

# This script tries to:
# List all LFS references in a source remote on the given target branch and all tags
# List all LFS references in a destination remote on the given target branch and all tags
# Verify which LFS references are missing in the destination remote
# Fetch ONLY the missing LFS references from the destination remote
# Push all the LFS objects to the destination repo

set -euo pipefail

# 1. Handle Command-Line Arguments
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <src_remote> <destination_remote> [branch]"
    echo "Example: $0 origin upstream main"
    exit 1
fi

SRC_REMOTE="$1"
DST_REMOTE="$2"
BRANCH="$3"
SAFE_BRANCH="${BRANCH//\//_}" # Replace slashes with underscores for safe filenames

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

echo "Starting LFS sync from '$SRC_REMOTE' to '$DST_REMOTE' for branch '$BRANCH' and all tags..."
echo "Using temporary directory: $TMP_DIR"

echo "1. Fetching Git metadata for $BRANCH and tags from source..."
git fetch "$SRC_REMOTE" "$BRANCH" --tags
echo "   Fetching Git metadata for $BRANCH from destination..."
git fetch "$DST_REMOTE" "$BRANCH"

echo "2. Inventorying LFS objects for Source ($BRANCH + Tags)..."
# Get branch output
git lfs ls-files "$SRC_REMOTE/$BRANCH" --long > "$TMP_DIR/src_${SAFE_BRANCH}.txt"

# Run xargs safely by writing to unique files based on the commit hash
echo "   Running parallel inventory on source tags using $CORES CPU cores..." >&2
git ls-remote --tags --refs "$SRC_REMOTE" | awk '{print $1}' | sort -u | \
    xargs -I {} -P "$CORES" bash -c "git lfs ls-files \"{}\" --long 2>/dev/null > \"$TMP_DIR/src_{}.txt\""

# Concatenate all source files and deduplicate
for file in "$TMP_DIR"/src_*.txt; do
    # Extract the glob part using bash string manipulation
    filename="${file##*/src_}" # Removes the path and "src_"
    git_ref="${filename%.txt}"       # Removes the ".txt" suffix

    # Avoid having a special case for branch, get the corresponding sha1 from source remote
    if [[ "$git_ref" == "$SAFE_BRANCH" ]]; then
        git_ref=$(git rev-parse "$SRC_REMOTE/$BRANCH")
    fi

    # Read each line, safely extracting the ID and preserving the full path spacing
    awk -v g="$git_ref" '{
        oid = $1
        type = $2

        sub("^[ \t]*" oid "[ \t]+" type "[ \t]+", "")

        print g, oid, $0
    }' "$file"
done | sort -u -k 2,3 > "$TMP_DIR/src_unique_oid_paths.txt"

echo "3. Inventorying LFS objects for Destination ($BRANCH + Tags)..."
git lfs ls-files "$DST_REMOTE/$BRANCH" --long 2>/dev/null > "$TMP_DIR/dst_${SAFE_BRANCH}.txt"

echo "   Running parallel inventory on destination tags using $CORES CPU cores..." >&2
git ls-remote --tags --refs "$DST_REMOTE" | awk '{print $1}' | sort -u | \
    xargs -I {} -P "$CORES" bash -c "git lfs ls-files \"{}\" --long 2>/dev/null > \"$TMP_DIR/dst_{}.txt\""

# Concatenate all destination files and deduplicate
for file in "$TMP_DIR"/dst_*.txt; do
    # Extract the glob part using bash string manipulation
    filename="${file##*/dst_}" # Removes the path and "dst_"
    git_ref="${filename%.txt}"       # Removes the ".txt" suffix

    # Avoid having a special case for branch, get the corresponding sha1 from source remote
    if [[ "$git_ref" == "$SAFE_BRANCH" ]]; then
        git_ref=$(git rev-parse "$DST_REMOTE/$BRANCH")
    fi

    # Read each line, safely extracting the ID and preserving the full path spacing
    awk -v g="$git_ref" '{
        oid = $1
        type = $2

        sub("^[ \t]*" oid "[ \t]+" type "[ \t]+", "")

        print g, oid, $0
    }' "$file"
done | sort -u -k 2,3 > "$TMP_DIR/dst_unique_oid_paths.txt"

echo "4. Comparing to find missing LFS objects..."
comm -23 <(awk '{print $2}' "$TMP_DIR/src_unique_oid_paths.txt" | sort) \
         <(awk '{print $2}' "$TMP_DIR/dst_unique_oid_paths.txt" | sort) > "$TMP_DIR/missing_oids.txt"

if [ ! -s "$TMP_DIR/missing_oids.txt" ]; then
    echo "No missing LFS objects found for $BRANCH and tags. Destination is up to date."
    exit 0
fi

MISSING_COUNT=$(wc -l < "$TMP_DIR/missing_oids.txt")
echo "Found $MISSING_COUNT missing LFS objects. Extracting paths..."

# -F: patterns are fixed strings, -w: match whole word, -f: get them from the file
grep -F -w -f "$TMP_DIR/missing_oids.txt" "$TMP_DIR/src_unique_oid_paths.txt" | \
    sort -u -k 2 > "$TMP_DIR/missing_refs_oid_paths.txt"

echo "5. Fetching ONLY missing LFS objects from source..."
# Use the git lfs smudge trick to download a file without checking against current source tree
# The script passed to bash -c (to be able to use pipes) has variables like "$2" which won't expand
# using the current context, this is on purpose and so we disable shellcheck's warning
# shellcheck disable=SC2016
awk '{
    ref = $1
    oid = $2
    # Snip off the ref and oid to isolate the full path in $0
    sub("^[ \t]*" ref "[ \t]+" oid "[ \t]+", "")
    printf "%s:%s\n", ref, $0
}' "$TMP_DIR/missing_refs_oid_paths.txt" | \
    xargs -d '\n' -I {} -P "$CORES" bash -c '
        git show "$1" | \
        GIT_LFS_SKIP_SMUDGE=0 \
        git -c lfs.fetchinclude="*" \
        -c lfs.fetchexclude="" \
        -c lfs.defaultremote="$2" lfs smudge > /dev/null
    ' _ "{}" "$SRC_REMOTE"

echo "6. Pushing ONLY the missing LFS objects to destination..."
# Pipe directly into xargs to prevent "Argument list too long" errors. Batches of 100 objects.
awk '{print $2}' "$TMP_DIR/missing_refs_oid_paths.txt" | \
    xargs -n 100 -P "$CORES" git lfs push --object-id "$DST_REMOTE"

echo "LFS Sync complete!"
