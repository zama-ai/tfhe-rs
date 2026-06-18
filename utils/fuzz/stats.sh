#!/usr/bin/env bash
#
# Produce the stored corpus + crashes for a fuzzing campaign and report statistics.
#
# Corpus pipeline:
#   1. Merge every instance's queue from the sync dir into one directory.
#   2. Content-dedup it (collapses the byte-identical copies AFL syncs across instances) — this
#      only speeds up the cmin passes, it does not change their result.
#   3. Coverage-minimize independently with each harness, then union the results. Each harness
#      carries a different instrumentation bitmap (deser is denylisted out of verify/compute), so
#      the union preserves every harness's coverage — a single cmin would lose two of the three.
#   4. Content-dedup the union (an input selected by two harnesses appears twice) → stored corpus.
#   5. fuzz-stats over the stored corpus.
#
# Crash pipeline (per harness, mapped by instance-name prefix):
#   merge that harness's crashes → content-dedup → afl-cmin -C (minimize by crash coverage) → count.
#
# The stored corpus (--out) and crashes (--crashes-out) are what CI uploads to S3; the corpus also
# seeds the next campaign. Hangs are AFL's concern and are ignored.
#
# Usage:
#   ./stats.sh                  # defaults: sync_dir, JOBS=nproc, table output
#   ./stats.sh --json           # machine-readable stats (for CI / Slack)
#   ./stats.sh --jobs 32        # parallelism for the cmin passes
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Defaults ────────────────────────────────────────────────────────────────
SYNC_DIR="$SCRIPT_DIR/sync_dir"
OUT_DIR="$SCRIPT_DIR/stored_corpus"
CRASHES_OUT="$SCRIPT_DIR/stored_crashes"
JOBS="$(nproc)"
JSON_FLAG=""
HARNESSES=(harness-deser harness-verify harness-compute)

# ── Parse arguments ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sync-dir)    SYNC_DIR="$2";    shift 2 ;;
        --out)         OUT_DIR="$2";     shift 2 ;;
        --crashes-out) CRASHES_OUT="$2"; shift 2 ;;
        --jobs)        JOBS="$2";        shift 2 ;;
        --json)        JSON_FLAG="--json"; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Build the stored corpus (three-way cmin union) + minimized crashes,"
            echo "and report statistics."
            echo ""
            echo "Options:"
            echo "  --sync-dir DIR     AFL sync/output directory (default: utils/fuzz/sync_dir)"
            echo "  --out DIR          Stored corpus output (default: utils/fuzz/stored_corpus)"
            echo "  --crashes-out DIR  Minimized crashes output (default: utils/fuzz/stored_crashes)"
            echo "  --jobs N           Parallelism for the cmin passes (default: nproc)"
            echo "  --json             Emit machine-readable JSON stats"
            echo "  -h, --help         Show this help message"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

cd "$REPO_ROOT"

for harness in "${HARNESSES[@]}"; do
    if [[ ! -x "$REPO_ROOT/target/release/$harness" ]]; then
        echo "ERROR: target/release/$harness not found. Run build.sh first." >&2
        exit 1
    fi
done

if [[ ! -d "$SYNC_DIR" ]]; then
    echo "ERROR: sync directory '$SYNC_DIR' not found." >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export AFL_SKIP_CPUFREQ=1
export RAYON_NUM_THREADS=1
# Disable the fork server for cmin/showmap. The afl crate's deferred fork server doesn't deliver the
# testcase to the harness under afl-showmap (every input traces identically → cmin keeps nothing); a
# fresh exec per input delivers stdin correctly. Slower per input (keys reload each exec), but the
# sharded parallelism (cmin_parallel) hides it.
export AFL_NO_FORKSRV=1

# Hash used only for content-dedup. No collision resistance is needed (a collision would merely drop
# a distinct corpus input); any ≥128-bit hash is fine. Files are tiny, so this is open/read-bound,
# not hash-bound — the algorithm barely matters. A faster one (b2sum, xxhsum) can be dropped in.
HASH_CMD="sha256sum"

# Content-dedup the regular files directly under the given source dirs into "$1".
#
# Reads sources in place (no merge-copy) and copies only one file per unique content hash, named by
# that hash. Hashing is batched and parallelized across $JOBS workers — a per-file `sha256sum` loop
# spawns millions of subprocesses on a real campaign and is the dominant cost. `stdbuf -oL` keeps
# each `sha256sum` output line atomic (< PIPE_BUF) so parallel writers can't interleave mid-line.
dedup_dirs_into() {
    local dst="$1"
    shift
    mkdir -p "$dst"
    [[ $# -gt 0 ]] || return 0
    # Keep one file per unique hash. The awk split on the hash field is hash-width-independent and
    # tolerates paths with spaces (the path is everything after "<hash>  ").
    find "$@" -maxdepth 1 -type f ! -name 'README.txt' -print0 \
        | xargs -0 -r -P "$JOBS" -n 256 stdbuf -oL "$HASH_CMD" \
        | awk '!seen[$1]++ { print $1 "\t" substr($0, length($1) + 3) }' \
        | while IFS=$'\t' read -r h f; do
            [[ -e "$dst/$h" ]] || cp "$f" "$dst/$h"
        done
}

# Coverage-minimize the files in "$2" with harness "$1", result deduped into "$3". Any further
# arguments (e.g. -C for crash mode) are passed through to afl-cmin.
#
# afl-cmin's own -T parallelism needs a file-input (@@) target, but the harnesses read stdin, so we
# parallelize ourselves: shard the inputs into up-to-$JOBS dirs and run one single-task (stdin) cmin
# per shard concurrently, then union the shard outputs. Each shard's cmin preserves that shard's
# coverage, so the union preserves the harness's full coverage (lossless, though not globally minimal
# — a per-shard representative may recur across shards).
cmin_parallel() {
    local harness="$1" input="$2" out="$3"
    shift 3
    local extra=("$@")
    local bin="$REPO_ROOT/target/release/$harness"
    local base
    base="$(mktemp -d "$WORK/cmin.XXXXXX")"
    mkdir -p "$out"

    local nfiles
    nfiles="$(find "$input" -maxdepth 1 -type f | wc -l)"
    [[ "$nfiles" -eq 0 ]] && return 0
    local n=$((nfiles < JOBS ? nfiles : JOBS))

    local j
    for ((j = 0; j < n; j++)); do mkdir -p "$base/in/$j"; done
    # Round-robin the inputs into shard dirs via parallel hardlinks (avoids a per-file ln loop).
    find "$input" -maxdepth 1 -type f -printf '%p\0%f\0' \
        | awk -v RS='\0' -v ORS='\0' -v n="$n" -v root="$base/in" '
            NR % 2 == 1 { src = $0; next }
            { print src; print root "/" ((NR / 2 - 1) % n) "/" $0 }' \
        | xargs -0 -r -n2 ln

    # One single-task cmin per shard, $JOBS at a time. Output is silenced (interleaved logs are
    # noise); an empty union afterwards is the signal that something went wrong.
    seq 0 $((n - 1)) | xargs -P "$JOBS" -I{} \
        cargo afl cmin "${extra[@]}" -m none -i "$base/in/{}" -o "$base/out/{}" -- "$bin" \
        >/dev/null 2>&1 || true

    dedup_dirs_into "$out" "$base"/out/*
}

# ── Corpus step 1+2: gather all queues and content-dedup (speed) ───────────
shopt -s nullglob
queue_dirs=("$SYNC_DIR"/*/queue)
shopt -u nullglob
if [[ ${#queue_dirs[@]} -eq 0 ]]; then
    echo "ERROR: no queue directories found under '$SYNC_DIR'/*/queue." >&2
    exit 1
fi

echo "==> Scanning ${#queue_dirs[@]} queues..."
merged_count="$(find "${queue_dirs[@]}" -maxdepth 1 -type f | wc -l)"
echo "==> Deduplicating $merged_count queue entries with $JOBS workers..."
UNIQUE="$WORK/unique"
dedup_dirs_into "$UNIQUE" "${queue_dirs[@]}"
unique_count="$(find "$UNIQUE" -type f | wc -l)"
echo "==> $merged_count queue entries → $unique_count unique inputs"

# ── Corpus step 3: minimize independently per harness (sharded parallel) ───
for harness in "${HARNESSES[@]}"; do
    echo "==> cmin with $harness ($JOBS-way sharded)"
    cmin_parallel "$harness" "$UNIQUE" "$WORK/min_$harness"
done

# ── Corpus step 4: union the minimized sets + content-dedup → stored corpus ─
rm -rf "$OUT_DIR"
dedup_dirs_into "$OUT_DIR" "$WORK"/min_harness-*
stored_count="$(find "$OUT_DIR" -type f | wc -l)"
echo "==> Stored corpus: $stored_count inputs ($OUT_DIR)"

# ── Crashes: per harness, merge → dedup → cmin -C → count ──────────────────
# A crash reproduces only on the harness that produced it, so we minimize each harness's crashes
# with its own binary. cmin -C keeps crashing inputs and minimizes by crash coverage, giving a
# unique-crash count (a coverage proxy for distinct bugs, not exact bug dedup).
rm -rf "$CRASHES_OUT"
declare -A crash_counts
total_crashes=0
for harness in "${HARNESSES[@]}"; do
    prefix="${harness#harness-}"
    crash_counts[$prefix]=0

    shopt -s nullglob
    crash_dirs=("$SYNC_DIR/${prefix}"_*/crashes)
    shopt -u nullglob
    [[ ${#crash_dirs[@]} -eq 0 ]] && continue

    cdedup="$WORK/crash_unique_$prefix"
    dedup_dirs_into "$cdedup" "${crash_dirs[@]}"
    [[ -n "$(find "$cdedup" -maxdepth 1 -type f -print -quit 2>/dev/null)" ]] || continue

    # -C: crash mode (keep crashing inputs, minimize by crash coverage). Sharded like the corpus.
    echo "==> crash cmin with $harness"
    cmin_parallel "$harness" "$cdedup" "$CRASHES_OUT/$prefix" -C
    n="$(find "$CRASHES_OUT/$prefix" -type f | wc -l)"

    # Safety net: never under-report crashes to 0. If cmin kept nothing despite real crash inputs,
    # fall back to the content-deduped set (content-unique rather than coverage-unique).
    if [[ "$n" -eq 0 ]]; then
        echo "warning: crash cmin kept 0 for $harness; falling back to content-unique crashes" >&2
        dedup_dirs_into "$CRASHES_OUT/$prefix" "$cdedup"
        n="$(find "$CRASHES_OUT/$prefix" -type f | wc -l)"
    fi

    crash_counts[$prefix]=$n
    total_crashes=$((total_crashes + n))
done
echo "==> Crashes: $total_crashes unique (deser: ${crash_counts[deser]}, verify: ${crash_counts[verify]}, compute: ${crash_counts[compute]}) ($CRASHES_OUT)"

# ── Statistics ─────────────────────────────────────────────────────────────
echo "==> Computing statistics"
cargo build --release -p fuzz-stats
STATS_BIN="$REPO_ROOT/target/release/fuzz-stats"

stats_rc=0
if [[ -n "$JSON_FLAG" ]]; then
    corpus_json="$("$STATS_BIN" --json "$OUT_DIR")" || stats_rc=$?
    printf '{"corpus":%s,"crashes":{"total":%d,"deser":%d,"verify":%d,"compute":%d}}\n' \
        "$corpus_json" "$total_crashes" \
        "${crash_counts[deser]}" "${crash_counts[verify]}" "${crash_counts[compute]}"
else
    "$STATS_BIN" "$OUT_DIR" || stats_rc=$?
fi

# Propagate a panic in the corpus (fuzz-stats exits nonzero) — that's a regression. Crashes
# themselves are expected findings and do not fail the run.
exit "$stats_rc"
