#!/usr/bin/env bash
#
# Postprocess a fuzzing campaign: save crashes, minimize the corpus, write a summary.
#
# Sections run in this order so each artifact is persisted before the next section starts.
# If a later section fails, the earlier outputs are already on disk and CI can upload them.
#
# 1. Crashes (per harness): merge → content-dedup → afl-cmin -C → count
#    Crashes are processed first because they are findings we never want to lose.
# 2. Corpus: merge queues → content-dedup → per-harness afl-cmin → union → content-dedup
# 3. Freshness from AFL fuzzer_stats per harness.
# 4. Run fuzz-stats over the stored corpus to produce the final histogram + summary.md; any input
#    that panics under fuzz-stats is archived under stored_crashes/from-corpus and folded into
#    the total crash count (catches flaky crashes AFL left in the queue).
#
# Outputs (under utils/fuzz/):
#   summary.md:                       markdown report (Slack-mrkdwn compatible) ready to paste as-is
#   stored_corpus/:                   minimized corpus
#   stored_crashes/:                  coverage-minimized crashes per harness
#   stored_crashes/from-corpus/:      flaky/undetected crashes surfaced by fuzz-stats
#
# Usage:
#   ./postcampaign.sh                  # defaults
#   ./postcampaign.sh --jobs 32        # parallelism for the cmin passes
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Defaults ────────────────────────────────────────────────────────────────
SYNC_DIR="$SCRIPT_DIR/sync_dir"
OUT_DIR="$SCRIPT_DIR/stored_corpus"
CRASHES_OUT="$SCRIPT_DIR/stored_crashes"
JOBS="$(nproc)"
HARNESSES=(harness-deser harness-verify harness-compute)

# ── Parse arguments ────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build the stored corpus (afl-cmin) + minimized crashes, and write summary.md."
    echo ""
    echo "Options:"
    echo "  --sync-dir DIR     AFL sync/output directory (default: $SCRIPT_DIR/sync_dir)"
    echo "  --out DIR          Stored corpus output (default: $SCRIPT_DIR/stored_corpus)"
    echo "  --crashes-out DIR  Minimized crashes output (default: $SCRIPT_DIR/stored_crashes)"
    echo "  --jobs N           Parallelism for the cmin passes (default: nproc)"
    echo "  -h, --help         Show this help message"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sync-dir)    SYNC_DIR="$2";    shift 2 ;;
        --out)         OUT_DIR="$2";     shift 2 ;;
        --crashes-out) CRASHES_OUT="$2"; shift 2 ;;
        --jobs)        JOBS="$2";        shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

cd "$REPO_ROOT"

TARGET_DIR="$(cargo metadata --format-version=1 --no-deps \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["target_directory"])')"

for harness in "${HARNESSES[@]}"; do
    if [[ ! -x "$TARGET_DIR/release/$harness" ]]; then
        echo "ERROR: $TARGET_DIR/release/$harness not found. Run build.sh first." >&2
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
# Workaround for a cmin bug in persistent mode: https://github.com/AFLplusplus/AFLplusplus/issues/2826
# Should be removed once the fixed version is integrated to cargo-afl.
export AFL_NO_FORKSRV=1

# Content-dedup the regular files directly under the given source dirs into "$1".
#
# Reads files and copies only one file per unique content hash, named by that hash.
# Hashing is batched and parallelized across $JOBS workers.
dedup_dirs_into() {
    local dst="$1"
    shift
    mkdir -p "$dst"
    [[ $# -gt 0 ]] || return 0

    # list samples in the input folder
    local files
    files="$(find "$@" -maxdepth 1 -type f ! -name 'README.txt')"

    echo "$files" |
        xargs -r -P "$JOBS" -n 256 stdbuf -oL sha256sum | # hash each file in parallel
        sort -u -k1,1 |                                     # keep one line per unique hash
        while read -r hash file; do                         # copy that file in, named by its hash
            [[ -e "$dst/$hash" ]] || cp "$file" "$dst/$hash"
        done
}

# Coverage-minimize the files in "$2" with harness "$1" into "$3". Any further arguments (e.g. -C
# for crash mode) are passed through to afl-cmin.
#
# `-T $JOBS` runs afl-cmin in parallel; that needs a file-input (@@) target, which the harnesses
# support for cmin/showmap (see harness_main).
cmin_into() {
    local harness="$1" input="$2" out="$3"
    shift 3
    cargo afl cmin -T "$JOBS" "$@" -m none \
        -i "$input" -o "$out" -- "$TARGET_DIR/release/$harness" @@
}

# ── Crashes (first, so they are saved before any corpus or stats step can fail) ──
# A crash reproduces only on the harness that produced it, so minimize each harness's crashes with
# its own binary. cmin -C keeps crashing inputs and minimizes by crash coverage, giving a
# unique-crash count (a coverage proxy for distinct bugs, not exact bug dedup).
rm -rf "$CRASHES_OUT"
declare -A crash_counts
total_crashes=0
for harness in "${HARNESSES[@]}"; do
    prefix="${harness#harness-}"
    crash_counts[$prefix]=0

    shopt -s nullglob # return an empty array if dir does not exist
    crash_dirs=("$SYNC_DIR/${prefix}"_*/crashes)
    shopt -u nullglob
    [[ ${#crash_dirs[@]} -eq 0 ]] && continue

    cdedup="$WORK/crash_unique_$prefix"
    dedup_dirs_into "$cdedup" "${crash_dirs[@]}"
    # skip if there is no crash
    [[ -n "$(find "$cdedup" -maxdepth 1 -type f -print -quit 2>/dev/null)" ]] || continue

    # -C: crash mode (keep crashing inputs, minimize by crash coverage).
    echo "==> crash cmin with $harness"
    cmin_into "$harness" "$cdedup" "$CRASHES_OUT/$prefix" -C
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

# ── Corpus: gather queues → dedup → per-harness cmin → union → dedup → stored corpus ──
shopt -s nullglob # return an empty array if dir does not exist
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

# Minimize independently per harness. Each harness reaches a different subset of the code
# (deser only deserializes; verify additionally proves; compute expands + does FHE ops), so
# a single global cmin would collapse to whichever harness's coverage came last. Union +
# content-dedup preserves all three.
for harness in "${HARNESSES[@]}"; do
    echo "==> cmin with $harness"
    cmin_into "$harness" "$UNIQUE" "$WORK/min_$harness"
done

rm -rf "$OUT_DIR"
dedup_dirs_into "$OUT_DIR" "$WORK"/min_harness-*
stored_count="$(find "$OUT_DIR" -type f | wc -l)"
echo "==> Stored corpus: $stored_count inputs ($OUT_DIR)"

# ── Freshness per harness from AFL fuzzer_stats ────────────────────────────
# Each instance writes fuzzer_stats with unix timestamps: start_time / last_update / last_find.
# Aggregate per harness: max(last_find) across its instances = "most recent find anywhere",
# referenced against max(last_update) for "how long since" and min(start_time) for "for how long".
# Use this to rebalance instance counts between campaigns: long since_last_find → reduce that
# harness's instances; still finding paths near campaign end → give it more cores.

# Extract one field from a fuzzer_stats file. Lines look like `key : value`: value is field 3.
# Returns 0 if the key is missing so the caller can use the value in arithmetic unconditionally.
get_stat() {
    local key="$1" file="$2" v
    v=$(awk -v k="$key" '$1==k {print $3; exit}' "$file")
    echo "${v:-0}"
}

declare -A last_find_age duration_seconds total_execs instance_count
for harness in "${HARNESSES[@]}"; do
    prefix="${harness#harness-}"

    shopt -s nullglob
    stats_files=("$SYNC_DIR/${prefix}"_*/fuzzer_stats)
    shopt -u nullglob
    instance_count[$prefix]=${#stats_files[@]}
    [[ ${#stats_files[@]} -eq 0 ]] && continue

    # Aggregate across the harness's instances:
    #   max_lf  = most recent last_find      (any instance found a new path)
    #   max_lu  = most recent last_update    (campaign stop)
    #   min_st  = earliest start_time        (campaign start)
    #   execs   = total execs across instances (execs_done is per-instance)
    max_lf=0; max_lu=0; min_st=0; execs=0
    for sf in "${stats_files[@]}"; do
        lf=$(get_stat last_find   "$sf")
        lu=$(get_stat last_update "$sf")
        st=$(get_stat start_time  "$sf")
        ex=$(get_stat execs_done  "$sf")

        (( lf > max_lf )) && max_lf=$lf
        (( lu > max_lu )) && max_lu=$lu
        (( min_st == 0 || st < min_st )) && min_st=$st
        execs=$(( execs + ex ))
    done

    if (( max_lf > 0 && max_lu > 0 )); then
        diff=$(( max_lu - max_lf ))
        (( diff < 0 )) && diff=0
        last_find_age[$prefix]=$diff
    fi
    (( min_st > 0 && max_lu > 0 )) && duration_seconds[$prefix]=$(( max_lu - min_st ))
    total_execs[$prefix]=$execs
done

fmt_age() {
    local s="${1:-}"
    [[ -z "$s" ]] && { printf 'n/a'; return; }
    if   [[ "$s" -lt 60    ]]; then printf '%ds' "$s"
    elif [[ "$s" -lt 3600  ]]; then printf '%dm%02ds' $((s/60)) $((s%60))
    elif [[ "$s" -lt 86400 ]]; then printf '%dh%02dm' $((s/3600)) $(((s%3600)/60))
    else                            printf '%dd%02dh' $((s/86400)) $(((s%86400)/3600))
    fi
}

fmt_num() {
    local n="${1:-}"
    [[ -z "$n" ]] && { printf 'n/a'; return; }
    numfmt --to=si --format='%.1f' "$n" 2>/dev/null || printf '%s' "$n"
}

# ── Statistics + summary.md ────────────────────────────────────────────────
echo "==> Computing statistics"
cargo build --release -p fuzz-stats
STATS_BIN="$TARGET_DIR/release/fuzz-stats"

SUMMARY="$SCRIPT_DIR/summary.md"
STATS_TABLE="$WORK/stats_table.txt"

CORPUS_CRASHES_DIR="$CRASHES_OUT/from-corpus"
"$STATS_BIN" --save-crashes "$CORPUS_CRASHES_DIR" "$OUT_DIR" > "$STATS_TABLE"

corpus_panic_count=0
if [[ -d "$CORPUS_CRASHES_DIR" ]]; then
    corpus_panic_count="$(find "$CORPUS_CRASHES_DIR" -maxdepth 1 -type f | wc -l)"
fi
total_crashes=$((total_crashes + corpus_panic_count))

{
    echo "*${total_crashes} crashes* - ran for $(fmt_age "${duration_seconds[deser]-}")"
    echo ""
    echo '```'
    cat "$STATS_TABLE"
    echo ""
    crash_breakdown="deser: ${crash_counts[deser]}, verify: ${crash_counts[verify]}, compute: ${crash_counts[compute]}"
    if (( corpus_panic_count > 0 )); then
        # "corpus" = panics found by re-running the stored corpus (likely flaky crashes AFL kept
        # in the queue instead of crashes/).
        crash_breakdown="$crash_breakdown, corpus: $corpus_panic_count"
    fi
    echo "Crashes: $total_crashes ($crash_breakdown)"
    echo ""
    echo "Instances (master + secondaries):"
    for harness in "${HARNESSES[@]}"; do
        prefix="${harness#harness-}"
        echo "  $prefix: ${instance_count[$prefix]:-0}"
    done
    echo ""
    echo "Executions:"
    for harness in "${HARNESSES[@]}"; do
        prefix="${harness#harness-}"
        echo "  $prefix: $(fmt_num "${total_execs[$prefix]-}")"
    done
    echo ""
    echo "Time since last new path found:"
    for harness in "${HARNESSES[@]}"; do
        prefix="${harness#harness-}"
        echo "  $prefix: $(fmt_age "${last_find_age[$prefix]-}")"
    done
    echo '```'
} > "$SUMMARY"

cat "$SUMMARY"
