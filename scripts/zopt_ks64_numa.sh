#!/usr/bin/env bash
# Compares two NUMA placements of the zopt KS64 keys at a pinned batch: one process with
# the memory interleaved over the nodes, and one process per node with its own copy of
# the keys. Samples every 15 s the memory of a benchmark process per node (all of it,
# and its largest mapping: the key). The first-touch runs are in the history.
#
# Usage: scripts/zopt_ks64_numa.sh <ks_pbs|pbs128> <cargo toolchain argument>
set -euo pipefail

BENCH="$1"
TOOLCHAIN="$2"

cargo_bench() {
    cargo "${TOOLCHAIN}" bench --bench "core_crypto-${BENCH//_/-}" \
        --features=boolean,shortint,internal-keycache -p tfhe-benchmark
}

echo "=== machine"
nproc
cat /sys/kernel/mm/transparent_hugepage/enabled || true
cat /proc/sys/kernel/numa_balancing || true
if ! command -v numactl > /dev/null; then
    sudo apt-get install -y numactl > /dev/null || sudo apt-get update > /dev/null \
        && sudo apt-get install -y numactl > /dev/null
fi
numactl --hardware

# The memory of the benchmark process per node, in MB, from its numa_maps.
numa_sample() {
    local pid
    pid=$(pgrep -n -f '/core_crypto_[a-z0-9_]+-[0-9a-f]{16}( |$)') || return 0
    awk '
        {
            kb = 4; t = 0; delete m
            for (i = 1; i <= NF; i++) if ($i ~ /^kernelpagesize_kB=/) { split($i, a, "="); kb = a[2] }
            for (i = 1; i <= NF; i++) if ($i ~ /^N[0-9]+=/) {
                split($i, a, "="); n = substr(a[1], 2); mb = a[2] * kb / 1024
                total[n] += mb; m[n] = mb; t += mb
            }
            if (t > big) { big = t; delete bm; for (n in m) bm[n] = m[n] }
        }
        END {
            s = sprintf("total:"); for (n = 0; n < 8; n++) s = s sprintf(" N%d=%.0f", n, total[n])
            s = s sprintf(" | largest %.0f:", big); for (n = 0; n < 8; n++) s = s sprintf(" N%d=%.0f", n, bm[n])
            print s
        }' "/proc/${pid}/numa_maps" 2> /dev/null || true
}

(
    while true; do
        migrated=$(awk '/^numa_pages_migrated/ {print $2}' /proc/vmstat)
        echo "=== numa $(date +%T) migrated=${migrated} $(numa_sample)"
        sleep 15
    done
) &
MONITOR=$!
trap 'kill ${MONITOR}' EXIT

export __TFHE_RS_BENCH_TYPE=THROUGHPUT

variant() {
    echo "=== variant $1"
    ZOPT_KS64_TAG="$1" "${@:2}" bash -c "$(declare -f cargo_bench); BENCH=${BENCH} TOOLCHAIN=${TOOLCHAIN} cargo_bench"
}

NODES=$(ls -d /sys/devices/system/node/node[0-9]* | wc -l)

# One process per NUMA node, each on the cores and the memory of its node, so with its
# own copy of the keys, at 1/NODES of the batch. A barrier before each set keeps the
# processes on the same set; the machine throughput is the sum of the processes'.
per_node() {
    local tag="$1" batch="$2" exe barrier n
    exe=$(cargo "${TOOLCHAIN}" bench --no-run --message-format=json --bench "core_crypto-${BENCH//_/-}" \
        --features=boolean,shortint,internal-keycache -p tfhe-benchmark \
        | grep -o '"executable":"[^"]*/core_crypto_[^"]*"' | tail -1 | cut -d'"' -f4)
    [ -x "${exe}" ] || { echo "no benchmark executable" >&2; exit 1; }
    barrier=$(mktemp -d)
    echo "=== variant ${tag}: ${NODES} processes of batch $((batch / NODES)), ${exe}"
    # Waits for the benchmark processes only: a bare wait would also wait for the
    # monitor, which never ends. Each line of output is prefixed with its node.
    local pids=()
    for n in $(seq 0 $((NODES - 1))); do
        (cd tfhe-benchmark && ZOPT_KS64_TAG="${tag}_N${n}" ZOPT_KS64_BATCH=$((batch / NODES)) \
            ZOPT_KS64_BARRIER_DIR="${barrier}" ZOPT_KS64_BARRIER_N="${NODES}" \
            CARGO_TARGET_DIR="$(pwd)/../target" \
            numactl --cpunodebind="${n}" --membind="${n}" "${exe}" --bench 2>&1 \
            | sed -u "s/^/[node ${n}] /") &
        pids+=($!)
    done
    local status=0
    for pid in "${pids[@]}"; do
        wait "${pid}" || status=$?
    done
    echo "=== variant ${tag} done, status ${status}"
}

case "${BENCH}" in
ks_pbs)
    export ZOPT_KS64_BATCH=2048
    ZOPT_KS64_ONLY=none cargo_bench
    variant _INTERLEAVE numactl --interleave=all
    per_node _PER_NODE 2048
    ;;
pbs128)
    # One squashing PBS per core per iteration: the largest keys take seconds each.
    export ZOPT_KS64_BATCH=192
    ZOPT_KS64_ONLY=none cargo_bench
    variant _INTERLEAVE numactl --interleave=all
    per_node _PER_NODE 192
    ;;
esac
