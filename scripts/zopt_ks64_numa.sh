#!/usr/bin/env bash
# Checks where the zopt KS64 benchmarks place their keys over the NUMA nodes and how
# the throughput depends on it: runs a benchmark with and without the memory
# interleaved over the nodes, at a pinned batch, and samples every 15 s the memory of
# the benchmark process per node (all of it, and its largest mapping: the key).
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
    pid=$(pgrep -n -f 'target/release/deps/core_crypto_') || return 0
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

case "${BENCH}" in
ks_pbs)
    export ZOPT_KS64_BATCH=2048
    ZOPT_KS64_ONLY=none cargo_bench
    for name in BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 \
        ZOPT_KS64_160_S125_2M160_BOOTSTRAP_COST; do
        export ZOPT_KS64_ONLY="${name}"
        variant _NUMA_FIRST_TOUCH env
        variant _NUMA_INTERLEAVE numactl --interleave=all
    done
    ;;
pbs128)
    # One squashing PBS per core per iteration: the largest keys take seconds each.
    export ZOPT_KS64_BATCH=192
    variant _INTERLEAVE numactl --interleave=all
    variant _FIRST_TOUCH env
    ;;
esac
