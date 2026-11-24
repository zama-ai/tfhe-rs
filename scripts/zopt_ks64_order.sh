#!/usr/bin/env bash
# Investigates why the KS-PBS set measured first gets ~1.5x more throughput than the
# sets measured after it. Runs the zopt KS64 throughput benchmarks in several variants,
# all at the same pinned batch, and logs the CPU frequency and the huge pages meanwhile.
#
# Usage: scripts/zopt_ks64_order.sh <cargo toolchain argument>
set -euo pipefail

TOOLCHAIN="$1"

cargo_bench() {
    cargo "${TOOLCHAIN}" bench --bench core_crypto-ks-pbs \
        --features=boolean,shortint,internal-keycache -p tfhe-benchmark
}

echo "=== machine"
nproc
ls -d /sys/devices/system/node/node* || true
cat /sys/kernel/mm/transparent_hugepage/enabled || true
cat /sys/kernel/mm/transparent_hugepage/defrag || true
ldd --version | head -1 || true

# Average CPU frequency and huge pages every 15 s.
(
    while true; do
        mhz=$(awk '/cpu MHz/ {s += $4; n++} END {if (n) printf "%.0f", s / n}' /proc/cpuinfo)
        thp=$(awk '/AnonHugePages/ {print $2}' /proc/meminfo)
        free=$(awk '/MemFree/ {print $2}' /proc/meminfo)
        echo "=== monitor $(date +%T) avg_mhz=${mhz} anon_huge_kb=${thp} mem_free_kb=${free}"
        sleep 15
    done
) &
MONITOR=$!
trap 'kill ${MONITOR}' EXIT

export __TFHE_RS_BENCH_TYPE=THROUGHPUT
export ZOPT_KS64_BATCH=2048

# Builds once, outside the measures.
ZOPT_KS64_ONLY=none cargo_bench

echo "=== variant CONTROL: one process, default first and last"
ZOPT_KS64_TAG=_CONTROL cargo_bench

echo "=== variant MMAP: same, glibc mmap threshold fixed"
MALLOC_MMAP_THRESHOLD_=131072 ZOPT_KS64_TAG=_MMAP cargo_bench

echo "=== variant REVERSE: one process, reversed order"
ZOPT_KS64_REVERSE=1 ZOPT_KS64_TAG=_REVERSE cargo_bench

echo "=== variant ALONE: one process per set"
for name in BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 \
    ZOPT_KS64_132_S80_2M128_COST ZOPT_KS64_132_S80_2M128_BOOTSTRAP_COST \
    ZOPT_KS64_132_S80_2M160_COST ZOPT_KS64_132_S80_2M160_BOOTSTRAP_COST \
    ZOPT_KS64_160_S80_2M128_COST ZOPT_KS64_160_S80_2M128_BOOTSTRAP_COST \
    ZOPT_KS64_160_S126_2M128_COST ZOPT_KS64_160_S126_2M128_BOOTSTRAP_COST \
    ZOPT_KS64_160_S125_2M160_COST ZOPT_KS64_160_S125_2M160_BOOTSTRAP_COST \
    BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_LAST; do
    ZOPT_KS64_ONLY="${name}" ZOPT_KS64_TAG=_ALONE cargo_bench
done
