# Fuzzing `ProvenCompactCiphertextList`

This directory contains AFL-based fuzz harnesses targeting `ProvenCompactCiphertextList`,
the type received from untrusted clients with ZK proofs.

## What we're testing

Two safety invariants:

1. **Deserialization + conformance checking never crash**, regardless of input.
2. **If conformance passes, all downstream operations never crash**: verification,
   expansion, and FHE arithmetic must either succeed or return an error, never panic.

## Harnesses

Three harnesses run in the same campaign, sharing a sync directory so AFL
cross-pollinates findings between them:

| Harness           | What it does                                                            | Speed                                 |
|-------------------|-------------------------------------------------------------------------|---------------------------------------|
| `harness-deser`   | `safe_deserialize_conformant` only                                      | Fast - explores byte patterns quickly |
| `harness-verify`  | Deserialize, then verify the ZK proof                                   | Medium                                |
| `harness-compute` | Deserialize, `expand_without_verification`, then add/mul/sub + compress | Slow - exercises FHE arithmetic       |

`harness-compute` skips ZK verification intentionally: randomly producing a valid
proof is astronomically unlikely, so verification would reject every input before
reaching the code we actually want to test.

To avoid wasting coverage on deserialization code that `harness-deser` already
covers thoroughly, `harness-verify` and `harness-compute` are built with
`denylist_deep.txt`, which excludes `deserialize*`, `is_conformant*`,
`unversionize*`, and `upgrade*` from AFL instrumentation.

## Prerequisites

Install `cargo-afl`:

```
cargo install cargo-afl
```

## Quick start

```bash
cd utils/fuzz

# Build harnesses + generate initial corpus and auxiliary data (keys, CRS)
./build.sh --corpusgen

# Run a short test campaign (1 hour, default 16 instances)
./run.sh --duration 3600
```

To rebuild harnesses without regenerating corpus/keys:

```bash
./build.sh
```

## Build script (`build.sh`)

```
./build.sh [--corpusgen]
```

- Builds all three harnesses with AFL instrumentation (`cargo afl build --release`).
- `harness-deser` gets full instrumentation; `harness-verify` and `harness-compute`
  use the denylist.
- `--corpusgen` also builds and runs the corpus generator, which writes:
  - `corpus/input.bin`: seed input (a valid proven compact ciphertext list)
  - `aux_data/server_key.bin`, `aux_data/crs.bin`, `aux_data/pubkey.bin`: loaded
    by harnesses at startup

All auxiliary data uses intentionally insecure parameters (tiny LWE dimension, zero
noise) for two reasons:
- FHE operations are faster, meaning more exec/seconds
- input space is smaller, increasing the probability of meaningful mutations

## Launch script (`run.sh`)

```
./run.sh [OPTIONS]
```

| Option                  | Default               | Description                                     |
|-------------------------|-----------------------|-------------------------------------------------|
| `--corpus-dir DIR`      | `utils/fuzz/corpus`   | Initial corpus directory                        |
| `--sync-dir DIR`        | `utils/fuzz/sync_dir` | AFL output / sync directory                     |
| `--deser-secondary N`   | 3                     | Number of `harness-deser` secondary instances   |
| `--verify-secondary N`  | 3                     | Number of `harness-verify` secondary instances  |
| `--compute-secondary N` | 5                     | Number of `harness-compute` secondary instances |
| `--duration SECONDS`    | 86400 (24h)           | How long to run before stopping                 |

This launches one master (`-M`) per harness plus the configured secondaries (`-S`),
all writing to the same `--sync-dir`. The default layout uses 16 cores:

| Instance         | Harness         | Role      |
|------------------|-----------------|-----------|
| `deser_m`        | harness-deser   | Master    |
| `deser_s1..s3`   | harness-deser   | Secondary |
| `verify_m`       | harness-verify  | Master    |
| `verify_s1..s3`  | harness-verify  | Secondary |
| `compute_m`      | harness-compute | Master    |
| `compute_s1..s5` | harness-compute | Secondary |

Press `Ctrl-C` to stop early; the script sends `SIGINT` to all instances on exit.

### CMPLOG

AFL++'s CMPLOG instruments comparisons to help solve magic bytes and multi-byte
checks in deserialization code. It roughly doubles instrumentation overhead, so
it's only useful on a few instances. The script keeps CMPLOG enabled on master
instances (the cargo-afl default) and disables it on all secondaries (`-c -`).

### Scaling to large instances

Each AFL instance uses one core (`RAYON_NUM_THREADS=1`), so a 192-core server
can run 192 instances. Distribute them unevenly based on harness cost:

| Harness         | Masters | Secondaries | Total | Rationale        |
|-----------------|---------|-------------|-------|------------------|
| harness-deser   | 1       | 15          | 16    | Fast but shallow |
| harness-verify  | 1       | 47          | 48    | Medium speed     |
| harness-compute | 1       | 127         | 128   | Slowest per-exec |

```bash
./run.sh --deser-secondary 15 --verify-secondary 47 --compute-secondary 127
```

This is a starting point. After the first campaign, check `afl-whatsup` output
per group: if deser instances show no new paths for 12h, reduce them; if compute
instances are still finding paths at hour 24, give them more cores.

At this scale, AFL's sync mechanism (each instance periodically scans all other
instances' queues) can cause I/O pressure. Mitigations:

- Set `AFL_IMPORT_FIRST=1` so instances prioritize syncing from others before
  doing their own mutations.
- Ensure the sync dir is on fast local storage (NVMe), not a network mount.

### Threading

All instances run single-threaded (`RAYON_NUM_THREADS=1`). This is required because:

- N single-threaded instances explore N different inputs in parallel: better
  coverage per core than one multi-threaded instance.
- Rayon's work-stealing is non-deterministic, which tanks AFL's stability metric
  and corrupts the shared coverage bitmap.

## Interpreting results

After a campaign, results are in the sync directory:

```
sync_dir/
├── deser_m/
│   ├── crashes/     # inputs that caused a panic/crash
│   ├── queue/       # corpus entries discovered by this instance
│   └── fuzzer_stats
├── deser_s1/
│   └── ...
├── verify_m/
│   └── ...
└── compute_m/
    └── ...
```

### Crashes

Any file in a `crashes/` subdirectory is an input that caused the harness to panic.
To reproduce:

```bash
# Without AFL (reads from stdin, prints the outcome)
./target/release/harness-compute < sync_dir/compute_m/crashes/id:000000,...
```

A crash in `harness-deser` means deserialization or conformance panicked — a
violation of invariant 1. A crash in `harness-verify` or `harness-compute` means
post-conformance code panicked — a violation of invariant 2.

### Corpus reuse

The corpus grows incrementally across campaigns. To reuse it, point `--corpus-dir`
at a previous sync directory's merged queue, or use `afl-cmin` to minimize first:

```bash
# Merge all queues into one directory
mkdir merged_corpus
cp sync_dir/*/queue/id:* merged_corpus/

# Minimize (remove redundant inputs)
cargo afl cmin -i merged_corpus -o minimized_corpus -- ./target/release/harness-deser

# Start next campaign from minimized corpus
./run.sh --corpus-dir minimized_corpus
```

**Important:** auxiliary data (keys, CRS, public key) and corpus must always come
from the same generation. Never mix a corpus produced with one set of keys with
different auxiliary data — deserialization will reject every input.
