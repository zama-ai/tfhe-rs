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

# After a campaign: minimize the corpus and report outcome statistics
./stats.sh
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

### Stored corpus + statistics (`stats.sh` / `fuzz-stats`)

`stats.sh` builds the **stored corpus** — the artifact CI uploads to S3 and reuses
as the next campaign's seed — and reports statistics on it:

```bash
./stats.sh            # table output, JOBS=nproc
./stats.sh --json     # machine-readable (for CI / Slack)
./stats.sh --jobs 32  # cmin parallelism
```

| Option              | Default                     | Description                              |
|---------------------|-----------------------------|------------------------------------------|
| `--sync-dir DIR`    | `utils/fuzz/sync_dir`       | Campaign sync/output directory           |
| `--out DIR`         | `utils/fuzz/stored_corpus`  | Stored corpus output (uploaded/reused)   |
| `--crashes-out DIR` | `utils/fuzz/stored_crashes` | Minimized crashes output (uploaded)      |
| `--jobs N`          | `nproc`                     | Parallelism (dedup hashing + `cmin` shards) |
| `--json`            | off                         | Emit JSON instead of a table             |

The corpus pipeline:

1. **Content-dedup** every instance's `queue/`. AFL syncs byte-identical copies of
   each discovery across all instances, so this collapses huge redundancy. Hashing is
   batched and parallelized across `--jobs` workers (a per-file `sha256sum` loop spawns
   millions of subprocesses on a real campaign — the dominant cost), and reads the
   queues in place rather than copying them first. This only speeds up the `cmin`
   passes (fewer inputs to execute) — it does not change their result.
2. **Minimize independently with each harness, then union.** Each harness carries a
   *different* instrumentation bitmap (`deser`/conformance is denylisted out of
   `verify`/`compute`), so a single `afl-cmin` would preserve only one of the three
   coverages. Minimizing per-harness and unioning preserves all three.

   `afl-cmin`'s own `-T` parallelism needs a file-input (`@@`) target, but the harnesses
   read stdin (the `afl` crate's `fuzz!` only does shmem/stdin), so we parallelize
   ourselves: each harness's inputs are sharded into up-to-`--jobs` dirs and one
   single-task `afl-cmin` runs per shard concurrently (each fed via stdin, with
   `RAYON_NUM_THREADS=1` for deterministic coverage), then the shard outputs are unioned.

   We also set `AFL_NO_FORKSRV=1` for the `cmin` passes. The `afl` crate uses a *deferred*
   fork server, which under `afl-showmap` (what `cmin` drives) fails to deliver the testcase
   — every input traces identically and `cmin` keeps nothing. A fresh `exec` per input
   delivers stdin correctly; it reloads the keys each exec (~0.3 s), which the sharded
   parallelism hides.
   Sharding is coverage-lossless (every shard preserves its own coverage) but not globally
   minimal — a representative may recur across shards. That's an accepted trade for the
   parallel speedup; the stored corpus stays well below the deduped input either way.
3. **Content-dedup the union** (an input selected by two harnesses appears twice) →
   the stored corpus.
4. Run **`fuzz-stats`** over it.

The crash pipeline runs alongside, **per harness** (mapped by instance-name prefix,
`deser_*` → `harness-deser`, …): content-dedup that harness's `crashes/` → sharded
`afl-cmin -C` (keep crashing inputs, minimize by crash coverage) → count. A crash
reproduces only on the harness that produced it, so each is minimized with its own
binary. The resulting unique-crash count is a coverage proxy for distinct bugs (not
exact bug dedup — see "Future improvements" for stack-based triage). Minimized crashes
are written per-harness under `--crashes-out` for upload/triage. If `cmin` unexpectedly
keeps nothing despite real crash inputs, it falls back to the content-unique set so the
count is never silently under-reported to 0. Hangs are ignored.

A crash count is reported but does **not** fail the run — crashes are expected
findings. `fuzz-stats` exiting nonzero (a panic on a *corpus* input) does fail it,
since the stored corpus is meant to be crash-free.

`fuzz-stats` is a plain (non-AFL) binary — build it with `cargo build`, never
`cargo afl build`. It runs each input through deserialization, then (if conformant)
the verify and compute branches independently, and tallies a histogram:

```
corpus: 1234 inputs (stored_corpus)
(counters are independent; an input may fail both verify and compute)
  SafeDeserializationFailed      321 ( 26.0%)
  ZkVerificationFailed           905 ( 73.3%)
  ExpandFailed                    44 (  3.6%)
  ExpanderGetFailed                2 (  0.2%)
  UnsupportedType                  9 (  0.7%)
  ExecSuccess                      8 (  0.6%)
  panicked                         0 (  0.0%)
```

The counters are **independent**, not a partition: a single input that fails both
verify and compute increments two buckets, so they need not sum to the input count.
`ExecSuccess` is counted only when deserialization, verification, *and* computation
all succeed. `fuzz-stats` exits nonzero if any input panics — the stored corpus is
expected to be crash-free, so a panic here is a regression.

With `--json`, `stats.sh` wraps the `fuzz-stats` histogram together with the crash
counts into one object (the shape CI parses for the Slack report):

```json
{
  "corpus": {"total": 1234, "safe_deserialization_failed": 321, "...": "..."},
  "crashes": {"total": 2, "deser": 1, "verify": 0, "compute": 1}
}
```

**Reading the numbers.** These describe the *stored (coverage-minimized) corpus*, not
the fuzzer's input stream — the per-bucket *proportions* reflect the shape of the
coverage frontier, so don't read "26% deser-fail" as a campaign-health figure. The
meaningful campaign signals are the corpus **size** (`total` — it grows as new
coverage is found) and the **absolute counts** reaching deep stages
(`expand`/compute/`ExecSuccess`). For cross-campaign trends to be comparable, keep the
minimization method fixed.

### Corpus reuse

The corpus grows incrementally across campaigns. Reuse the stored corpus from
`stats.sh` (written to `--out`, default `utils/fuzz/stored_corpus`) as the seed
for the next run:

```bash
./run.sh --corpus-dir stored_corpus
```

**Important:** auxiliary data (keys, CRS, public key) and corpus must always come
from the same generation. Never mix a corpus produced with one set of keys with
different auxiliary data — deserialization will reject every input.
