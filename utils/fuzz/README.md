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

| Harness           | What it does                                                            |
|-------------------|-------------------------------------------------------------------------|
| `harness-deser`   | `safe_deserialize_conformant` only                                      |
| `harness-verify`  | Deserialize, then verify the ZK proof                                   |
| `harness-compute` | Deserialize, `expand_without_verification`, then add/mul/sub + compress |

`harness-compute` skips ZK verification intentionally: randomly producing a valid
proof is astronomically unlikely, so verification would reject every input before
reaching the code we actually want to test.

## Prerequisites

Install `cargo-afl`:
```
make install_cargo_afl
```

And then configure your system (**warning**: requires sudo access):
```
make fuzz_system_config
```

## Quick start

### Make commands
The easiest is to use the provided make commands from the root of the repo:

1. Create the initial corpus and build the harnesses
```bash
make fuzz_precampaign
```

2. Run the campaign
```
make fuzz_run
```

3. Minimize the corpus and generate a report
```
make fuzz_postcampaign
```

### Bash scripts
For more control over the campaign, you can manually run the scripts instead:

```bash
cd utils/fuzz

# Build harnesses + generate initial corpus and auxiliary data (keys, CRS)
./build.sh --corpusgen

# Rebuild harnesses without regenerating corpus/keys:
./build.sh

# Run a short test campaign (1 hour, number of instances based on available cores)
./run.sh --duration-seconds 3600

# Increase the number of fuzzer targeting deserialization
./run.sh --deser-weight 5

# Only use 16 cores
./run.sh --total-cores 16

# After a campaign: save crashes, minimize the corpus, report outcome statistics
./postcampaign.sh
```

## Build script (`build.sh`)

```
./build.sh [--corpusgen]
```

- Builds all three harnesses with AFL instrumentation (`cargo afl build --release`).
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

| Option                  | Default               | Description                                          |
|-------------------------|-----------------------|------------------------------------------------------|
| `--corpus-dir DIR`      | `utils/fuzz/corpus`   | Initial corpus directory                             |
| `--sync-dir DIR`        | `utils/fuzz/sync_dir` | AFL output / sync directory                          |
| `--duration-seconds N`  | 14400 (4h)            | How long to run before stopping                      |
| `--total-cores N`       | `nproc`               | Override the auto-detected core count                |
| `--deser-weight N`      | 1                     | Weight of `harness-deser` in the secondary split     |
| `--verify-weight N`     | 3                     | Weight of `harness-verify` in the secondary split    |
| `--compute-weight N`    | 8                     | Weight of `harness-compute` in the secondary split   |
| `--deser-secondary N`   | (derived)             | Pin `harness-deser` secondaries (overrides ratio)    |
| `--verify-secondary N`  | (derived)             | Pin `harness-verify` secondaries (overrides ratio)   |
| `--compute-secondary N` | (derived)             | Pin `harness-compute` secondaries (overrides ratio)  |

This launches one master (`-M`) per harness plus the derived secondaries (`-S`),
all writing to the same `--sync-dir`. Press `Ctrl-C` to stop early; the script
sends `SIGINT` to all instances on exit.

### Sizing

Each AFL instance uses one core (see rationale below), scaling is done by spawning more instances.
The number of instances is based on the number of available cores (`nproc`):
3 cores go to the masters and `nproc - 3` secondaries are distributed across harnesses by weight.
The default ratio `deser : verify : compute` is `1 : 3 : 8`. This reflects per-exec cost: compute is the
slowest harness and gets the largest share. The floor-division remainder is added to compute.

| `nproc` | deser (1 M + sec) | verify (1 M + sec) | compute (1 M + sec) | Total |
|--------:|-------------------|--------------------|---------------------|------:|
|       4 | 1 + 0             | 1 + 0              | 1 + 1               |     4 |
|       8 | 1 + 0             | 1 + 1              | 1 + 4               |     8 |
|      16 | 1 + 1             | 1 + 3              | 1 + 9               |    16 |
|      32 | 1 + 2             | 1 + 7              | 1 + 20              |    32 |
|      64 | 1 + 5             | 1 + 15             | 1 + 41              |    64 |
|     192 | 1 + 15            | 1 + 47             | 1 + 127             |   192 |

To pin a different layout (e.g. lots of `harness-deser` for early-stage byte-pattern
hunting), pass any of `--deser-secondary` / `--verify-secondary` / `--compute-secondary`.
The others stay derived from the ratio.

After the first campaign, check `afl-whatsup` per harness: if deser shows no new
paths for 12h, lower `--deser-weight`; if compute is still finding paths near the
end of the run, raise `--compute-weight`.

At 192-core scale, AFL's sync mechanism (each instance periodically scans all other
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

A crash in `harness-deser` means deserialization or conformance panicked (a
violation of invariant 1). A crash in `harness-verify` or `harness-compute` means
post-conformance code panicked (a violation of invariant 2).

### Postcampaign processing (`postcampaign.sh` / `fuzz-stats`)

`postcampaign.sh` saves crashes, builds the **stored corpus** (reused between campaigns), and
reports statistics on it:

```bash
./postcampaign.sh            # default
./postcampaign.sh --jobs 32  # cmin parallelism
```

| Option              | Default                     | Description                              |
|---------------------|-----------------------------|------------------------------------------|
| `--sync-dir DIR`    | `utils/fuzz/sync_dir`       | Campaign sync/output directory           |
| `--out DIR`         | `utils/fuzz/stored_corpus`  | Stored corpus output (uploaded/reused)   |
| `--crashes-out DIR` | `utils/fuzz/stored_crashes` | Minimized crashes output (uploaded)      |
| `--jobs N`          | `nproc`                     | Parallelism (dedup hashing + `cmin` shards) |

The histogram + crashes summary + freshness are written to `summary.md` (and echoed to stdout)
as the final report.

The following steps are run by `poscampaign.sh`:

1. **Crashes** (per harness, mapped by instance-name prefix): first deduplicate the content of this
   harness' `crashes/` folder by file hashes, then run `afl-cmin -C` on the result, and count.
   Minimized crashes are written per-harness under `--crashes-out` for upload/triage. Crashes are
   processed first because
   they are findings we never want to lose.
2. **Corpus**: content-dedup (hash) every instance's `queue/` folder (AFL syncs byte-identical copies
   of each discovery across all instances, so there is a huge redundancy). Then minimize
   independently with each harness and union the results.
   Content-dedup the union (otherwise an input selected by two harnesses appears twice). This produces
   the stored corpus.
3. **Freshness**: read each instance's `fuzzer_stats` and aggregate per harness.
4. **`fuzz-stats`**: histogram over the stored corpus.

`fuzz-stats` is a plain (non-AFL) binary. It runs each input through deserialization, then (if
conformant) the verify and compute branches independently, and tallies a histogram:

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

`summary.md` also displays per harness statistics:

```
Crashes: 2 (deser: 1, verify: 0, compute: 1)

Instances (master + secondaries):
  deser: 3
  verify: 8
  compute: 21

Executions:
  deser: 2,3M
  verify: 1,2M
  compute: 13,3M

Time since last new path found:
  deser: 2s
  verify: 0s
  compute: 0s
```

Use these to rebalance the next campaign: a harness whose `since_last_find` approaches
the campaign duration is plateauing and can give up cores; one still finding paths near
campaign end deserves more (the heuristic in [Sizing](#sizing)).

**Reading the numbers.** These describe the *coverage-minimized corpus*, not
the fuzzer's input stream. The per-bucket *proportions* reflect the shape of the
coverage frontier.

### Corpus reuse

The corpus grows incrementally across campaigns. Reuse the stored corpus from
`postcampaign.sh` (written to `--out`, default `utils/fuzz/stored_corpus`) as the seed
for the next run:

```bash
./run.sh --corpus-dir stored_corpus
```

**Important:** auxiliary data (server key, public key, CRS) and corpus must always come
from the same generation. Never mix a corpus produced with one set of keys with
different auxiliary data (verification will reject every input).
