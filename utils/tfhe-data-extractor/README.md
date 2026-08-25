# tfhe-data-extractor

Reads benchmark results back out of the Zama PostgreSQL instance and renders
them as CSV, Markdown or SVG tables. It is the tool behind the performance
tables published in the documentation and behind the regression reports.

`--help` lists every flag. This file covers how the tool works, what it needs to
connect, and how to run it once.

## How it works

The database stores one row per benchmark, and the whole structured identity of
a result (layer, operation, parameter set, precision, metric) lives inside its
`name` column as a rendered id. A run is therefore four steps:

1. **Build patterns.** The selection becomes SQL `LIKE` patterns over those ids,
   either one broad pattern for the whole `--tfhe-rs-layer`, or one exact
   pattern per bench path when a regression profile drives the selection.
   `--dry-run` prints those patterns and exits without opening a connection.
2. **Query.** One read-only query, narrowed further by hardware, backend,
   branch, metric, PBS kind and either a commit or a date window.
3. **Parse.** Every id is parsed back into its parts with `benchmark_spec`.
   Rows whose id does not follow the spec grammar are counted and reported on
   stderr rather than dropped in silence.
4. **Render.** The parsed rows are laid out into a table, then serialized. The
   `--generate-*` flags are mutually exclusive and the CSV is written alongside
   whichever one is picked, so there is no `--generate-csv`. With none of them,
   nothing is written and the first ten rows are printed instead.

Which table gets built depends on the layer and the subset:

| Layer         | Subset     | Tables                                                    |
| ------------- | ---------- | --------------------------------------------------------- |
| `integer`     | `all`      | `-ciphertext` and `-plaintext`                            |
| `integer`     | `zk`       | `-ciphertext<load>`, one per compute load                 |
| `core_crypto` | `all`      | `-<noise>-<p_fail>`, one per parameter set family         |
| `hlapi`       | `erc7984`  | `-ciphertext`                                             |
| `hlapi`       | `kv_store` | `-ciphertext<op>`, one per key/value store operation      |

A subset also narrows the query: `--bench-subset zk` looks for
`tfhe::integer::zk::%` rather than fetching the whole layer and filtering
afterwards.

The `core_crypto` tables need `--grouping-factor`: several are benchmarked in
the same window, and without one the multi-bit rows come out empty.

Profiles come from `ci/regression.toml`, selected with `--regression-profiles`
plus `--regression-selected-profile` (the two go together). Their entries are
spec path fragments, not bare operation names: under `target.hlapi-dex`,
`swap_request::whitepaper` is a valid entry and `swap_request` alone is not.
`cargo test -p tfhe-data-extractor` checks that every default profile still
resolves against the spec.

## Configuration

Three environment variables carry the credentials:

```shell
export DATA_EXTRACTOR_DATABASE_HOST=...
export DATA_EXTRACTOR_DATABASE_USER=...
export DATA_EXTRACTOR_DATABASE_PASSWORD=...
```

They are enough on their own, and this is how CI passes its secrets. The same
three values can also live in a TOML file given with `--config-file`: copy
`config.example.toml` to `config.toml` and fill it in. When both are present,
the environment wins.

The database name is part of neither: it is the `--database` flag, defaulting to
`tfhe_rs`.

## Example

Integer tables for the last 30 days, as SVG plus the CSV that comes with it:

```shell
cargo run -p tfhe-data-extractor -- bench-results \
  --generate-svg \
  --tfhe-rs-layer integer \
  --hardware hpc8a.96xlarge \
  --branch main
```

The first argument is a path prefix with no extension, so this writes
`bench-results-ciphertext.svg`, `bench-results-plaintext.svg` and the two
matching `.csv` files.
