# tfhe-data-extractor

Reads benchmark results back out of the Zama PostgreSQL instance and renders
them as CSV, Markdown or SVG tables. It is the tool behind the performance
tables published in the documentation and behind the regression reports.

`--help` lists every flag. This file covers how to get access, how to run the
tool once, and how it works internally.

## Access

There is no local database to set up. The tool always reads the remote Zama
PostgreSQL instance, so a run from your laptop and a run from CI look at the
same data. The only statement it ever issues is a `SELECT`, so a local run
cannot alter anything.

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

If you do not have those credentials, ask TFHE-rs team. Note that `--dry-run` needs none of them: it prints the
SQL `LIKE` patterns a selection resolves to and exits without opening a
connection, which is the cheapest way to check a command line, with or without
access.

## Usage

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

The `--generate-*` flags are mutually exclusive and the CSV is written alongside
whichever one is picked, so there is no `--generate-csv`. With none of them,
nothing is written and the first ten rows are printed instead.

Which tables get built depends on the layer and the subset:

| Layer     | Subset     | Tables                                               |
| --------- | ---------- | ---------------------------------------------------- |
| `integer` | `all`      | `-ciphertext` and `-plaintext`                       |
| `hlapi`   | `erc7984`  | `-ciphertext`                                        |
| `hlapi`   | `kv_store` | `-ciphertext<op>`, one per key/value store operation |

### Regression profiles

Profiles come from `ci/regression.toml`, selected with `--regression-profiles`
plus `--regression-selected-profile` (the two go together). Their entries are
spec path fragments, not bare operation names: under `target.hlapi-dex`,
`swap_request::whitepaper` is a valid entry and `swap_request` alone is not.
`cargo test -p tfhe-data-extractor` checks that every default profile still
resolves against the spec.

## How it works

The database stores one row per benchmark, and the whole structured identity of
a result (layer, operation, parameter set, precision, metric) lives inside its
`name` column as a rendered id. A run is therefore four steps:

1. **Build patterns.** The selection becomes SQL `LIKE` patterns over those ids,
   either one broad pattern for the whole `--tfhe-rs-layer`, or one exact
   pattern per bench path when a regression profile drives the selection.
2. **Query.** One read-only query, narrowed further by hardware, backend,
   branch, metric, PBS kind and either a commit or a date window.
3. **Parse.** Every id is parsed back into its parts with `benchmark_spec`.
   Rows whose id does not follow the spec grammar are counted and reported on
   stderr rather than dropped in silence.
4. **Render.** The parsed rows are laid out into a table, then serialized.
