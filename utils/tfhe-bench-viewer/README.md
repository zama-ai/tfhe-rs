# tfhe-bench-viewer

A local explorer for the benchmark results: what ran, on what, and how it moved.

```sh
cd utils/tfhe-bench-viewer
DATA_EXTRACTOR_DATABASE_HOST=… DATA_EXTRACTOR_DATABASE_USER=… \
DATA_EXTRACTOR_DATABASE_PASSWORD=… cargo run --release

# or, with the extractor's own TOML file
cargo run --release -- path/to/config.toml

# or with no database at all, from a snapshot someone shared: drop the
# .data.json on the window.
```

## In a browser

The same window runs in a canvas:

```sh
trunk serve            # or `trunk build --release` for a static bundle
```

It cannot fetch. A page speaks HTTP, WebSocket and WebRTC, never a raw TCP
socket, and PostgreSQL speaks its own protocol over TCP; reaching the database
from there would take an HTTP service in front of it, which is a deployment and
an authentication problem rather than a missing library. So the web build reads
snapshots: drop a `.data.json` or a `.view.json` on the page and everything else
behaves as it does natively, export apart.

That split is the point rather than a concession: the binary holds the
credentials and produces snapshots, the page reads them. Nobody needs database
access to look at the numbers.

The database half is left out of that build entirely, through
`[target.'cfg(not(target_arch = "wasm32"))'.dependencies]`: sqlx needs a socket
and tokio's multi-threaded runtime needs threads, neither of which exists there.
`data/browser.rs` stands in for it, and says so in the status line.

## How it works

One fetch, on startup and on the `Fetch` button: every result inserted in the
last N days on `main`, across the whole fleet, anchored on the `tfhe::%` and
`zk::%` id prefixes. Nothing narrower is asked of SQL. Everything after that is
local, so changing a series costs nothing.

**Time is the X axis.** A series is one benchmark followed across the window,
which is what makes a regression visible. Everything that used to be an axis is
now a filter.

The **browse line** walks the tree with one menu per level, each listing only
what the fetch holds under the levels above it. A level's entries are of two
kinds and behave differently on purpose: a branch navigates and closes the menu,
a benchmark is a checkbox that leaves it open, with its point count beside it.
Plotting `add` and `mul` is two ticks in one menu rather than two round trips
through it. Unticking takes the series back out.

A row's path stays re-pointable: clicking it opens its **neighbours**, flat, so
swapping one operation for the next is a single click rather than a walk back
down from the root. The rest of the tree sits one entry lower, under
`elsewhere`. The dimensions the row carries are kept across the move, and fall
back on their own where the new path does not have them.

A row then narrows that series down, one dimension at a time, on the same rule:

```
backend → metric → machine → bits → params → variant
```

A level with a single option is written out as plain text rather than a dropdown
nobody would open. A pick that stops existing falls back to the first available
value instead of emptying the plot. So a selection that plots nothing is not
reachable, and no two runs are ever silently averaged into one curve.

`+` on a row copies it and switches to another backend the data has, which is
the CPU/GPU overlay in one click. `Clear all` drops every series. `Log scale`
switches both plots between a log and a linear Y axis.

Two plots, latency and throughput, because nanoseconds and operations per second
do not share an axis.

## What leaves the window

All four actions are named after the `file` field, so one stem drives them all.

| Action | File | Holds |
|---|---|---|
| Save / Load data | `<stem>.data.json` | the whole fetch, to hand to someone with no database access |
| Drop a file | either of the above | read by extension, the only way in on the web |
| Save / Load view | `<stem>.view.json` | the series and their settings, not the numbers |
| Export SVG | `<stem>-latency.svg`, `<stem>-throughput.svg` | one file per plot that has something in it |

A snapshot weighs what a week of history weighs, megabytes rather than
kilobytes; a view is a handful of lines and stays readable. Loading a view whose
paths are not in the current data is not an error: those rows say so and the
others plot.

The export goes through the same layout code as the window, so the two cannot
drift. It carries its own light background and its own legend, since the table
it reads from on screen does not travel with it.

## How the code is laid out

Five modules, layered, each depending only on the ones below it:

```
main.rs      the entry point, and nothing else
app/         the window: toolbar, files, browse line, series table, unparsed list
chart/       one layout, two ways of writing it down
series.rs    what a curve is, and how it narrows down
data/        what was fetched, and how
catalogue.rs the fetched paths as a tree; pure data, no widgets
```

`app/` holds one file per panel, each taking the whole `App`: every panel reads
the fetch and writes the series list, so splitting the state would only move the
coupling around. What they share sits in `app/widgets.rs`.

`chart/` is split along the line that matters: `mod.rs` decides where everything
goes and talks to a `Canvas`, `screen.rs` and `svg.rs` implement that canvas.
Adding a third output is implementing one trait, and no layout moves.

## Where the numbers come from

`data/`, and only from the database. It reuses `tfhe-data-extractor`:
`DbConfig` for the credentials, `FetchQuery` for the filters,
`fetch_bench_history` for the query, and `benchmark_spec`'s `MeasuredId` to
parse each stored id back into a path, a backend and a metric. Nothing here
spells a segment by hand, and no value is computed.

Only `_mean` rows are kept; the standard deviations are dropped.

Ids the grammar does not parse are counted in the toolbar and listed verbatim
behind that count, each with what the parser said about it. That list is the
measure of what the spec has yet to cover, so it is worth reading rather than
counting.

**They are plottable too.** A failed parse loses the name, not the value, so
`+` on any of those rows adds it as a series under its stored name. Such a
series is keyed on the whole id, so nothing can share its curve; it names no
backend, and which of the two plots it belongs in is a declaration rather than a
reading, which both the dropdown (`latency?`) and the curve label say out loud.

## What it needed from the two crates it sits on

- `tfhe-data-extractor` was bin-only. It now has a `lib.rs`; the binary is
  unchanged.
- `db.rs` grew `fetch_bench_history`, which is `fetch_bench_rows` without the
  `DISTINCT ON` and with the insertion time, the parameter alias and no "latest
  value only" rule. The table queries are untouched.
- `benchmark_spec` grew a `BenchmarkSpec::backend()` getter. The field was there
  with no accessor, and it is what sorts a stored row by backend from its id
  rather than from the `backend` column, which has drifted.

## What it is not

Not a table generator, not a regression check, and pinned to `main`: the branch
and the database name are constants at the top of `data/fetch.rs`.

Series are capped at 8: past that a categorical palette stops being readable,
and the answer is faceting, not more hues.
