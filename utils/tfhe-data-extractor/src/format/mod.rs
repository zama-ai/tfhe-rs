//! The published benchmark tables, one module per table.
//!
//! This module holds what all of them need: the [`Table`] result, cell
//! collection, id parsing and value formatting.

pub mod erc7984;
pub mod integer;
pub mod kv_store;
pub mod render;

use std::collections::HashMap;
use std::hash::Hash;

use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, MeasuredId};

use crate::db::BenchRow;

/// A stored result the spec recognised, reduced to what the tables read.
///
/// The statistic and the run variant are left behind: the query pins them
/// through `--name-suffix`, so every row carries the same ones.
pub struct Measured {
    pub spec: BenchmarkSpec,
    pub bit_size: i64,
    pub value: f64,
}

/// A table as data, before serialization. Cell values are already formatted;
/// only the layout is left to the renderer.
///
/// ```text
/// | Operation \ Size | FheUint8 | FheUint16 |   <- row_header, then columns
/// | Add / Sub (+,-)  | 2.31 ms  | N/A       |   <- one Row { label, cells }
/// ```
pub struct Grid {
    /// Header of the first column, the one holding row labels.
    pub row_header: String,
    /// Remaining column headers, in order.
    pub columns: Vec<String>,
    pub rows: Vec<Row>,
}

pub struct Row {
    pub label: String,
    /// One entry per column, `None` when that column was not measured.
    pub cells: Vec<Option<String>>,
}

/// A built table plus what it could not account for.
pub struct Table {
    pub grid: Grid,
    /// Rows with no result at any column. Whether they are printed as `N/A` or
    /// left out is up to each table.
    pub empty_rows: Vec<String>,
    /// Cells several benchmarks competed for with different values, meaning the
    /// selection is under-specified. Already formatted by the table they belong
    /// to, which is the only one that knows how to name its own cells.
    pub conflicts: Vec<String>,
}

impl Table {
    /// Reports on stderr what the table could not account for.
    pub fn report(&self) {
        if !self.empty_rows.is_empty() {
            eprintln!(
                "warning: {} rows without any result: {}",
                self.empty_rows.len(),
                self.empty_rows.join(", "),
            );
        }
        if !self.conflicts.is_empty() {
            eprintln!(
                "warning: {} cell(s) matched by several benchmarks, first kept. \
                 Narrow the selection with --param:",
                self.conflicts.len(),
            );
            for conflict in &self.conflicts {
                eprintln!("  {conflict}");
            }
        }
    }
}

/// One value per cell of a table.
///
/// A second, different value for the same cell means the query did not narrow
/// down to a single benchmark. The first wins, which is deterministic since
/// rows arrive ordered by `test.name`, and the clash is recorded.
struct Cells<K> {
    values: HashMap<K, String>,
    conflicts: Vec<Conflict<K>>,
}

/// A contested cell: its key, the value kept and the one dropped.
///
/// The key is kept rather than formatted on the spot, so that a table sharing a
/// [`Cells`] with its siblings can pick out the clashes that are its own, and
/// name them the way it names its cells.
struct Conflict<K> {
    key: K,
    kept: String,
    dropped: String,
}

impl<K: Eq + Hash> Cells<K> {
    fn new() -> Self {
        Self {
            values: HashMap::new(),
            conflicts: Vec::new(),
        }
    }

    fn insert(&mut self, key: K, value: String) {
        match self.values.get(&key) {
            Some(kept) if *kept != value => self.conflicts.push(Conflict {
                key,
                kept: kept.clone(),
                dropped: value,
            }),
            Some(_) => {}
            None => {
                self.values.insert(key, value);
            }
        }
    }

    fn get(&self, key: &K) -> Option<&String> {
        self.values.get(key)
    }

    /// Contested cells in the order they turned up, which follows `test.name`.
    fn conflicts(&self) -> impl Iterator<Item = &Conflict<K>> {
        self.conflicts.iter()
    }
}

/// A table's layout, declared the same way by every table.
struct GridSpec<'a, R, C> {
    /// Header of the first column, the one holding row labels.
    row_header: &'a str,
    /// Row label and the key it is looked up by, in publication order.
    rows: Vec<(String, R)>,
    /// Column header and the key it is looked up by, in publication order.
    columns: Vec<(String, C)>,
    /// Leave out a row with no result at any column, instead of filling it
    /// with `N/A`.
    drop_empty_rows: bool,
}

/// Fills a layout from `lookup`, returning the grid and the labels of the rows
/// that had no result at any column.
fn build_grid<R, C>(
    spec: GridSpec<'_, R, C>,
    lookup: impl Fn(&R, &C) -> Option<String>,
) -> (Grid, Vec<String>) {
    let mut grid_rows = Vec::with_capacity(spec.rows.len());
    let mut empty_rows = Vec::new();

    for (label, row_key) in spec.rows {
        let cells: Vec<Option<String>> = spec
            .columns
            .iter()
            .map(|(_, col_key)| lookup(&row_key, col_key))
            .collect();

        if cells.iter().all(Option::is_none) {
            empty_rows.push(label.clone());
            if spec.drop_empty_rows {
                continue;
            }
        }

        grid_rows.push(Row { label, cells });
    }

    let grid = Grid {
        row_header: spec.row_header.to_string(),
        columns: spec.columns.into_iter().map(|(name, _)| name).collect(),
        rows: grid_rows,
    };

    (grid, empty_rows)
}

/// Parses each stored name against the spec, returning the rows that parsed and
/// how many did not.
pub fn parse_rows(rows: &[BenchRow]) -> (Vec<Measured>, usize) {
    let mut parsed = Vec::with_capacity(rows.len());
    let mut unparsed = 0;

    for row in rows {
        match row.name.parse::<MeasuredId>() {
            Ok(id) => parsed.push(Measured {
                spec: id.spec,
                bit_size: row.bit_size,
                value: row.value,
            }),
            Err(_) => unparsed += 1,
        }
    }

    (parsed, unparsed)
}

/// Human-readable latency from a nanosecond figure.
fn readable_latency(ns: f64) -> String {
    if ns < 1e3 {
        format!("{ns:.0} ns")
    } else if ns < 1e6 {
        format!("{:.2} us", ns / 1e3)
    } else if ns < 1e9 {
        format!("{:.2} ms", ns / 1e6)
    } else {
        format!("{:.2} s", ns / 1e9)
    }
}

/// Renders a value with the unit implied by its metric.
fn readable_value(metric: BenchmarkMetric, value: f64) -> String {
    match metric {
        BenchmarkMetric::Latency => readable_latency(value),
        BenchmarkMetric::Throughput => format!("{value:.2} elem/s"),
        // Counts and byte sizes are not durations.
        BenchmarkMetric::PbsCount | BenchmarkMetric::KeySize => format!("{value:.0}"),
    }
}
