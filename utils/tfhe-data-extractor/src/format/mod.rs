//! The published benchmark tables, one module per table.
//!
//! This module holds what all of them need: the [`Table`] result, cell
//! collection, id parsing and value formatting.

pub mod core_crypto;
pub mod erc7984;
pub mod integer;
pub mod kv_store;
pub mod render;
pub mod zk;

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

/// Renders a figure with three significant digits: `231`, `45.6`, `2.31`.
///
/// At or above 100 the decimals disappear entirely; below it, trailing zeros go
/// but one decimal always survives, so `1.0` does not become `1`. Hence the
/// explicit precision rather than `Display`, which renders `1.0_f64` as `1`.
fn three_significant_digits(value: f64) -> String {
    // Zero shares the branch for want of a logarithm.
    if value >= 100.0 || value == 0.0 {
        return format!("{value:.0}");
    }

    let decimals = (2 - value.abs().log10().floor() as i32).max(0) as usize;
    let rendered = format!("{value:.decimals$}");

    match rendered.trim_end_matches('0') {
        trimmed if trimmed.ends_with('.') => format!("{trimmed}0"),
        trimmed => trimmed.to_string(),
    }
}

/// Human-readable latency from a nanosecond figure.
///
/// The thresholds are exclusive, so exactly 1e6 ns reads as `1000 us`, not
/// `1.0 ms`: promoting it would lose the third significant digit.
fn readable_latency(ns: f64) -> String {
    let (scaled, unit) = if ns > 1e9 {
        (ns / 1e9, "s")
    } else if ns > 1e6 {
        (ns / 1e6, "ms")
    } else if ns > 1e3 {
        (ns / 1e3, "us")
    } else {
        (ns, "ns")
    };

    format!("{} {unit}", three_significant_digits(scaled))
}

/// Human-readable throughput from a figure in elements per second.
fn readable_throughput(per_second: f64) -> String {
    let (scaled, unit) = if per_second > 1e6 {
        (per_second / 1e6, "M.ops/s")
    } else if per_second > 1e3 {
        (per_second / 1e3, "k.ops/s")
    } else {
        (per_second, "ops/s")
    };

    format!("{} {unit}", three_significant_digits(scaled))
}

/// Renders a value with the unit implied by its metric.
fn readable_value(metric: BenchmarkMetric, value: f64) -> String {
    match metric {
        BenchmarkMetric::Latency => readable_latency(value),
        BenchmarkMetric::Throughput => readable_throughput(value),
        // Counts and byte sizes are not durations.
        BenchmarkMetric::PbsCount | BenchmarkMetric::KeySize => format!("{value:.0}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{readable_latency, readable_throughput};

    /// Expectations taken from the previous Python implementation, which wrote
    /// the tables published today.
    #[test]
    fn latency_matches_the_published_spelling() {
        for (ns, expected) in [
            (0.5, "0.5 ns"),
            (12.0, "12.0 ns"),
            (850.0, "850 ns"),
            (999.0, "999 ns"),
            (1_000.0, "1000 ns"),
            (1_000.5, "1.0 us"),
            (2_310.0, "2.31 us"),
            (45_600.0, "45.6 us"),
            (100_000.0, "100 us"),
            (231_000.0, "231 us"),
            (999_999.0, "1000 us"),
            (1_000_000.0, "1000 us"),
            (1_000_001.0, "1.0 ms"),
            (2_300_000.0, "2.3 ms"),
            (2_310_000.0, "2.31 ms"),
            (12_345_678.0, "12.3 ms"),
            (999_999_999.0, "1000 ms"),
            (1_000_000_000.0, "1000 ms"),
            (2_500_000_000.0, "2.5 s"),
        ] {
            assert_eq!(readable_latency(ns), expected, "for {ns} ns");
        }
    }

    #[test]
    fn throughput_matches_the_published_spelling() {
        for (per_second, expected) in [
            (0.5, "0.5 ops/s"),
            (12.0, "12.0 ops/s"),
            (999.0, "999 ops/s"),
            (1_000.0, "1000 ops/s"),
            (1_001.0, "1.0 k.ops/s"),
            (1_234.0, "1.23 k.ops/s"),
            (45_600.0, "45.6 k.ops/s"),
            (231_000.0, "231 k.ops/s"),
            (1_000_000.0, "1000 k.ops/s"),
            (1_000_001.0, "1.0 M.ops/s"),
            (2_310_000.0, "2.31 M.ops/s"),
            (12_345_678.0, "12.3 M.ops/s"),
        ] {
            assert_eq!(
                readable_throughput(per_second),
                expected,
                "for {per_second}"
            );
        }
    }

    /// The previous tool raised a domain error on a stored zero.
    #[test]
    fn zero_does_not_panic() {
        assert_eq!(readable_latency(0.0), "0 ns");
        assert_eq!(readable_throughput(0.0), "0 ops/s");
    }
}
