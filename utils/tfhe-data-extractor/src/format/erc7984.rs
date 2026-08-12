//! The `transfer implementation × metric` table of the ERC7984 benchmarks.

use benchmark_spec::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};
use benchmark_spec::{BenchCrate, BenchmarkMetric, HlapiBench, TfheLayer};

use super::{Cells, GridSpec, Table, build_grid, parse_rows, readable_value};
use crate::db::BenchRow;

const ROW_HEADER: &str = "Transfer implementation";

/// Column headers, spelled as published.
const COLUMNS: &[(&str, BenchmarkMetric)] = &[
    ("Latency", BenchmarkMetric::Latency),
    ("Throughput", BenchmarkMetric::Throughput),
];

/// Rows in publication order. HPU publishes a different set (`hpu_optim`,
/// `hpu_simd`) that is not covered here.
const ROWS: &[TransferFlavor] = &[
    TransferFlavor::Whitepaper,
    TransferFlavor::NoCmux,
    TransferFlavor::Overflow,
];

/// Builds the ERC7984 transfer table.
///
/// A flavour with no result at all is still printed, as two `N/A` cells: the
/// table exists to compare the three against each other, so a missing one is
/// the finding.
pub fn table(rows: &[BenchRow]) -> Table {
    let mut cells: Cells<(TransferFlavor, BenchmarkMetric)> = Cells::new();
    let (parsed, unparsed) = parse_rows(rows);

    for (id, row) in parsed {
        let BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Erc7984(Erc7984::Transfer(flavor)))) =
            id.spec.bench_crate()
        else {
            continue;
        };
        // Only benchmarked on 64-bit ciphertexts, so flavour and metric are
        // the whole key.
        cells.insert(
            (flavor, id.spec.metric()),
            readable_value(id.spec.metric(), row.value),
            || format!("{flavor}::{:?}", id.spec.metric()),
        );
    }

    let (grid, empty_rows) = build_grid(
        GridSpec {
            row_header: ROW_HEADER,
            rows: ROWS
                .iter()
                .map(|flavor| (flavor.to_string(), *flavor))
                .collect(),
            columns: COLUMNS,
            drop_empty_rows: false,
        },
        |flavor, metric| cells.get(&(*flavor, *metric)).cloned(),
    );

    Table {
        grid,
        unparsed,
        empty_rows,
        conflicts: cells.conflicts(),
    }
}
