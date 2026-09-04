//! The `transfer implementation × metric` table of the ERC7984 benchmarks.

use benchmark_spec::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};
use benchmark_spec::{BenchPath, BenchmarkMetric, HlapiBench, TfheLayer};

use super::{Cells, GridSpec, Measured, Table, build_grid, readable_value};

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
    TransferFlavor::Safe,
];

/// Builds the ERC7984 transfer table.
///
/// A flavour with no result at all is still printed, as two `N/A` cells: the
/// table exists to compare the three against each other, so a missing one is
/// the finding.
pub fn table(measured: &[Measured]) -> Table {
    let mut cells: Cells<(TransferFlavor, BenchmarkMetric)> = Cells::new();

    for m in measured {
        let BenchPath::Tfhe(TfheLayer::Hlapi(HlapiBench::Erc7984(Erc7984::Transfer(flavor)))) =
            m.spec.bench_path()
        else {
            continue;
        };
        // Only benchmarked on 64-bit ciphertexts, so flavour and metric are
        // the whole key.
        cells.insert(
            (flavor, m.spec.metric()),
            readable_value(m.spec.metric(), m.value),
        );
    }

    let (grid, empty_rows) = build_grid(
        GridSpec {
            row_header: ROW_HEADER,
            rows: ROWS
                .iter()
                .map(|flavor| (flavor.to_string(), *flavor))
                .collect(),
            columns: COLUMNS
                .iter()
                .map(|(name, key)| (name.to_string(), *key))
                .collect(),
            drop_empty_rows: false,
        },
        |flavor, metric| cells.get(&(*flavor, *metric)).cloned(),
    );

    Table {
        grid,
        empty_rows,
        conflicts: cells
            .conflicts()
            .map(|c| {
                let (flavor, metric) = c.key;
                format!("{flavor}::{metric:?} ({} / {})", c.kept, c.dropped)
            })
            .collect(),
    }
}
