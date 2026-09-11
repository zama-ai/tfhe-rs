//! The `input size × operation` tables of the proven compact list benches.
//!
//! Two tables per run, one per [`ComputeLoad`]. The parameter set decides which
//! side of the proof carries the work, and a proof-heavy run is not comparable
//! with a verify-heavy one, so the two never share a grid.

use benchmark_spec::{BenchPath, ComputeLoad, IntegerBench, TfheLayer, TypeTag, ZkPkeBench};

use super::{Cells, GridSpec, Measured, Table, build_grid, readable_value};

/// Only the 2048-bit CRS is published. The other sizes are benchmarked to track
/// the cost of the CRS itself, not to be read next to it.
const CRS_BITS: u32 = 2048;

/// Columns in publication order. The spec knows three more (`only_expand`,
/// `crs`, `proven_list`) that the documentation does not show.
const COLUMNS: &[(&str, ZkPkeBench)] = &[
    ("Proving", ZkPkeBench::Proof),
    ("Verifying", ZkPkeBench::Verify),
    ("Verify + expand", ZkPkeBench::VerifyAndExpand),
];

/// Rows in publication order: how many bits the proven list packs, labelled as
/// the `FheUint64` count that represents.
const ROWS: &[(&str, u32)] = &[
    ("1xFheUint64 (64 bits)", 64),
    ("4xFheUint64 (256 bits)", 256),
    ("32xFheUint64 (2048 bits)", 2048),
];

const LOADS: &[ComputeLoad] = &[ComputeLoad::Proof, ComputeLoad::Verify];

/// The header names the trade-off the parameter set makes, which is the whole
/// reason the two tables are kept apart.
fn row_header(load: ComputeLoad) -> &'static str {
    match load {
        ComputeLoad::Proof => "Inputs (slow proof / fast verify)",
        ComputeLoad::Verify => "Inputs (fast proof / slow verify)",
    }
}

/// File suffix, spelled as the previous tool wrote it so the published asset
/// names do not move.
fn suffix(load: ComputeLoad) -> &'static str {
    match load {
        ComputeLoad::Proof => "slow_proof_and_fast_verify",
        ComputeLoad::Verify => "fast_proof_and_slow_verify",
    }
}

/// Builds one table per compute load, suffixed with the trade-off it describes.
pub fn tables(measured: &[Measured]) -> Vec<(String, Table)> {
    LOADS
        .iter()
        .map(|load| {
            let mut cells: Cells<(u32, ZkPkeBench)> = Cells::new();

            for m in measured {
                let BenchPath::Tfhe(TfheLayer::Integer(IntegerBench::Zk(op))) = m.spec.bench_path()
                else {
                    continue;
                };
                let Some(TypeTag::ZkPke(config)) = m.spec.type_tag() else {
                    continue;
                };
                // The CRS is measured per CRS size alone, so it carries neither
                // a packed size nor a load and drops out on its tag.
                let (Some(bits_packed), Some(measured_load)) =
                    (config.bits_packed, config.compute_load)
                else {
                    continue;
                };
                if measured_load != *load || config.crs_bits != CRS_BITS {
                    continue;
                }
                // `proven_list` and `only_expand` are tagged like the published
                // operations, so they have to be turned away by name. Letting
                // them in would cost nothing at lookup, which never asks for
                // them, but they would contest cells and be reported for it.
                if !COLUMNS.iter().any(|(_, column)| *column == op) {
                    continue;
                }

                // The zk scheme is not a column: the documentation publishes one
                // table per compute load, whatever scheme produced it. Two
                // schemes in the same window therefore contest a cell, which is
                // reported rather than silently resolved.
                cells.insert((bits_packed, op), readable_value(m.spec.metric(), m.value));
            }

            let (grid, empty_rows) = build_grid(
                GridSpec {
                    row_header: row_header(*load),
                    rows: ROWS
                        .iter()
                        .map(|(label, bits)| (label.to_string(), *bits))
                        .collect(),
                    columns: COLUMNS
                        .iter()
                        .map(|(name, key)| (name.to_string(), *key))
                        .collect(),
                    // The three sizes exist to be read against each other, so a
                    // size with no result is the finding, not noise.
                    drop_empty_rows: false,
                },
                |bits, op| cells.get(&(*bits, *op)).cloned(),
            );

            let table = Table {
                grid,
                empty_rows,
                conflicts: cells
                    .conflicts()
                    .map(|c| {
                        let (bits, op) = c.key;
                        format!("{bits}_bits_packed::{op} ({} / {})", c.kept, c.dropped)
                    })
                    .collect(),
            };

            (format!("-{}", suffix(*load)), table)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use benchmark_spec::MeasuredId;

    use super::*;

    fn measured(id: &str, value: f64) -> Measured {
        let parsed: MeasuredId = id.parse().unwrap_or_else(|e| panic!("parse {id:?}: {e:?}"));
        Measured {
            spec: parsed.spec,
            bit_size: 64,
            value,
        }
    }

    /// Starts from stored ids rather than hand-built specs, so the test covers
    /// the parsing too: a tag the grammar stops rendering this way would fail
    /// here rather than silently empty the published table.
    #[test]
    fn loads_are_split_and_unpublished_rows_dropped() {
        let rows = vec![
            measured(
                "tfhe::integer::zk::proof::PARAM_MESSAGE_2_CARRY_2\
                 ::64_bits_packed::2048_bits_crs::compute_load_proof::zk_v2_mean_avx512",
                2_310_000.0,
            ),
            measured(
                "tfhe::integer::zk::verify::PARAM_MESSAGE_2_CARRY_2\
                 ::64_bits_packed::2048_bits_crs::compute_load_verify::zk_v2_mean_avx512",
                1_230_000.0,
            ),
            // Another CRS size: benchmarked, not published.
            measured(
                "tfhe::integer::zk::proof::PARAM_MESSAGE_2_CARRY_2\
                 ::64_bits_packed::4096_bits_crs::compute_load_proof::zk_v2_mean_avx512",
                9_990_000.0,
            ),
            // The CRS itself carries no load and no packed size.
            measured(
                "tfhe::integer::zk::crs::key_size::PARAM_MESSAGE_2_CARRY_2\
                 ::2048_bits_crs::zk_v2_mean_avx512",
                4096.0,
            ),
        ];

        let tables = tables(&rows);
        assert_eq!(tables.len(), 2);

        let (proof_suffix, proof) = &tables[0];
        assert_eq!(proof_suffix, "-slow_proof_and_fast_verify");
        assert_eq!(proof.grid.row_header, "Inputs (slow proof / fast verify)");
        // Proving measured, the other two columns not.
        assert_eq!(
            proof.grid.rows[0].cells,
            vec![Some("2.31 ms".to_string()), None, None],
        );
        // The 4096-bit CRS row did not leak into the 64-bit line.
        assert_eq!(proof.grid.rows[0].label, "1xFheUint64 (64 bits)");

        let (verify_suffix, verify) = &tables[1];
        assert_eq!(verify_suffix, "-fast_proof_and_slow_verify");
        assert_eq!(
            verify.grid.rows[0].cells,
            vec![None, Some("1.23 ms".to_string()), None],
        );

        // Both tables keep the three published sizes, filled with N/A by the
        // renderers rather than dropped.
        assert_eq!(proof.grid.rows.len(), 3);
        assert_eq!(verify.grid.rows.len(), 3);
        assert!(proof.conflicts.is_empty());
    }
}
