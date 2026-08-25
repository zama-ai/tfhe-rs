//! The `operation × precision` tables of the core_crypto layer.
//!
//! One table per noise distribution and failure probability: the four
//! combinations are four different parameter sets, and their timings are not
//! comparable.

use benchmark_spec::{BenchPath, CoreCryptoBench, TfheLayer};

use super::{Cells, GridSpec, Measured, Table, build_grid, readable_value};
use crate::params::{NoiseDistribution, PFail, ParamSet};

const ROW_HEADER: &str = r"Operation \ Precision (bits)";

/// Published precisions, as message plus carry bits.
const PRECISIONS: &[u32] = &[2, 4, 6, 8];

const P_FAILS: &[PFail] = &[PFail::TwoMinus64, PFail::TwoMinus128];

const NOISES: &[NoiseDistribution] = &[NoiseDistribution::Gaussian, NoiseDistribution::TUniform];

/// Rows in publication order.
const ROWS: &[Row] = &[Row::Pbs, Row::MultiBitPbs, Row::KsPbs, Row::MultiBitKsPbs];

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
enum Row {
    Pbs,
    MultiBitPbs,
    KsPbs,
    MultiBitKsPbs,
}

impl Row {
    fn label(self) -> &'static str {
        match self {
            Self::Pbs => "PBS",
            Self::MultiBitPbs => "MB-PBS",
            Self::KsPbs => "KS - PBS",
            Self::MultiBitKsPbs => "KS - MB-PBS",
        }
    }

    /// The row an operation belongs to, `None` for the ones the documentation
    /// does not publish.
    ///
    /// A deterministic multi-bit run shares the row of the ordinary one: the
    /// benches pick one spelling or the other, never both.
    fn of(bench: CoreCryptoBench) -> Option<Self> {
        match bench {
            CoreCryptoBench::PbsMemOptimized => Some(Self::Pbs),
            CoreCryptoBench::MultiBitPbs | CoreCryptoBench::MultiBitDeterministicPbs => {
                Some(Self::MultiBitPbs)
            }
            CoreCryptoBench::KsPbs => Some(Self::KsPbs),
            CoreCryptoBench::MultiBitKsPbs | CoreCryptoBench::MultiBitDeterministicKsPbs => {
                Some(Self::MultiBitKsPbs)
            }
            _ => None,
        }
    }

    fn is_multi_bit(self) -> bool {
        matches!(self, Self::MultiBitPbs | Self::MultiBitKsPbs)
    }
}

/// Builds one table per parameter set family, suffixed with the family it
/// describes: `-tuniform-2m64`.
///
/// `grouping_factor` is the one `--grouping-factor` asked for. Multi-bit results
/// measured on any other are left out, and all of them are when nothing was
/// asked for, since there would be no telling which the table shows.
pub fn tables(measured: &[Measured], grouping_factor: Option<u32>) -> Vec<(String, Table)> {
    let mut tables = Vec::with_capacity(P_FAILS.len() * NOISES.len());

    for p_fail in P_FAILS {
        for noise in NOISES {
            let mut cells: Cells<(Row, u32)> = Cells::new();

            for m in measured {
                let BenchPath::Tfhe(TfheLayer::CoreCrypto(bench)) = m.spec.bench_crate() else {
                    continue;
                };
                let Some(row) = Row::of(bench) else {
                    continue;
                };
                let Some(params) = ParamSet::parse(m.spec.param_name()) else {
                    continue;
                };
                if !params.is_compute_set() || params.p_fail != *p_fail || params.noise != *noise {
                    continue;
                }
                // A multi-bit operation runs on a multi-bit set and a classical
                // one on a classical set, so an operation and a set that
                // disagree are two halves of different runs.
                if row.is_multi_bit() != params.grouping_factor.is_some() {
                    continue;
                }
                if row.is_multi_bit() && params.grouping_factor != grouping_factor {
                    continue;
                }

                cells.insert(
                    (row, params.message_bits * 2),
                    readable_value(m.spec.metric(), m.value),
                );
            }

            let (grid, empty_rows) = build_grid(
                GridSpec {
                    row_header: ROW_HEADER,
                    rows: ROWS
                        .iter()
                        .map(|row| (row.label().to_string(), *row))
                        .collect(),
                    columns: PRECISIONS
                        .iter()
                        .map(|precision| (precision.to_string(), *precision))
                        .collect(),
                    // The four rows exist to be read against each other, so a
                    // missing one is the finding.
                    drop_empty_rows: false,
                },
                |row, precision| cells.get(&(*row, *precision)).cloned(),
            );

            let table = Table {
                grid,
                empty_rows,
                conflicts: cells
                    .conflicts()
                    .map(|c| {
                        let (row, precision) = c.key;
                        format!(
                            "{}::{precision} bits ({} / {})",
                            row.label(),
                            c.kept,
                            c.dropped
                        )
                    })
                    .collect(),
            };

            tables.push((format!("-{noise}-{p_fail}"), table));
        }
    }

    tables
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

    fn table<'a>(tables: &'a [(String, Table)], suffix: &str) -> &'a Table {
        &tables
            .iter()
            .find(|(s, _)| s == suffix)
            .unwrap_or_else(|| panic!("no {suffix} table"))
            .1
    }

    /// Starts from stored ids rather than hand-built specs, so the test covers
    /// the parsing too: an alias the benches stop spelling this way would fail
    /// here rather than silently empty the published table.
    #[test]
    fn families_are_split_and_grouping_factors_filtered() {
        let rows = vec![
            measured(
                "tfhe::core_crypto::pbs_mem_optimized\
                 ::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_mean_avx512",
                4_550_000.0,
            ),
            measured(
                "tfhe::core_crypto::ks_pbs\
                 ::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128_mean_avx512",
                5_720_000.0,
            ),
            measured(
                "tfhe::core_crypto::multi_bit_pbs\
                 ::BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2\
                 _KS_PBS_TUNIFORM_2M128_mean_avx512",
                2_550_000.0,
            ),
            // Same operation, another grouping factor: measured, not published.
            measured(
                "tfhe::core_crypto::multi_bit_pbs\
                 ::BENCH_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2\
                 _KS_PBS_TUNIFORM_2M128_mean_avx512",
                9_990_000.0,
            ),
            // The layer query brings back the keyswitch alone, which has no row.
            measured(
                "tfhe::core_crypto::keyswitch\
                 ::BENCH_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_mean_avx512",
                1_000_000.0,
            ),
        ];

        let built = tables(&rows, Some(4));
        assert_eq!(built.len(), 4);

        let tuniform = table(&built, "-tuniform-2m128");
        // 4-bit precision, so the second column.
        assert_eq!(
            tuniform.grid.rows[0].cells[1],
            Some("4.55 ms".to_string()),
            "PBS",
        );
        assert_eq!(
            tuniform.grid.rows[1].cells[1],
            Some("2.55 ms".to_string()),
            "MB-PBS",
        );
        // The other grouping factor did not contest the cell it shares.
        assert!(tuniform.conflicts.is_empty());

        let gaussian = table(&built, "-gaussian-2m128");
        assert_eq!(
            gaussian.grid.rows[2].cells[1],
            Some("5.72 ms".to_string()),
            "KS - PBS",
        );
        // Every table keeps the four published rows, filled with N/A by the
        // renderers rather than dropped.
        assert_eq!(table(&built, "-tuniform-2m64").grid.rows.len(), 4);
    }

    /// Without one, no multi-bit row can be attributed to a grouping factor.
    #[test]
    fn no_requested_grouping_factor_leaves_the_multi_bit_rows_empty() {
        let rows = vec![measured(
            "tfhe::core_crypto::multi_bit_ks_pbs\
             ::BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_mean_avx512",
            3_720_000.0,
        )];

        let built = tables(&rows, None);
        let tuniform = table(&built, "-tuniform-2m128");

        assert!(tuniform.grid.rows[3].cells.iter().all(Option::is_none));
    }
}
