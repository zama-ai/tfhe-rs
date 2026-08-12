//! One `store size × value precision` table per KV-store operation.
//!
//! The store size is `num_elements`, and the value type comes from the
//! [`TypeTag::KeyValue`] the bench builds.

use benchmark_spec::tfhe::hlapi::kv_store::KvStoreOp;
use benchmark_spec::{BenchPath, FheType, HlapiBench, TfheLayer, TypeTag};

use super::{Cells, GridSpec, Measured, Table, build_grid, readable_value};

const ROW_HEADER: &str = r"Store size \ Value";

/// Published value types. Their header is their own `Display`.
const COLUMNS: &[FheType] = &[
    FheType::Uint(8),
    FheType::Uint(16),
    FheType::Uint(32),
    FheType::Uint(64),
    FheType::Uint(128),
];

const ROWS: &[usize] = &[2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

/// Operations published, in order. The spec knows three more (`contains_*`)
/// that the documentation does not show.
const OPERATIONS: &[KvStoreOp] = &[KvStoreOp::Get, KvStoreOp::Update, KvStoreOp::Map];

/// Builds one table per operation, suffixed with the operation name.
pub fn tables(measured: &[Measured]) -> Vec<(String, Table)> {
    OPERATIONS
        .iter()
        .map(|op| {
            let mut cells: Cells<(usize, FheType)> = Cells::new();

            for m in measured {
                let BenchPath::Tfhe(TfheLayer::Hlapi(HlapiBench::KvStore(row_op))) =
                    m.spec.bench_crate()
                else {
                    continue;
                };
                if row_op != *op {
                    continue;
                }
                // Only the value type keys a column; a key type the columns do
                // not cover drops the measurement.
                let (Some(store_size), Some(TypeTag::KeyValue { value, .. })) =
                    (m.spec.num_elements(), m.spec.type_tag())
                else {
                    continue;
                };

                cells.insert(
                    (store_size, value),
                    readable_value(m.spec.metric(), m.value),
                );
            }

            let (grid, empty_rows) = build_grid(
                GridSpec {
                    row_header: ROW_HEADER,
                    rows: ROWS.iter().map(|size| (size.to_string(), *size)).collect(),
                    columns: COLUMNS.iter().map(|ty| (ty.to_string(), *ty)).collect(),
                    drop_empty_rows: false,
                },
                |size, ty| cells.get(&(*size, *ty)).cloned(),
            );

            let table = Table {
                grid,
                empty_rows,
                conflicts: cells
                    .conflicts()
                    .map(|c| {
                        let (size, ty) = c.key;
                        format!("{size} elements::{ty} ({} / {})", c.kept, c.dropped)
                    })
                    .collect(),
            };

            (format!("-{op}"), table)
        })
        .collect()
}
