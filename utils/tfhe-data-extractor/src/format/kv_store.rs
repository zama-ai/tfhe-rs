//! One `store size × value precision` table per KV-store operation.
//!
//! The store size is `num_elements` and the value type sits in `type_name` as
//! `key_<K>::value_<V>`.

use benchmark_spec::tfhe::hlapi::kv_store::KvStoreOp;
use benchmark_spec::{BenchPath, HlapiBench, TfheLayer};

use super::{Cells, GridSpec, Measured, Table, build_grid, readable_value};

const ROW_HEADER: &str = r"Store size \ Value";

const COLUMNS: &[(&str, u32)] = &[
    ("FheUint8", 8),
    ("FheUint16", 16),
    ("FheUint32", 32),
    ("FheUint64", 64),
    ("FheUint128", 128),
];

const ROWS: &[u32] = &[2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

/// Operations published, in order. The spec knows three more (`contains_*`)
/// that the documentation does not show.
const OPERATIONS: &[KvStoreOp] = &[KvStoreOp::Get, KvStoreOp::Update, KvStoreOp::Map];

/// Builds one table per operation, suffixed with the operation name.
pub fn tables(measured: &[Measured]) -> Vec<(String, Table)> {
    OPERATIONS
        .iter()
        .map(|op| {
            let mut cells: Cells<(u32, u32)> = Cells::new();

            for m in measured {
                let BenchPath::Tfhe(TfheLayer::Hlapi(HlapiBench::KvStore(row_op))) =
                    m.spec.bench_path()
                else {
                    continue;
                };
                if row_op != *op {
                    continue;
                }
                let (Some(store_size), Some(value_bits)) = (
                    m.spec.num_elements(),
                    m.spec.type_name().and_then(value_precision),
                ) else {
                    continue;
                };

                cells.insert(
                    (store_size, value_bits),
                    readable_value(m.spec.metric(), m.value),
                );
            }

            let (grid, empty_rows) = build_grid(
                GridSpec {
                    row_header: ROW_HEADER,
                    rows: ROWS.iter().map(|size| (size.to_string(), *size)).collect(),
                    columns: COLUMNS,
                    drop_empty_rows: false,
                },
                |size, bits| cells.get(&(*size, *bits)).cloned(),
            );

            let table = Table {
                grid,
                empty_rows,
                conflicts: cells
                    .conflicts()
                    .map(|c| {
                        let (size, bits) = c.key;
                        format!(
                            "{size} elements::FheUint{bits} ({} / {})",
                            c.kept, c.dropped
                        )
                    })
                    .collect(),
            };

            (format!("-{op}"), table)
        })
        .collect()
}

/// Pulls the value precision out of a `key_<K>::value_<V>` type tag. Anchored
/// on the `value_` marker so a differently spelled key type cannot shift it.
fn value_precision(type_name: &str) -> Option<u32> {
    type_name
        .split("::")
        .find_map(|part| part.strip_prefix("value_"))
        .and_then(|ty| ty.strip_prefix("FheUint"))
        .and_then(|bits| bits.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_precision_is_anchored() {
        assert_eq!(value_precision("key_FheUint32::value_FheUint64"), Some(64));
        // A key type that happens to look like a value must not be picked up.
        assert_eq!(value_precision("key_FheUint8"), None);
        assert_eq!(value_precision("FheUint64"), None);
    }
}
