//! The `operation × ciphertext size` table of the integer layer.

use benchmark_spec::{BenchPath, IntegerBench, IntegerOp, IntegerOpBySign, OperandType, TfheLayer};

use super::{Cells, GridSpec, Measured, Table, build_grid, readable_value};

const ROW_HEADER: &str = r"Operation \ Size";

/// Published precisions. FheUint2, FheUint4 and FheUint256 are benchmarked but
/// not shown.
const COLUMNS: &[(&str, i64)] = &[
    ("FheUint8", 8),
    ("FheUint16", 16),
    ("FheUint32", 32),
    ("FheUint64", 64),
    ("FheUint128", 128),
];

/// Rows in publication order, each a label and the operation it is measured
/// from. A label may name several operations while only one is benchmarked.
const CIPHERTEXT_ROWS: &[(&str, IntegerOp)] = &[
    ("Negation (-)", IntegerOp::NegParallelized),
    ("Add / Sub (+,-)", IntegerOp::AddParallelized),
    ("Mul (x)", IntegerOp::MulParallelized),
    ("Equal / Not Equal (eq, ne)", IntegerOp::EqParallelized),
    ("Comparisons (ge, gt, le, lt)", IntegerOp::GtParallelized),
    ("Max / Min (max, min)", IntegerOp::MaxParallelized),
    (
        "Bitwise operations (&, |, ^)",
        IntegerOp::BitandParallelized,
    ),
    ("Div / Rem  (/, %)", IntegerOp::DivRemParallelized),
    (
        "Left / Right Shifts (<<, >>)",
        IntegerOp::LeftShiftParallelized,
    ),
    (
        "Left / Right Rotations (left_rotate, right_rotate)",
        IntegerOp::RotateLeftParallelized,
    ),
    (
        "Leading / Trailing zeros/ones",
        IntegerOp::LeadingZerosParallelized,
    ),
    ("Log2", IntegerOp::Ilog2Parallelized),
    ("Select", IntegerOp::IfThenElseParallelized),
];

/// Same, for `scalar` operations, with `Div / Rem` split in two.
///
/// Negation, leading and trailing zeros/ones, and log2 are missing because they
/// are unary: there is no scalar form to measure. `Select` is missing for a
/// different reason, being available on scalars but not benchmarked, so its row
/// belongs here again the day it is.
const SCALAR_ROWS: &[(&str, IntegerOp)] = &[
    ("Add / Sub (+,-)", IntegerOp::AddParallelized),
    ("Mul (x)", IntegerOp::MulParallelized),
    ("Equal / Not Equal (eq, ne)", IntegerOp::EqParallelized),
    ("Comparisons (ge, gt, le, lt)", IntegerOp::GtParallelized),
    ("Max / Min (max, min)", IntegerOp::MaxParallelized),
    (
        "Bitwise operations (&, |, ^)",
        IntegerOp::BitandParallelized,
    ),
    ("Div  (/)", IntegerOp::DivParallelized),
    ("Rem  (%)", IntegerOp::RemParallelized),
    (
        "Left / Right Shifts (<<, >>)",
        IntegerOp::LeftShiftParallelized,
    ),
    (
        "Left / Right Rotations (left_rotate, right_rotate)",
        IntegerOp::RotateLeftParallelized,
    ),
];

/// Builds the integer table for one operand type.
pub fn table(measured: &[Measured], operand: OperandType) -> Table {
    let table_rows = match operand {
        OperandType::CipherText => CIPHERTEXT_ROWS,
        OperandType::PlainText => SCALAR_ROWS,
    };

    let mut cells: Cells<(IntegerOp, i64)> = Cells::new();

    for m in measured {
        if m.spec.operand_type().is_scalar() != operand.is_scalar() {
            continue;
        }
        // Unsigned operations only.
        let BenchPath::Tfhe(TfheLayer::Integer(IntegerBench::Ops(IntegerOpBySign::Unsigned(op)))) =
            m.spec.bench_crate()
        else {
            continue;
        };
        cells.insert((op, m.bit_size), readable_value(m.spec.metric(), m.value));
    }

    let (grid, empty_rows) = build_grid(
        GridSpec {
            row_header: ROW_HEADER,
            rows: table_rows
                .iter()
                .map(|(label, op)| (label.to_string(), *op))
                .collect(),
            columns: COLUMNS
                .iter()
                .map(|(name, key)| (name.to_string(), *key))
                .collect(),
            // An operation with no result at all is left out: the row list is a
            // catalogue, and benchmarking a subset of it is routine.
            drop_empty_rows: true,
        },
        |op, size| cells.get(&(*op, *size)).cloned(),
    );

    Table {
        grid,
        empty_rows,
        conflicts: cells
            .conflicts()
            .map(|c| {
                let (op, bits) = c.key;
                format!("{op}::{bits} bits ({} / {})", c.kept, c.dropped)
            })
            .collect(),
    }
}
