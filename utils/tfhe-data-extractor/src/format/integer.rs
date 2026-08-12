//! The `operation × ciphertext size` table of the integer layer.

use benchmark_spec::{
    BenchCrate, IntegerBench, IntegerOp, IntegerOpBySign, OperandType, TfheLayer,
};

use super::{Cells, GridSpec, Table, build_grid, parse_rows, readable_value};
use crate::db::BenchRow;

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

/// Same, for `scalar` operations. `Div / Rem` is split in two, and the rows
/// whose operation takes a single ciphertext are gone: negation, leading and
/// trailing zeros/ones, and log2 have no scalar form. Neither has `select`,
/// which is never benchmarked with a scalar operand.
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
pub fn table(rows: &[BenchRow], operand: OperandType) -> Table {
    let table_rows = match operand {
        OperandType::CipherText => CIPHERTEXT_ROWS,
        OperandType::PlainText => SCALAR_ROWS,
    };

    let mut cells: Cells<(IntegerOp, i64)> = Cells::new();
    let (parsed, unparsed) = parse_rows(rows);

    for (id, row) in parsed {
        if id.spec.operand_type().is_scalar() != operand.is_scalar() {
            continue;
        }
        // Unsigned operations only.
        let BenchCrate::Tfhe(TfheLayer::Integer(IntegerBench::Ops(IntegerOpBySign::Unsigned(op)))) =
            id.spec.bench_crate()
        else {
            continue;
        };
        cells.insert(
            (op, row.bit_size),
            readable_value(id.spec.metric(), row.value),
            || format!("{op}::{} bits", row.bit_size),
        );
    }

    let (grid, empty_rows) = build_grid(
        GridSpec {
            row_header: ROW_HEADER,
            rows: table_rows
                .iter()
                .map(|(label, op)| (label.to_string(), *op))
                .collect(),
            columns: COLUMNS,
            // An operation with no result at all is left out: the row list is a
            // catalogue, and benchmarking a subset of it is routine.
            drop_empty_rows: true,
        },
        |op, size| cells.get(&(*op, *size)).cloned(),
    );

    Table {
        grid,
        unparsed,
        empty_rows,
        conflicts: cells.conflicts(),
    }
}
