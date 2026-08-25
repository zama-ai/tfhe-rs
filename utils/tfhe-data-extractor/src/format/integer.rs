//! The `operation × ciphertext size` table of the integer layer.

use benchmark_spec::{
    Backend, BenchPath, IntegerBench, IntegerOp, IntegerOpBySign, OperandType, TfheLayer,
};

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

// Spelled once so the six catalogues below cannot drift apart.
const NEGATION: &str = "Negation (-)";
const ADD_SUB: &str = "Add / Sub (+,-)";
const MUL: &str = "Mul (x)";
const EQUALITY: &str = "Equal / Not Equal (eq, ne)";
const COMPARISONS: &str = "Comparisons (ge, gt, le, lt)";
const MAX_MIN: &str = "Max / Min (max, min)";
const BITWISE: &str = "Bitwise operations (&, |, ^)";
const DIV_REM: &str = "Div / Rem  (/, %)";
const DIV: &str = "Div  (/)";
const REM: &str = "Rem  (%)";
const SHIFTS: &str = "Left / Right Shifts (<<, >>)";
const ROTATIONS: &str = "Left / Right Rotations (left_rotate, right_rotate)";
const LEADING_TRAILING: &str = "Leading / Trailing zeros/ones";
const LOG2: &str = "Log2";
const SELECT: &str = "Select";

/// Rows in publication order. A label may name several operations while only
/// one is benchmarked: `Add / Sub` is measured on the addition alone.
const CPU_CIPHERTEXT_ROWS: &[(&str, IntegerOp)] = &[
    (NEGATION, IntegerOp::NegParallelized),
    (ADD_SUB, IntegerOp::AddParallelized),
    (MUL, IntegerOp::MulParallelized),
    (EQUALITY, IntegerOp::EqParallelized),
    (COMPARISONS, IntegerOp::GtParallelized),
    (MAX_MIN, IntegerOp::MaxParallelized),
    (BITWISE, IntegerOp::BitandParallelized),
    (DIV_REM, IntegerOp::DivRemParallelized),
    (SHIFTS, IntegerOp::LeftShiftParallelized),
    (ROTATIONS, IntegerOp::RotateLeftParallelized),
    (LEADING_TRAILING, IntegerOp::LeadingZerosParallelized),
    (LOG2, IntegerOp::Ilog2Parallelized),
    (SELECT, IntegerOp::IfThenElseParallelized),
];

/// Same, for `scalar` operations, with `Div / Rem` split in two.
///
/// Negation, leading and trailing zeros/ones, and log2 are missing because they
/// are unary: there is no scalar form to measure. `Select` is missing for a
/// different reason, being available on scalars but not benchmarked, so its row
/// belongs here again the day it is.
const CPU_SCALAR_ROWS: &[(&str, IntegerOp)] = &[
    (ADD_SUB, IntegerOp::ScalarAddParallelized),
    (MUL, IntegerOp::ScalarMulParallelized),
    (EQUALITY, IntegerOp::ScalarEqParallelized),
    (COMPARISONS, IntegerOp::ScalarGtParallelized),
    (MAX_MIN, IntegerOp::ScalarMaxParallelized),
    (BITWISE, IntegerOp::ScalarBitandParallelized),
    (DIV, IntegerOp::ScalarDivParallelized),
    (REM, IntegerOp::ScalarRemParallelized),
    (SHIFTS, IntegerOp::ScalarLeftShiftParallelized),
    (ROTATIONS, IntegerOp::ScalarRotateLeftParallelized),
];

/// The Cuda benches call the unparallelized names: the parallelism is the
/// device's, not rayon's.
const GPU_CIPHERTEXT_ROWS: &[(&str, IntegerOp)] = &[
    (NEGATION, IntegerOp::Neg),
    (ADD_SUB, IntegerOp::Add),
    (MUL, IntegerOp::Mul),
    (EQUALITY, IntegerOp::Eq),
    (COMPARISONS, IntegerOp::Gt),
    (MAX_MIN, IntegerOp::Max),
    (BITWISE, IntegerOp::Bitand),
    (DIV_REM, IntegerOp::DivRem),
    (SHIFTS, IntegerOp::LeftShift),
    (ROTATIONS, IntegerOp::RotateLeft),
    (LEADING_TRAILING, IntegerOp::LeadingZeros),
    (LOG2, IntegerOp::Ilog2),
    (SELECT, IntegerOp::IfThenElse),
];

const GPU_SCALAR_ROWS: &[(&str, IntegerOp)] = &[
    (ADD_SUB, IntegerOp::ScalarAdd),
    (MUL, IntegerOp::ScalarMul),
    (EQUALITY, IntegerOp::ScalarEq),
    (COMPARISONS, IntegerOp::ScalarGt),
    (MAX_MIN, IntegerOp::ScalarMax),
    (BITWISE, IntegerOp::ScalarBitand),
    (DIV, IntegerOp::ScalarDiv),
    (REM, IntegerOp::ScalarRem),
    (SHIFTS, IntegerOp::ScalarLeftShift),
    (ROTATIONS, IntegerOp::ScalarRotateLeft),
];

/// Two rows are looser than their label: negation does not exist on the device
/// yet and is measured on the subtraction, and only the division is measured
/// behind `Div / Rem`. Both are how the published tables already read.
const HPU_CIPHERTEXT_ROWS: &[(&str, IntegerOp)] = &[
    (NEGATION, IntegerOp::Sub),
    (ADD_SUB, IntegerOp::Add),
    (MUL, IntegerOp::Mul),
    (EQUALITY, IntegerOp::CmpEq),
    (COMPARISONS, IntegerOp::CmpGt),
    (MAX_MIN, IntegerOp::Max),
    (BITWISE, IntegerOp::BwAnd),
    (DIV_REM, IntegerOp::Div),
    (SHIFTS, IntegerOp::ShiftL),
    (ROTATIONS, IntegerOp::RotL),
    (LEADING_TRAILING, IntegerOp::Lead0),
    (LOG2, IntegerOp::Ilog2),
    (SELECT, IntegerOp::IfThenElse),
];

/// Shorter than the others: the spec has no scalar spelling for equality,
/// comparison, bitwise, leading zeros, log2 or select on this backend.
const HPU_SCALAR_ROWS: &[(&str, IntegerOp)] = &[
    (NEGATION, IntegerOp::ScalarSub),
    (ADD_SUB, IntegerOp::ScalarAdds),
    (MUL, IntegerOp::ScalarMuls),
    (MAX_MIN, IntegerOp::ScalarMax),
    (DIV_REM, IntegerOp::ScalarDivs),
    (SHIFTS, IntegerOp::ScalarShiftsL),
    (ROTATIONS, IntegerOp::ScalarRotsL),
];

fn rows(backend: Backend, operand: OperandType) -> &'static [(&'static str, IntegerOp)] {
    match (backend, operand) {
        (Backend::Cpu, OperandType::CipherText) => CPU_CIPHERTEXT_ROWS,
        (Backend::Cpu, OperandType::PlainText) => CPU_SCALAR_ROWS,
        (Backend::Cuda, OperandType::CipherText) => GPU_CIPHERTEXT_ROWS,
        (Backend::Cuda, OperandType::PlainText) => GPU_SCALAR_ROWS,
        (Backend::Hpu, OperandType::CipherText) => HPU_CIPHERTEXT_ROWS,
        (Backend::Hpu, OperandType::PlainText) => HPU_SCALAR_ROWS,
    }
}

/// Builds the integer table for one backend and operand type.
///
/// The backend comes from the caller: a parsed id does not carry it, and every
/// row of a run shares the one the query pinned.
pub fn table(measured: &[Measured], backend: Backend, operand: OperandType) -> Table {
    let table_rows = rows(backend, operand);
    let mut cells: Cells<(IntegerOp, i64)> = Cells::new();

    for m in measured {
        // Unsigned operations only. The catalogue alone tells the ciphertext
        // and scalar tables apart: scalar benches are their own operations
        // (`scalar_add_parallelized`), and `operand_type` is never set on an
        // integer bench, so it cannot discriminate.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_never_names_two_operations_within_one_catalogue() {
        for backend in [Backend::Cpu, Backend::Cuda, Backend::Hpu] {
            for operand in [OperandType::CipherText, OperandType::PlainText] {
                let catalogue = rows(backend, operand);
                for (index, (label, _)) in catalogue.iter().enumerate() {
                    assert!(
                        !catalogue[..index].iter().any(|(seen, _)| seen == label),
                        "{backend:?}/{operand:?} lists {label:?} twice",
                    );
                }
            }
        }
    }

    /// The scalar catalogues must hold scalar operations, or the `-plaintext`
    /// table silently republishes the ciphertext figures.
    #[test]
    fn scalar_catalogues_only_hold_scalar_operations() {
        for backend in [Backend::Cpu, Backend::Cuda, Backend::Hpu] {
            for (label, op) in rows(backend, OperandType::PlainText) {
                assert!(
                    op.to_string().starts_with("scalar_"),
                    "{backend:?} measures {label:?} from {op}, which is not a scalar operation",
                );
            }
        }
    }
}
