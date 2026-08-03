use strum::Display;

use crate::traits::SpecLeafNode;

/// Shortint server-key operations (unary, binary and scalar variants).
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ShortintOp {
    // Unary ops
    UncheckedNeg,
    Neg,
    // Binary ops
    UncheckedAdd,
    UncheckedSub,
    UncheckedMulLsb,
    UncheckedMulMsb,
    UncheckedDiv,
    SmartBitand,
    SmartBitor,
    SmartBitxor,
    SmartAdd,
    SmartSub,
    SmartMulLsb,
    Bitand,
    Bitor,
    Bitxor,
    Add,
    Sub,
    Mul,
    Div,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
    Equal,
    NotEqual,
    UncheckedGreater,
    UncheckedLess,
    UncheckedEqual,
    // Scalar ops
    UncheckedScalarAdd,
    UncheckedScalarSub,
    UncheckedScalarMul,
    UncheckedScalarLeftShift,
    UncheckedScalarRightShift,
    UncheckedScalarDiv,
    UncheckedScalarMod,
    ScalarAdd,
    ScalarSub,
    ScalarMul,
    ScalarLeftShift,
    ScalarRightShift,
    ScalarDiv,
    ScalarMod,
    ScalarGreater,
    ScalarGreaterOrEqual,
    ScalarLess,
    ScalarLessOrEqual,
    ScalarEqual,
    ScalarNotEqual,
}

impl SpecLeafNode for ShortintOp {}
