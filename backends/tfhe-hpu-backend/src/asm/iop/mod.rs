//!
//! IOp definition

mod field;
pub use field::{HexParsingError, IOp, IOpcode, Immediat, Operand, OperandKind};
mod fmt;
pub use fmt::{IOpRepr, IOpWordRepr};
mod iop_macro;
pub mod opcode;

mod arg;
pub use arg::{AsmIOpcode, ParsingError};

// TODO find a proper way to let this runtime properties
pub const MSG_WIDTH: u8 = 2;
pub const CARRY_WIDTH: u8 = 2;

/// Enum used to define a variable size relative to current integer width
#[derive(Debug, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum VarMode {
    Native,
    Half,
    Bool,
}

/// Struct used to depict IOp prototype with clarity
#[derive(Debug, Clone)]
pub struct ConstIOpProto<const D: usize, const S: usize> {
    pub dst: [VarMode; D],
    pub src: [VarMode; S],
    pub imm: usize,
}

/// Dynamic type to erase const template
/// TODO moved from runtime check to compile time one
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IOpProto {
    pub dst: Vec<VarMode>,
    pub src: Vec<VarMode>,
    pub imm: usize,
}

impl<const D: usize, const S: usize> From<ConstIOpProto<D, S>> for IOpProto {
    fn from(const_val: ConstIOpProto<D, S>) -> Self {
        Self {
            dst: const_val.dst.into(),
            src: const_val.src.into(),
            imm: const_val.imm,
        }
    }
}

// Define some common iop format
pub const IOP_CT_F_2CT: ConstIOpProto<1, 2> = ConstIOpProto {
    dst: [VarMode::Native; 1],
    src: [VarMode::Native; 2],
    imm: 0,
};
pub const IOP_CT_F_2CT_BOOL: ConstIOpProto<1, 3> = ConstIOpProto {
    dst: [VarMode::Native; 1],
    src: [VarMode::Native, VarMode::Native, VarMode::Bool],
    imm: 0,
};
pub const IOP_CT_F_CT_BOOL: ConstIOpProto<1, 2> = ConstIOpProto {
    dst: [VarMode::Native; 1],
    src: [VarMode::Native, VarMode::Bool],
    imm: 0,
};

pub const IOP_CT_F_CT_SCALAR: ConstIOpProto<1, 1> = ConstIOpProto {
    dst: [VarMode::Native; 1],
    src: [VarMode::Native; 1],
    imm: 1,
};

pub const IOP_CMP: ConstIOpProto<1, 2> = ConstIOpProto {
    dst: [VarMode::Bool; 1],
    src: [VarMode::Native; 2],
    imm: 0,
};

pub const IOP_2CT_F_3CT: ConstIOpProto<2, 3> = ConstIOpProto {
    dst: [VarMode::Native; 2],
    src: [VarMode::Native; 3],
    imm: 0,
};

use crate::iop;
use arg::IOpFormat;
use lazy_static::lazy_static;
use std::collections::HashMap;
iop!(
    [IOP_CT_F_CT_SCALAR -> "ADDS", opcode::ADDS],
    [IOP_CT_F_CT_SCALAR -> "SUBS", opcode::SUBS],
    [IOP_CT_F_CT_SCALAR -> "SSUB", opcode::SSUB],
    [IOP_CT_F_CT_SCALAR -> "MULS", opcode::MULS],
    // [IOP_CT_F_CT_SCALAR -> "MULSF", opcode::MULSF],
    [IOP_CT_F_2CT -> "ADD", opcode::ADD],
    [IOP_CT_F_2CT -> "ADDK", opcode::ADDK],
    [IOP_CT_F_2CT -> "SUB", opcode::SUB],
    [IOP_CT_F_2CT -> "SUBK", opcode::SUBK],
    [IOP_CT_F_2CT -> "MUL", opcode::MUL],
    // [IOP_CT_F_2CT -> "MULF", opcode::MULF],
    [IOP_CT_F_2CT -> "BW_AND", opcode::BW_AND],
    [IOP_CT_F_2CT -> "BW_OR", opcode::BW_OR],
    [IOP_CT_F_2CT -> "BW_XOR", opcode::BW_XOR],
    [IOP_CMP -> "CMP_GT", opcode::CMP_GT],
    [IOP_CMP -> "CMP_GTE", opcode::CMP_GTE],
    [IOP_CMP -> "CMP_LT", opcode::CMP_LT],
    [IOP_CMP -> "CMP_LTE", opcode::CMP_LTE],
    [IOP_CMP -> "CMP_EQ", opcode::CMP_EQ],
    [IOP_CMP -> "CMP_NEQ", opcode::CMP_NEQ],
    [IOP_CT_F_CT_BOOL -> "IF_THEN_ZERO", opcode::IF_THEN_ZERO],
    [IOP_CT_F_2CT_BOOL -> "IF_THEN_ELSE", opcode::IF_THEN_ELSE],
    [IOP_2CT_F_3CT -> "ERC_20", opcode::ERC_20],
);
