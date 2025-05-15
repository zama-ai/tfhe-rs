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

/// Implement FromString trait to enable parsing from CLI
impl std::str::FromStr for VarMode {
    type Err = ParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "n" | "nat" | "native" => Ok(VarMode::Native),
            "h" | "half" => Ok(VarMode::Half),
            "b" | "bool" => Ok(VarMode::Bool),
            _ => Err(ParsingError::InvalidArg(format!("Invalid VarMode: {}", s))),
        }
    }
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

/// Implement FromString trait to enable parsing from CLI
impl std::str::FromStr for IOpProto {
    type Err = ParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref PROTO_ARG_RE: regex::Regex =
                regex::Regex::new(r"<(?<dst>[\w\s,]+)>::<(?<src>[\w\s,]*)><(?<imm>\d+)>")
                    .expect("Invalid regex");
        }
        if let Some(caps) = PROTO_ARG_RE.captures(s) {
            let dst = if let Some(dst_raw) = caps.name("dst") {
                dst_raw
                    .as_str()
                    .split(',')
                    .map(|x| x.trim().parse())
                    .collect::<Result<Vec<VarMode>, ParsingError>>()
            } else {
                Err(ParsingError::Unmatch(
                    "Invalid IOpProto: Missing dst field (e.g. <Native, Bool>".to_string(),
                ))
            }?;

            let src = if let Some(src_raw) = caps.name("src") {
                src_raw
                    .as_str()
                    .split(',')
                    .map(|x| x.trim().parse())
                    .collect::<Result<Vec<VarMode>, ParsingError>>()
            } else {
                Err(ParsingError::Unmatch(
                    "Invalid IOpProto: Missing src field (e.g. <Native, Half, Bool, ...>"
                        .to_string(),
                ))
            }?;
            let imm = if let Some(imm_raw) = caps.name("imm") {
                imm_raw
                    .as_str()
                    .parse::<usize>()
                    .map_err(|err| ParsingError::InvalidArg(err.to_string()))
            } else {
                Err(ParsingError::Unmatch(
                    "Invalid IOpProto: Missing imm field (e.g. <2>".to_string(),
                ))
            }?;

            Ok(IOpProto { dst, src, imm })
        } else {
            Err(ParsingError::Unmatch(format!(
                "Invalid IOpProto format {s}"
            )))
        }
    }
}

// Define some common iop format
pub const IOP_CT_F_CT: ConstIOpProto<1, 1> = ConstIOpProto {
    dst: [VarMode::Native; 1],
    src: [VarMode::Native; 1],
    imm: 0,
};
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
    [IOP_CT_F_2CT -> "ADD", opcode::ADD],
    [IOP_CT_F_2CT -> "SUB", opcode::SUB],
    [IOP_CT_F_2CT -> "MUL", opcode::MUL],
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
    [IOP_CT_F_CT -> "MEMCPY", opcode::MEMCPY],
);
