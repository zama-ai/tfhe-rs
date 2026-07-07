//!
//! IOp definition
use super::dop::MAX_HPU_IN_CLUSTER;
mod field;
pub use field::{HexParsingError, IOp, IOpMapping, IOpcode, Immediate, Operand, OperandKind};
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
    type Err = Box<ParsingError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "n" | "nat" | "native" => Ok(VarMode::Native),
            "h" | "half" => Ok(VarMode::Half),
            "b" | "bool" => Ok(VarMode::Bool),
            _ => Err(Box::new(ParsingError::InvalidArg(format!(
                "Invalid VarMode: {s}"
            )))),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodesMap([u8; MAX_HPU_IN_CLUSTER]);

impl NodesMap {
    // Create a new nodes map based on configuration
    // Extend incomplete map and enforce that request nodes don't be higher than available one
    pub fn new(nodes_cfg: &[u8]) -> Self {
        let max_nodes = *nodes_cfg.iter().max().unwrap_or(&1);
        let mut default = [max_nodes; MAX_HPU_IN_CLUSTER];

        let mut prv_entry = 1;
        for (i, (s, n)) in std::iter::zip(default.iter_mut(), nodes_cfg.iter()).enumerate() {
            *s = if *n > (i + 1) as u8 { prv_entry } else { *n };
            prv_entry = *s;
        }
        Self(default)
    }

    pub fn get_nodes(&self, avail_hpu: u8) -> u8 {
        assert!(
            avail_hpu <= MAX_HPU_IN_CLUSTER as u8,
            "HPU could only gather at most {MAX_HPU_IN_CLUSTER} Hpu per cluster."
        );
        self.0[(avail_hpu - 1) as usize]
    }

    pub fn max_node(&self) -> u8 {
        *self.0.iter().max().unwrap_or(&1)
    }
}

/// Struct used to depict IOp prototype with clarity
#[derive(Debug, Clone)]
pub struct ConstIOpProto<const D: usize, const S: usize> {
    pub used_nodes: NodesMap,
    pub dst: [VarMode; D],
    pub src: [VarMode; S],
    pub imm: usize,
}

/// Dynamic type to erase const template
// TODO moved from runtime check to compile time one
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IOpProto {
    pub used_nodes: NodesMap,
    pub dst: Vec<VarMode>,
    pub src: Vec<VarMode>,
    pub imm: usize,
}

impl<const D: usize, const S: usize> From<ConstIOpProto<D, S>> for IOpProto {
    fn from(const_val: ConstIOpProto<D, S>) -> Self {
        Self {
            used_nodes: const_val.used_nodes,
            dst: const_val.dst.into(),
            src: const_val.src.into(),
            imm: const_val.imm,
        }
    }
}

/// Implement FromString trait to enable parsing from CLI
impl std::str::FromStr for IOpProto {
    type Err = Box<ParsingError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref PROTO_ARG_RE: regex::Regex = regex::Regex::new(
                r"\[(?<nodes>[\d\s,]+)\]<(?<dst>[\w\s,]+)>::<(?<src>[\w\s,]*)><(?<imm>\d+)>"
            )
            .expect("Invalid regex");
        }
        if let Some(caps) = PROTO_ARG_RE.captures(s) {
            let nodes_config = if let Some(nodes_raw) = caps.name("nodes") {
                nodes_raw
                    .as_str()
                    .trim()
                    .split(',')
                    .map(|nodes| nodes.trim().parse::<u8>())
                    .collect::<Result<Vec<_>, std::num::ParseIntError>>()
                    .map_err(|err| Box::new(ParsingError::InvalidArg(err.to_string())))
            } else {
                Err(Box::new(ParsingError::Unmatch(
                    "Invalid IOpProto: Missing nodes field (e.g. [1,2,4]".to_string(),
                )))
            }?;
            let dst = if let Some(dst_raw) = caps.name("dst") {
                dst_raw
                    .as_str()
                    .split(',')
                    .map(|x| x.trim().parse())
                    .collect::<Result<Vec<VarMode>, Box<ParsingError>>>()
            } else {
                Err(Box::new(ParsingError::Unmatch(
                    "Invalid IOpProto: Missing dst field (e.g. <Native, Bool>".to_string(),
                )))
            }?;

            let src = if let Some(src_raw) = caps.name("src") {
                src_raw
                    .as_str()
                    .split(',')
                    .map(|x| x.trim().parse())
                    .collect::<Result<Vec<VarMode>, Box<ParsingError>>>()
            } else {
                Err(Box::new(ParsingError::Unmatch(
                    "Invalid IOpProto: Missing src field (e.g. <Native, Half, Bool, ...>"
                        .to_string(),
                )))
            }?;
            let imm = if let Some(imm_raw) = caps.name("imm") {
                imm_raw
                    .as_str()
                    .parse::<usize>()
                    .map_err(|err| Box::new(ParsingError::InvalidArg(err.to_string())))
            } else {
                Err(Box::new(ParsingError::Unmatch(
                    "Invalid IOpProto: Missing imm field (e.g. <2>".to_string(),
                )))
            }?;

            Ok(IOpProto {
                used_nodes: NodesMap::new(&nodes_config),
                dst,
                src,
                imm,
            })
        } else {
            Err(Box::new(ParsingError::Unmatch(format!(
                "Invalid IOpProto format {s}"
            ))))
        }
    }
}

// Define some common IOp scaling
// Couldn't rely on NodesMap::new for constness reasons
const NODE_MAP_SINGLE: NodesMap = NodesMap([1; MAX_HPU_IN_CLUSTER]);
//const NODE_MAP_LINEAR: NodesMap = NodesMap([1, 2, 3, 4, 5, 6, 7, 8]);
//const NODE_MAP_EVEN: NodesMap = NodesMap([1, 2, 2, 4, 4, 6, 6, 8]);
//const NODE_MAP_POW2: NodesMap = NodesMap([1, 2, 2, 4, 4, 4, 4, 8]);

// Define some common iop format
pub const IOP1_CT_F_CT: ConstIOpProto<1, 1> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native; 1],
    src: [VarMode::Native; 1],
    imm: 0,
};
pub const IOP1_CT_F_2CT: ConstIOpProto<1, 2> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native; 1],
    src: [VarMode::Native; 2],
    imm: 0,
};
pub const IOP4_CT_F_2CT: ConstIOpProto<1, 2> = ConstIOpProto {
    used_nodes: NodesMap([4; MAX_HPU_IN_CLUSTER]),
    dst: [VarMode::Native; 1],
    src: [VarMode::Native; 2],
    imm: 0,
};
pub const IOP1_CT_F_2CT_BOOL: ConstIOpProto<1, 3> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native; 1],
    src: [VarMode::Native, VarMode::Native, VarMode::Bool],
    imm: 0,
};
pub const IOP1_CT_F_CT_BOOL: ConstIOpProto<1, 2> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native; 1],
    src: [VarMode::Native, VarMode::Bool],
    imm: 0,
};
pub const IOP1_CT_F_CT_SCALAR: ConstIOpProto<1, 1> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native; 1],
    src: [VarMode::Native; 1],
    imm: 1,
};
pub const IOP1_CMP: ConstIOpProto<1, 2> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Bool; 1],
    src: [VarMode::Native; 2],
    imm: 0,
};
pub const IOP1_2CT_F_3CT: ConstIOpProto<2, 3> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native; 2],
    src: [VarMode::Native; 3],
    imm: 0,
};
pub const IOP1_CT_BOOL_F_2CT: ConstIOpProto<2, 2> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native, VarMode::Bool],
    src: [VarMode::Native, VarMode::Native],
    imm: 0,
};
pub const IOP1_CT_BOOL_F_CT_SCALAR: ConstIOpProto<2, 1> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native, VarMode::Bool],
    src: [VarMode::Native; 1],
    imm: 1,
};
pub const IOP1_2CT_F_2CT: ConstIOpProto<2, 2> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native; 2],
    src: [VarMode::Native; 2],
    imm: 0,
};
pub const IOP1_2CT_F_CT_SCALAR: ConstIOpProto<2, 1> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native; 2],
    src: [VarMode::Native; 1],
    imm: 1,
};

pub const SIMD_N: usize = 12; //TODO: We need to come up with a way to have this dynamic
pub const IOP1_NCT_F_2NCT: ConstIOpProto<{ SIMD_N }, { 2 * SIMD_N }> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native; SIMD_N],
    src: [VarMode::Native; 2 * SIMD_N],
    imm: 0,
};
pub const IOP1_2NCT_F_3NCT: ConstIOpProto<{ 2 * SIMD_N }, { 3 * SIMD_N }> = ConstIOpProto {
    used_nodes: NODE_MAP_SINGLE,
    dst: [VarMode::Native; 2 * SIMD_N],
    src: [VarMode::Native; 3 * SIMD_N],
    imm: 0,
};

use crate::iop;
use arg::IOpFormat;
use lazy_static::lazy_static;
use std::collections::HashMap;

iop!(
    [IOP1_CT_F_CT_SCALAR -> "ADDS", opcode::ADDS],
    [IOP1_CT_F_CT_SCALAR -> "SUBS", opcode::SUBS],
    [IOP1_CT_F_CT_SCALAR -> "SSUB", opcode::SSUB],
    [IOP1_CT_F_CT_SCALAR -> "MULS", opcode::MULS],
    [IOP1_2CT_F_CT_SCALAR -> "DIVS", opcode::DIVS],
    [IOP1_CT_F_CT_SCALAR -> "MODS", opcode::MODS],
    [IOP1_CT_BOOL_F_CT_SCALAR -> "OVF_ADDS", opcode::OVF_ADDS],
    [IOP1_CT_BOOL_F_CT_SCALAR -> "OVF_SUBS", opcode::OVF_SUBS],
    [IOP1_CT_BOOL_F_CT_SCALAR -> "OVF_SSUB", opcode::OVF_SSUB],
    [IOP1_CT_BOOL_F_CT_SCALAR -> "OVF_MULS", opcode::OVF_MULS],
    [IOP1_CT_F_CT_SCALAR -> "SHIFTS_R", opcode::SHIFTS_R],
    [IOP1_CT_F_CT_SCALAR -> "SHIFTS_L", opcode::SHIFTS_L],
    [IOP1_CT_F_CT_SCALAR -> "ROTS_R", opcode::ROTS_R],
    [IOP1_CT_F_CT_SCALAR -> "ROTS_L", opcode::ROTS_L],
    [IOP1_CT_F_2CT -> "ADD", opcode::ADD],
    [IOP1_CT_F_2CT -> "SUB", opcode::SUB],
    [IOP1_CT_F_2CT -> "MUL", opcode::MUL],
    [IOP4_CT_F_2CT -> "MHMUL", opcode::MHMUL],
    [IOP1_2CT_F_2CT -> "DIV", opcode::DIV],
    [IOP1_CT_F_2CT -> "MOD", opcode::MOD],
    [IOP1_CT_BOOL_F_2CT -> "OVF_ADD", opcode::OVF_ADD],
    [IOP1_CT_BOOL_F_2CT -> "OVF_SUB", opcode::OVF_SUB],
    [IOP1_CT_BOOL_F_2CT -> "OVF_MUL", opcode::OVF_MUL],
    [IOP1_CT_F_2CT -> "SHIFT_R", opcode::SHIFT_R],
    [IOP1_CT_F_2CT -> "SHIFT_L", opcode::SHIFT_L],
    [IOP1_CT_F_2CT -> "ROT_R", opcode::ROT_R],
    [IOP1_CT_F_2CT -> "ROT_L", opcode::ROT_L],
    [IOP1_CT_F_2CT -> "BW_AND", opcode::BW_AND],
    [IOP1_CT_F_2CT -> "BW_OR", opcode::BW_OR],
    [IOP1_CT_F_2CT -> "BW_XOR", opcode::BW_XOR],
    [IOP1_CT_F_CT  -> "BW_NOT", opcode::BW_NOT],
    [IOP1_CMP -> "CMP_GT", opcode::CMP_GT],
    [IOP1_CMP -> "CMP_GTE", opcode::CMP_GTE],
    [IOP1_CMP -> "CMP_LT", opcode::CMP_LT],
    [IOP1_CMP -> "CMP_LTE", opcode::CMP_LTE],
    [IOP1_CMP -> "CMP_EQ", opcode::CMP_EQ],
    [IOP1_CMP -> "CMP_NEQ", opcode::CMP_NEQ],
    [IOP1_CT_F_CT_BOOL -> "IF_THEN_ZERO", opcode::IF_THEN_ZERO],
    [IOP1_CT_F_2CT_BOOL -> "IF_THEN_ELSE", opcode::IF_THEN_ELSE],
    [IOP1_2CT_F_3CT -> "ERC_7984", opcode::ERC_7984],
    [IOP1_CT_F_CT -> "MEMCPY", opcode::MEMCPY],
    [IOP1_CT_F_CT -> "ILOG2", opcode::ILOG2],
    [IOP1_CT_F_CT -> "COUNT0", opcode::COUNT0],
    [IOP1_CT_F_CT -> "COUNT1", opcode::COUNT1],
    [IOP1_CT_F_CT -> "LEAD0", opcode::LEAD0],
    [IOP1_CT_F_CT -> "LEAD1", opcode::LEAD1],
    [IOP1_CT_F_CT -> "TRAIL0", opcode::TRAIL0],
    [IOP1_CT_F_CT -> "TRAIL1", opcode::TRAIL1],
    [IOP1_NCT_F_2NCT -> "ADD_SIMD", opcode::ADD_SIMD],
    [IOP1_2NCT_F_3NCT -> "ERC_7984_SIMD", opcode::ERC_7984_SIMD],
);
