mod field;
pub use field::{
    FwMode, HexParsingError, IOp, IOpMapping, IOpcode, Immediate, Operand, OperandKind,
};
mod fmt;
pub use fmt::{IOpRepr, IOpWordRepr};
mod iop_macro;
pub mod opcode;

mod arg;
pub use arg::{AsmIOpcode, ParsingError};

use lazy_static::lazy_static;
use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::str::FromStr;

pub const ASM_COMMENT_PREFIX: [char; 2] = [';', '#'];

// TODO find a proper way to let this runtime properties
pub const MSG_WIDTH: u8 = 2;
pub const CARRY_WIDTH: u8 = 2;
pub const MAX_HPU_IN_CLUSTER: usize = 8;

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

// Common type used in asm definition -----------------------------------------
/// Ciphertext Id
/// On-board memory is viewed as an array of ciphertext,
/// Thus, instead of using bytes address, ct id is used
/// => Id of the first ciphertext of the vector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CtId(pub u16);

/// Virtual Id
/// Depict the Hpu virtual target for firmware definition
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default,
)]
pub struct VirtId(pub u8);

impl std::fmt::Display for VirtId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "N{}", self.0)
    }
}

impl std::str::FromStr for VirtId {
    type Err = Box<ParsingError>;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref HID_ARG_RE: regex::Regex =
                regex::Regex::new(r"^N(?<id>(\d+))").expect("Invalid regex");
        }
        if let Some(caps) = HID_ARG_RE.captures(s) {
            let hid = caps["id"]
                .parse::<u8>()
                .map_err(|err| Box::new(ParsingError::InvalidArg(err.to_string())))?;
            Ok(Self(hid))
        } else {
            Err(Box::new(ParsingError::Unmatch(format!(
                "Invalid argument format for VirtId {s}"
            ))))
        }
    }
}

/// TargetId
/// Templated DOp used same field to encode PhysId/VirtId without available bit to keep the type
/// information TargetId is a generic type that maps to to PhysId/VirtId.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default,
)]
pub struct PhysId(pub u8);

impl std::fmt::Display for PhysId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Np{}", self.0)
    }
}

/// Describe IOp instruction Id, used to attach Ucore instruction flag to
/// the correct IOp.
/// Indeed, with the context of multi-hpu Node, multiple IOp could be executed at the same time.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize, Hash,
)]
pub struct IOpId(pub u8);

impl std::fmt::Display for IOpId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "iid{}", self.0)
    }
}

impl std::str::FromStr for IOpId {
    type Err = Box<ParsingError>;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref IID_ARG_RE: regex::Regex =
                regex::Regex::new(r"^iid(?<id>(\d+))").expect("Invalid regex");
        }
        if let Some(caps) = IID_ARG_RE.captures(s) {
            let iid = caps["id"]
                .parse::<u8>()
                .map_err(|err| Box::new(ParsingError::InvalidArg(err.to_string())))?;
            Ok(Self(iid))
        } else {
            Err(Box::new(ParsingError::Unmatch(format!(
                "Invalid argument format for IOpId {s}"
            ))))
        }
    }
}

/// Reserved IOpId for Sw generated value
pub const SW_IOP_ID: IOpId = IOpId(0);
// ------------------------------------------------------------------------------

/// Simple test for Asm parsing
#[cfg(test)]
mod tests;

/// Type to aggregate Op and header
/// Aim is to kept correct interleaving while parsing
#[derive(Debug, Clone)]
pub enum AsmOp {
    Comment(String),
    Stmt(IOp),
}

impl std::fmt::Display for AsmOp {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Comment(c) => write!(f, "{}{c}", ASM_COMMENT_PREFIX[0]),
            Self::Stmt(op) => write!(f, "{op}"),
        }
    }
}

/// Struct to represent a sequence of IOp operations
/// Used to extract IOp from ASM/HEX file
#[derive(Debug, Clone, Default)]
pub struct Program(Vec<AsmOp>);

impl Program {
    pub fn new(ops: Vec<AsmOp>) -> Self {
        Self(ops)
    }
    /// Push a new statement in the program
    pub fn push_stmt(&mut self, op: IOp) {
        self.0.push(AsmOp::Stmt(op))
    }
    /// Push a new statement in the program
    /// Returns the position in which the statement was inserted
    pub fn push_stmt_pos(&mut self, op: IOp) -> usize {
        let ret = self.0.len();
        self.0.push(AsmOp::Stmt(op));
        ret
    }
    /// Push a new comment in the program
    pub fn push_comment(&mut self, comment: String) {
        self.0.push(AsmOp::Comment(comment))
    }

    pub fn get_stmt_mut(&mut self, i: usize) -> &mut AsmOp {
        &mut self.0[i]
    }
}

impl std::ops::Deref for Program {
    type Target = Vec<AsmOp>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for op in self.0.iter() {
            writeln!(f, "{op}")?;
        }
        Ok(())
    }
}

impl Program {
    /// Extract IOp from ASM file
    pub fn read_asm(file: &str) -> Result<Self, anyhow::Error> {
        // Open file
        let rd_f = std::io::BufReader::new(
            std::fs::OpenOptions::new()
                .create(false)
                .read(true)
                .open(file)?,
        );

        let mut asm_ops = Vec::new();
        for (line, val) in rd_f.lines().map_while(Result::ok).enumerate() {
            if let Some(comment) = val.trim().strip_prefix(ASM_COMMENT_PREFIX) {
                asm_ops.push(AsmOp::Comment(comment.to_string()))
            } else if !val.is_empty() {
                match IOp::from_str(&val) {
                    Ok(op) => asm_ops.push(AsmOp::Stmt(op)),
                    Err(err) => {
                        tracing::warn!("ReadAsm failed @{file}:{}", line + 1);
                        anyhow::bail!("ReadAsm failed @{file}:{} with {}", line + 1, err);
                    }
                }
            }
        }
        Ok(Self(asm_ops))
    }

    /// Write IOp Program in ASM file
    pub fn write_asm(&self, file: &str) -> Result<(), anyhow::Error> {
        // Create path
        let path = std::path::Path::new(file);
        if let Some(dir_p) = path.parent() {
            std::fs::create_dir_all(dir_p).unwrap();
        }

        // Open file
        let mut wr_f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        writeln!(wr_f, "{self}").map_err(anyhow::Error::new)
    }

    /// Extract IOp from hex file
    pub fn read_hex(file: &str) -> Result<Self, anyhow::Error> {
        // Open file
        let rd_f = std::io::BufReader::new(
            std::fs::OpenOptions::new()
                .create(false)
                .read(true)
                .open(file)
                .unwrap_or_else(|_| panic!("Invalid HEX file {file}")),
        );

        let mut prog = Self::default();
        // Buffer word stream.
        // When comment token occurred, convert the word stream into IOp
        // -> No comment could be inserted in a middle of IOp word stream
        let mut word_stream = VecDeque::new();
        let mut file_len = 0;

        for val in rd_f.lines().map_while(Result::ok) {
            file_len += 1;
            if let Some(comment) = val.trim().strip_prefix(ASM_COMMENT_PREFIX) {
                while !word_stream.is_empty() {
                    match IOp::from_words(&mut word_stream) {
                        Ok(op) => prog.push_stmt(op),
                        Err(err) => {
                            tracing::warn!(
                                "IOp::ReadHex failed @{file}:{}",
                                file_len - word_stream.len()
                            );
                            return Err(err.into());
                        }
                    }
                }
                prog.push_comment(comment.to_string());
            } else {
                let word = IOpWordRepr::from_str_radix(
                    std::str::from_utf8(val.as_bytes()).unwrap(),
                    16,
                )?;
                word_stream.push_back(word);
            }
        }
        // Flush word stream
        while !word_stream.is_empty() {
            match IOp::from_words(&mut word_stream) {
                Ok(op) => prog.push_stmt(op),
                Err(err) => {
                    tracing::warn!(
                        "IOp::ReadHex failed @{file}:{}",
                        file_len - word_stream.len()
                    );
                    return Err(err.into());
                }
            }
        }
        Ok(prog)
    }

    /// Write IOp Program in Hex file
    pub fn write_hex(&self, file: &str) -> Result<(), anyhow::Error> {
        // Create path
        let path = std::path::Path::new(file);
        if let Some(dir_p) = path.parent() {
            std::fs::create_dir_all(dir_p).unwrap();
        }

        // Open file
        let mut wr_f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        for op in self.0.iter() {
            match op {
                AsmOp::Comment(comment) => writeln!(wr_f, "{}{}", ASM_COMMENT_PREFIX[0], comment)?,
                AsmOp::Stmt(op) => {
                    op.to_words()
                        .into_iter()
                        .try_for_each(|word| writeln!(wr_f, "{word:0>8x}"))?;
                }
            }
        }
        Ok(())
    }
}

use crate::iop;
use arg::IOpFormat;
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
