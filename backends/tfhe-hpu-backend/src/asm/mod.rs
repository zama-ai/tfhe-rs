mod field;
pub use field::{
    FwMode, HexParsingError, IOp, IOpMapping, IOpcode, Immediate, Operand, OperandKind,
};
mod fmt;
pub use fmt::{IOpRepr, IOpWordRepr};
pub mod static_iop;
pub use static_iop::StaticIOp;

mod arg;
pub use arg::ParsingError;

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

/// Dynamic type to erase const template
// TODO moved from runtime check to compile time one
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IOpProto {
    pub used_nodes: NodesMap,
    pub dst: Vec<VarMode>,
    pub src: Vec<VarMode>,
    pub imm: usize,
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
                let word =
                    IOpWordRepr::from_str_radix(std::str::from_utf8(val.as_bytes()).unwrap(), 16)?;
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
