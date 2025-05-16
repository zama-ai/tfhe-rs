//!
//! Gather DOp argument in a common type
//! Provides a FromStr implementation for parsing

use crate::asm::CtId;

use super::field::{ImmId, MemId, RegId, SyncId};
use super::*;
use lazy_static::lazy_static;

/// Minimum asm arg width to have aligned field
pub const ARG_MIN_WIDTH: usize = 16;
pub const DOP_MIN_WIDTH: usize = 10;

/// Generic arguments
/// Used to pack argument under the same type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Reg(RegId),
    Mem(MemId),
    Imm(ImmId),
    Pbs(Pbs),
    Sync(SyncId),
}

/// Use Display trait to convert into asm human readable file
/// Simply defer to inner type display impl while forcing the display width
impl std::fmt::Display for Arg {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Arg::Reg(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
            Arg::Mem(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
            Arg::Imm(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
            Arg::Pbs(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
            Arg::Sync(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
        }
    }
}

/// Parsing error
#[derive(thiserror::Error, Debug, Clone)]
pub enum ParsingError {
    #[error("Unmatch Asm Operation: {0}")]
    Unmatch(String),
    #[error("Invalid arguments number: expect {0}, get {1}")]
    ArgNumber(usize, usize),
    #[error("Invalid arguments type: expect {0}, get {1}")]
    ArgType(String, Arg),
    #[error("Invalid arguments: {0}")]
    InvalidArg(String),
    #[error("Empty line")]
    Empty,
}

/// Use FromStr trait to decode from asm file
impl std::str::FromStr for Arg {
    type Err = ParsingError;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
                    static ref DOP_ARG_RE: regex::Regex = regex::Regex::new(
        r"(?<register>^R(?<rid>[0-9]+))|(?<mem_addr>^@((?<hex_cid>0x[0-9a-fA-F]+)|(?<cid>[0-9]+)))|(?<mem_tmpl>^(?<mt_orig>TS|TD|TH)(\[(?<mt_id>\d+)\])*\.(?<mt_bid>\d+))|(?<imm_cst>^((?<hex_cst>0x[0-9a-fA-F]+)|(?<cst>[0-9]+)))|(?<imm_var>^TI\[(?<it_id>\d+)\]\.(?<it_bid>\d+))|(?<pbs>^Pbs(?<pbs_name>(\S+)))"
                    )
                    .expect("Invalid regex");
                }

        if let Some(caps) = DOP_ARG_RE.captures(s) {
            if let Some(_register) = caps.name("register") {
                let rid = caps["rid"]
                    .parse::<u8>()
                    .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
                Ok(Arg::Reg(RegId(rid)))
            } else if let Some(_mem_addr) = caps.name("mem_addr") {
                let cid = if let Some(raw_cid) = caps.name("cid") {
                    raw_cid
                        .as_str()
                        .parse::<u16>()
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?
                } else {
                    // One of them must match, otherwise error will be arose before
                    let raw_hex_cid = caps.name("hex_cid").unwrap();
                    u16::from_str_radix(&raw_hex_cid.as_str()[2..], 16)
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?
                };
                Ok(Arg::Mem(MemId::Addr(CtId(cid))))
            } else if let Some(_mem_tmpl) = caps.name("mem_tmpl") {
                let tid = if let Some(raw_tid) = caps.name("mt_id") {
                    Some(
                        raw_tid
                            .as_str()
                            .parse::<u8>()
                            .map_err(|err| ParsingError::InvalidArg(err.to_string()))?,
                    )
                } else {
                    None
                };
                let bid = caps["mt_bid"]
                    .parse::<u16>()
                    .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;

                match &caps["mt_orig"] {
                    "TS" => {
                        if tid.is_none() {
                            return Err(ParsingError::InvalidArg(format!("Memory template Src must have following format `TS[tid].bid` (parsed {})",&caps["mem_tmpl"])));
                        }
                        Ok(Arg::Mem(MemId::Src {
                            tid: tid.unwrap(),
                            bid: bid as u8,
                        }))
                    }
                    "TD" => {
                        if tid.is_none() {
                            return Err(ParsingError::InvalidArg(format!("Memory template Dst must have following format `TD[tid].bid` (parsed {})",&caps["mem_tmpl"])));
                        }
                        Ok(Arg::Mem(MemId::Dst {
                            tid: tid.unwrap(),
                            bid: bid as u8,
                        }))
                    }
                    "TH" => {
                        if tid.is_some() {
                            return Err(ParsingError::InvalidArg(format!("Memory template Heap must have following format `TH.bid` (parsed {})",&caps["mem_tmpl"])));
                        }
                        Ok(Arg::Mem(MemId::Heap { bid }))
                    }
                    _ => Err(ParsingError::InvalidArg(format!(
                        "Invalid memory template argument {}",
                        &caps["mem_tmpl"]
                    ))),
                }
            } else if let Some(_imm_cst) = caps.name("imm_cst") {
                let cst = if let Some(raw_cst) = caps.name("cst") {
                    raw_cst
                        .as_str()
                        .parse::<u16>()
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?
                } else {
                    // One of them must match, otherwise error will be arose before
                    let raw_hex_cst = caps.name("hex_cst").unwrap();
                    u16::from_str_radix(&raw_hex_cst.as_str()[2..], 16)
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?
                };
                Ok(Arg::Imm(ImmId::Cst(cst)))
            } else if let Some(_imm_var) = caps.name("imm_var") {
                let tid = caps["it_id"]
                    .parse::<u8>()
                    .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
                let bid = caps["it_bid"]
                    .parse::<u8>()
                    .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
                Ok(Arg::Imm(ImmId::Var { tid, bid }))
            } else if let Some(_pbs) = caps.name("pbs") {
                Ok(Arg::Pbs(Pbs::from_str(&caps["pbs_name"])?))
            } else {
                Err(ParsingError::Unmatch(format!(
                    "Invalid argument format {s}"
                )))
            }
        } else {
            Err(ParsingError::Unmatch(format!(
                "Invalid argument format {s}"
            )))
        }
    }
}

pub trait FromAsm
where
    Self: Sized,
{
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, ParsingError>;
}

#[enum_dispatch]
pub trait ToAsm
where
    Self: Sized,
{
    fn name(&self) -> &'static str {
        std::any::type_name_of_val(self)
    }

    fn args(&self) -> Vec<arg::Arg> {
        let mut arg = self.dst();
        arg.extend_from_slice(self.src().as_slice());
        arg
    }
    fn dst(&self) -> Vec<arg::Arg>;
    fn src(&self) -> Vec<arg::Arg>;
}

#[enum_dispatch]
pub trait IsFlush
where
    Self: Sized,
{
    fn is_flush(&self) -> bool {
        false
    }
}

pub trait ToFlush
where
    Self: Sized + Clone,
{
    fn to_flush(&self) -> Self {
        self.clone()
    }
}

impl FromAsm for field::PeArithInsn {
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, ParsingError> {
        if (args.len() != 3) && (args.len() != 4) {
            return Err(ParsingError::ArgNumber(3, args.len()));
        }

        let dst_rid = match args[0] {
            Arg::Reg(id) => id,
            _ => {
                return Err(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[0].clone(),
                ))
            }
        };
        let src0_rid = match args[1] {
            Arg::Reg(id) => id,
            _ => {
                return Err(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[1].clone(),
                ))
            }
        };
        let src1_rid = match args[2] {
            Arg::Reg(id) => id,
            _ => {
                return Err(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[2].clone(),
                ))
            }
        };

        let mul_factor = if let Some(arg) = args.get(3) {
            match arg {
                Arg::Imm(ImmId::Cst(id)) => MulFactor(*id as u8),
                _ => {
                    return Err(ParsingError::ArgType(
                        "Arg::Imm::Cst".to_string(),
                        args[3].clone(),
                    ))
                }
            }
        } else {
            MulFactor(0)
        };

        Ok(Self {
            opcode: Opcode::from(opcode),
            mul_factor,
            src1_rid,
            src0_rid,
            dst_rid,
        })
    }
}

impl ToAsm for PeArithInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        vec![arg::Arg::Reg(self.dst_rid)]
    }
    fn src(&self) -> Vec<arg::Arg> {
        let mut src = vec![arg::Arg::Reg(self.src0_rid), arg::Arg::Reg(self.src1_rid)];
        if self.mul_factor != MulFactor(0) {
            src.push(arg::Arg::Imm(ImmId::Cst(self.mul_factor.0 as u16)));
        }
        src
    }
}

impl FromAsm for field::PeArithMsgInsn {
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, ParsingError> {
        if args.len() != 3 {
            return Err(ParsingError::ArgNumber(3, args.len()));
        }

        let dst_rid = match args[0] {
            Arg::Reg(id) => id,
            _ => {
                return Err(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[0].clone(),
                ))
            }
        };
        let src_rid = match args[1] {
            Arg::Reg(id) => id,
            _ => {
                return Err(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[1].clone(),
                ))
            }
        };
        let msg_cst = match args[2] {
            Arg::Imm(id) => id,
            _ => {
                return Err(ParsingError::ArgType(
                    "Arg::Imm".to_string(),
                    args[2].clone(),
                ))
            }
        };

        Ok(Self {
            opcode: Opcode::from(opcode),
            msg_cst,
            src_rid,
            dst_rid,
        })
    }
}

impl ToAsm for PeArithMsgInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        vec![arg::Arg::Reg(self.dst_rid)]
    }
    fn src(&self) -> Vec<arg::Arg> {
        vec![arg::Arg::Reg(self.src_rid), arg::Arg::Imm(self.msg_cst)]
    }
}

impl FromAsm for field::PeMemInsn {
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, ParsingError> {
        if args.len() != 2 {
            return Err(ParsingError::ArgNumber(2, args.len()));
        }

        let (rid, mid) = match opcode {
            _x if _x == u8::from(opcode::Opcode::LD()) => {
                let rid = match args[0] {
                    Arg::Reg(id) => id,
                    _ => {
                        return Err(ParsingError::ArgType(
                            "Arg::Reg".to_string(),
                            args[0].clone(),
                        ))
                    }
                };
                let slot = match args[1] {
                    Arg::Mem(id) => id,
                    _ => {
                        return Err(ParsingError::ArgType(
                            "Arg::Mem".to_string(),
                            args[1].clone(),
                        ))
                    }
                };
                (rid, slot)
            }
            _x if _x == u8::from(opcode::Opcode::ST()) => {
                let slot = match args[0] {
                    Arg::Mem(id) => id,
                    _ => {
                        return Err(ParsingError::ArgType(
                            "Arg::Mem".to_string(),
                            args[0].clone(),
                        ))
                    }
                };

                let rid = match args[1] {
                    Arg::Reg(id) => id,
                    _ => {
                        return Err(ParsingError::ArgType(
                            "Arg::Reg".to_string(),
                            args[1].clone(),
                        ))
                    }
                };
                (rid, slot)
            }
            _ => {
                return Err(ParsingError::Unmatch(
                    "PeMemInsn expect LD/ST opcode".to_string(),
                ))
            }
        };

        Ok(Self {
            opcode: Opcode::from(opcode),
            slot: mid,
            rid,
        })
    }
}

impl ToAsm for PeMemInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        match self.opcode {
            _x if _x == opcode::Opcode::LD() => vec![Arg::Reg(self.rid)],
            _x if _x == opcode::Opcode::ST() => vec![Arg::Mem(self.slot)],
            _ => panic!("Unsupported opcode for PeMemInsn"),
        }
    }
    fn src(&self) -> Vec<arg::Arg> {
        match self.opcode {
            _x if _x == opcode::Opcode::LD() => vec![Arg::Mem(self.slot)],
            _x if _x == opcode::Opcode::ST() => vec![Arg::Reg(self.rid)],
            _ => panic!("Unsupported opcode for PeMemInsn"),
        }
    }
}

impl FromAsm for field::PePbsInsn {
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, ParsingError> {
        if args.len() != 3 {
            return Err(ParsingError::ArgNumber(3, args.len()));
        }

        let dst_rid = match args[0] {
            Arg::Reg(id) => id,
            _ => {
                return Err(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[0].clone(),
                ))
            }
        };
        let src_rid = match args[1] {
            Arg::Reg(id) => id,
            _ => {
                return Err(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[1].clone(),
                ))
            }
        };
        let pbs_lut = match &args[2] {
            Arg::Pbs(id) => id,
            _ => {
                return Err(ParsingError::ArgType(
                    "Arg::Pbs".to_string(),
                    args[2].clone(),
                ))
            }
        };

        Ok(Self {
            opcode: Opcode::from(opcode),
            gid: pbs_lut.gid(),
            src_rid,
            dst_rid,
        })
    }
}

impl ToAsm for PePbsInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        vec![Arg::Reg(self.dst_rid)]
    }
    fn src(&self) -> Vec<arg::Arg> {
        vec![
            Arg::Reg(self.src_rid),
            Arg::Pbs(Pbs::from_hex(self.gid).unwrap()),
        ]
    }
}

impl FromAsm for field::PeSyncInsn {
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, ParsingError> {
        if (args.len() != 1) && (!args.is_empty()) {
            return Err(ParsingError::ArgNumber(1, args.len()));
        }

        let sid = if let Some(arg) = args.get(1) {
            match arg {
                Arg::Sync(id) => *id,
                _ => {
                    return Err(ParsingError::ArgType(
                        "Arg::Sync".to_string(),
                        args[1].clone(),
                    ))
                }
            }
        } else {
            SyncId(0)
        };

        Ok(Self {
            opcode: Opcode::from(opcode),
            sid,
        })
    }
}

impl ToAsm for PeSyncInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        vec![]
    }
    fn src(&self) -> Vec<arg::Arg> {
        vec![Arg::Sync(self.sid)]
    }
}

impl ToFlush for field::PePbsInsn {
    fn to_flush(&self) -> Self {
        PePbsInsn {
            opcode: self.opcode.to_flush(),
            ..*self
        }
    }
}
impl ToFlush for field::PeSyncInsn {}
impl ToFlush for field::PeArithInsn {}
impl ToFlush for field::PeArithMsgInsn {}
impl ToFlush for field::PeMemInsn {}
