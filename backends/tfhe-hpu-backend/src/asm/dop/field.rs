//! List of DOp field
//! Mainly thin wrapper over basic type to enforce correct used of asm fields

// Retrieved common IOp/DOp definition
// Those definition are on the boundaries between IOp and DOp and thus define in the top.
use super::opcode::Opcode;
use crate::asm::dop::ParsingError;
use crate::asm::{CtId, IOpId, PhysId, VirtId};
use lazy_static::lazy_static;

/// Register argument
/// Direct mapping of value to register Id
/// 7bits wide -> 128 registers
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default,
)]
pub struct RegId(pub u8);

impl std::ops::Add<usize> for RegId {
    type Output = RegId;
    fn add(self, rhs: usize) -> Self::Output {
        RegId(self.0 + (rhs as u8))
    }
}

impl std::fmt::Display for RegId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "R{}", self.0)
    }
}

impl std::str::FromStr for RegId {
    type Err = ParsingError;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref REG_ARG_RE: regex::Regex =
                regex::Regex::new(r"^R(?<rid>(\d+))").expect("Invalid regex");
        }
        if let Some(caps) = REG_ARG_RE.captures(s) {
            let rid = caps["rid"]
                .parse::<u8>()
                .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
            Ok(Self(rid))
        } else {
            Err(ParsingError::Unmatch(format!(
                "Invalid argument format for RegId {s}"
            )))
        }
    }
}

/// MulFactor argument
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MulFactor(pub u8);

impl std::fmt::Display for MulFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "R{}", self.0)
    }
}

/// Memory arguments
/// Have multiple mode for proper support of template addressing
/// Template enable runtime replacement of MemId with associated Top-level arguments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MemId {
    Addr(CtId),
    Heap { bid: u16 },
    Src { tid: u8, bid: u8 },
    Dst { tid: u8, bid: u8 },
}

impl MemId {
    pub fn new_heap(bid: u16) -> Self {
        Self::Heap { bid }
    }
    pub fn new_dst(tid: u8, bid: u8) -> Self {
        Self::Dst { tid, bid }
    }
    pub fn new_src(tid: u8, bid: u8) -> Self {
        Self::Src { tid, bid }
    }
    pub fn unwrap_addr(self) -> u16 {
        match self {
            MemId::Addr(CtId(val)) => val,
            _ => panic!("Unwrap as addr called on templated MemId"),
        }
    }
}

impl Default for MemId {
    fn default() -> Self {
        Self::Addr(CtId(0))
    }
}

impl std::fmt::Display for MemId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MemId::Addr(addr) => write!(f, "@0x{:x}", addr.0),
            MemId::Heap { bid } => write!(f, "TH.{bid}"),
            MemId::Src { tid, bid } => write!(f, "TS[{tid}].{bid}"),
            MemId::Dst { tid, bid } => write!(f, "TD[{tid}].{bid}"),
        }
    }
}

impl std::str::FromStr for MemId {
    type Err = ParsingError;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
                    static ref MEM_ARG_RE: regex::Regex = regex::Regex::new(
        r"(?<addr>^@((?<hex_cid>0x[0-9a-fA-F]+)|(?<cid>[0-9]+)))|(?<tmpl>^(?<mt_orig>TS|TD|TH)(\[(?<mt_id>\d+)\])*\.(?<mt_bid>\d+))"
                    )
                    .expect("Invalid regex");
                }
        if let Some(caps) = MEM_ARG_RE.captures(s) {
            if let Some(_addr) = caps.name("addr") {
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
                Ok(Self::Addr(CtId(cid)))
            } else if let Some(_tmpl) = caps.name("tmpl") {
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
                            return Err(ParsingError::InvalidArg(format!("Memory template Src must have following format `TS[tid].bid` (parsed {})",&caps["tmpl"])));
                        }
                        Ok(Self::Src {
                            tid: tid.unwrap(),
                            bid: bid as u8,
                        })
                    }
                    "TD" => {
                        if tid.is_none() {
                            return Err(ParsingError::InvalidArg(format!("Memory template Dst must have following format `TD[tid].bid` (parsed {})",&caps["tmpl"])));
                        }
                        Ok(Self::Dst {
                            tid: tid.unwrap(),
                            bid: bid as u8,
                        })
                    }
                    "TH" => {
                        if tid.is_some() {
                            return Err(ParsingError::InvalidArg(format!("Memory template Heap must have following format `TH.bid` (parsed {})",&caps["tmpl"])));
                        }
                        Ok(Self::Heap { bid })
                    }
                    _ => Err(ParsingError::InvalidArg(format!(
                        "Invalid memory template argument {}",
                        &caps["tmpl"]
                    ))),
                }
            } else {
                unreachable!()
            }
        } else {
            Err(ParsingError::Unmatch(format!(
                "Invalid argument format for MemId {s}"
            )))
        }
    }
}

/// Immediate arguments
/// Have multiple mode for proper support of template addressing
/// Template enable runtime replacement of MemId with associated Top-level arguments
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ImmId {
    Cst(u16),
    Var { tid: u8, bid: u8 },
}

impl ImmId {
    /// Create new immediate template
    pub fn new_var(tid: u8, bid: u8) -> Self {
        Self::Var { tid, bid }
    }
    pub fn unwrap_cst(self) -> u16 {
        match self {
            ImmId::Cst(val) => val,
            _ => panic!("Unwrap as constant called on templated ImmId"),
        }
    }
}

impl std::fmt::Display for ImmId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ImmId::Cst(val) => write!(f, "{val}"),
            ImmId::Var { tid, bid } => write!(f, "TI[{tid}].{bid}"),
        }
    }
}

impl std::str::FromStr for ImmId {
    type Err = ParsingError;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
                    static ref IMM_ARG_RE: regex::Regex = regex::Regex::new(
        r"(?<imm_cst>^((?<hex_cst>0x[0-9a-fA-F]+)|(?<cst>[0-9]+)))|(?<imm_var>^TI\[(?<it_id>\d+)\]\.(?<it_bid>\d+))"
                    )
                    .expect("Invalid regex");
                }

        if let Some(caps) = IMM_ARG_RE.captures(s) {
            if let Some(_imm_cst) = caps.name("imm_cst") {
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
                Ok(ImmId::Cst(cst))
            } else if let Some(_imm_var) = caps.name("imm_var") {
                let tid = caps["it_id"]
                    .parse::<u8>()
                    .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
                let bid = caps["it_bid"]
                    .parse::<u8>()
                    .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
                Ok(ImmId::Var { tid, bid })
            } else {
                unreachable!()
            }
        } else {
            Err(ParsingError::Unmatch(format!(
                "Invalid argument format for ImmId {s}"
            )))
        }
    }
}

/// Pbs argument
/// Direct mapping to PBS Gid
/// 12bits wide -> 4096 lut entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PbsGid(pub u16);

impl std::fmt::Display for PbsGid {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Pbs{}", self.0)
    }
}

// Ucore arguments
// Define custom arguments for Ucore instruction and Ucore payload.
// Ucore specificity is that Ucore instruction is enhanced at execution with runtime information
// By this way only a subset of info is embedded in the code and all things related to
// execution context is carried over at runtime.
// This is useful this Ucore instruction is used to shared information between Hpu Nodes

/// UserFlag
/// Describe user event flag. It's like a hash/UUID for matching Ucore instruction together
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Hash, Default,
)]
pub struct UserFlag(pub u8);

impl std::fmt::Display for UserFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "F{}", self.0)
    }
}

impl std::str::FromStr for UserFlag {
    type Err = ParsingError;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref FLAG_ARG_RE: regex::Regex =
                regex::Regex::new(r"^F(?<fid>(\d+))").expect("Invalid regex");
        }
        if let Some(caps) = FLAG_ARG_RE.captures(s) {
            let fid = caps["fid"]
                .parse::<u8>()
                .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
            Ok(Self(fid))
        } else {
            Err(ParsingError::Unmatch(format!(
                "Invalid argument format for UcoreFlag {s}"
            )))
        }
    }
}

/// UcoreFlag
/// Describe ucore event flag. It's like a hash/UUID for matching Ucore instruction together
/// Ucore event are used for Src/Dst arguments fetching
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Hash)]
pub struct UcoreFlag {
    pub tid: u8,
    pub bid: u8,
    //NB: Targeted Hpu could have not received associated IOp (with trgt dst position)
    // Giving position in the payload enable direct data fetch
    pub trgt_cid: CtId,
}

/// Ucore payload could be issued by:
/// * user (i.e. from DOp) -> use as barrier inside same IOp
/// * ucore: Src/Dst barrier between IOps
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UcorePayloadMode {
    Ucore(UcoreFlag),
    User(UserFlag),
    IOpDone(u8),
}

// PeUcore instructions are enhanced at execution with context information and shared across Hpu
// Structs below depicts the message format used during inter-hpu control communications
/// PeUcorePayload
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UcorePayload {
    pub mode: UcorePayloadMode,
    pub slot: Option<CtId>,
    pub from_hid: PhysId,
    pub iid: IOpId,
}

/// PeArith instructions
/// Arithmetic operation that use one destination register and two sources register
/// Have also an extra mul_factor field for MAC insn
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeArithInsn {
    pub dst_rid: RegId,
    pub src0_rid: RegId,
    pub src1_rid: RegId,
    pub mul_factor: MulFactor,
    pub opcode: Opcode,
}

/// PeaMsg instructions
/// Arithmetic operation that use one destination register, one source register and an immediate
/// value
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeArithMsgInsn {
    pub dst_rid: RegId,
    pub src_rid: RegId,
    pub msg_cst: ImmId,
    pub opcode: Opcode,
}

/// PeMem instructions
/// LD/St operation with one register and one memory slot
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeMemInsn {
    pub rid: RegId,
    pub slot: MemId,
    pub opcode: Opcode,
}

/// PeSync instructions
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeSyncInsn {
    pub flag: UserFlag,
    pub hid: VirtId,
    pub iid: IOpId,
    pub is_inner_sync: bool,
    pub opcode: Opcode,
}

/// PePbs instructions
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PePbsInsn {
    pub dst_rid: RegId,
    pub src_rid: RegId,
    pub gid: PbsGid,
    pub opcode: Opcode,
}

/// PeUcore instructions
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeUcoreInsn {
    pub slot: MemId,
    pub flag: UserFlag,
    pub hid: VirtId,
    pub opcode: Opcode,
}
