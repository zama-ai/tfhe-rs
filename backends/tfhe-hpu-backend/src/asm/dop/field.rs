//! List of DOp field
//! Mainly thin wrapper over basic type to enforce correct used of asm fields

// Retrieved CtId definition
// This definition is on the boundaries between IOp and DOp and thus define in the top.
use super::opcode::Opcode;
use crate::asm::CtId;

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

/// Memory arguments
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
}

impl std::fmt::Display for ImmId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ImmId::Cst(val) => write!(f, "{val}"),
            ImmId::Var { tid, bid } => write!(f, "TI[{tid}].{bid}"),
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

/// Sync argument
/// Currently unused
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SyncId(pub u32);

impl std::fmt::Display for SyncId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
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

/// PePbs instructions
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PePbsInsn {
    pub dst_rid: RegId,
    pub src_rid: RegId,
    pub gid: PbsGid,
    pub opcode: Opcode,
}

/// PeSync instructions
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeSyncInsn {
    pub sid: SyncId,
    pub opcode: Opcode,
}
