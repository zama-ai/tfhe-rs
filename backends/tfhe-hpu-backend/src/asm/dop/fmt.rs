//!
//! Define binary format encoding of instructions
//! Rely on `bitfield_struct` crate to define bit-accurate insn format and enable serde to
//! byte-stream
//!
//! Provide conversion implementation between raw bitfield and DOp types
use bitfield_struct::bitfield;

use super::*;

// List of DOp format with there associated encoding
// NB: typedef couldn't be used in bitfield_struct macro. Thus macro rely on u32 instead of
// DOpRepr...
// ------------------------------------------------------------------------------------------------
/// Raw type used for encoding
pub type DOpRepr = u32;

#[enum_dispatch]
pub trait ToHex {
    fn to_hex(&self) -> DOpRepr;
}

/// DOp raw encoding used for Opcode extraction
#[bitfield(u32)]
pub struct DOpRawHex {
    #[bits(26)]
    _reserved: u32,
    #[bits(6)]
    pub opcode: u8,
}

/// PeArith instructions
/// Arithmetic operation that use one destination register and two sources register
/// Have also an extra mul_factor field for MAC insn
#[bitfield(u32)]
pub struct PeArithHex {
    #[bits(7)]
    dst_rid: u8,
    #[bits(7)]
    src0_rid: u8,
    #[bits(7)]
    src1_rid: u8,
    #[bits(5)]
    mul_factor: u8,
    #[bits(6)]
    opcode: u8,
}

impl From<&PeArithInsn> for PeArithHex {
    fn from(value: &PeArithInsn) -> Self {
        Self::new()
            .with_dst_rid(value.dst_rid.0)
            .with_src0_rid(value.src0_rid.0)
            .with_src1_rid(value.src1_rid.0)
            .with_mul_factor(value.mul_factor.0)
            .with_opcode(value.opcode.into())
    }
}
impl From<&PeArithHex> for PeArithInsn {
    fn from(value: &PeArithHex) -> Self {
        Self {
            dst_rid: RegId(value.dst_rid()),
            src0_rid: RegId(value.src0_rid()),
            src1_rid: RegId(value.src1_rid()),
            mul_factor: MulFactor(value.mul_factor()),
            opcode: Opcode::from(value.opcode()),
        }
    }
}

/// PeaMsg instructions
/// Arithmetic operation that use one destination register, one source register and an immediate
/// value
#[bitfield(u32)]
pub struct PeArithMsgHex {
    #[bits(7)]
    dst_rid: u8,
    #[bits(7)]
    src_rid: u8,
    #[bits(1)]
    msg_mode: bool,
    #[bits(11)]
    msg_cst: u16,
    #[bits(6)]
    opcode: u8,
}
// Define encoding for msg_mode
const IMM_CST: bool = false;
const IMM_VAR: bool = true;

impl From<&PeArithMsgInsn> for PeArithMsgHex {
    fn from(value: &PeArithMsgInsn) -> Self {
        let (mode, cst) = match value.msg_cst {
            ImmId::Cst(cst) => (IMM_CST, cst),
            ImmId::Var { tid, bid } => (IMM_VAR, (((tid as u16) << 8) + bid as u16)),
        };

        Self::new()
            .with_dst_rid(value.dst_rid.0)
            .with_src_rid(value.src_rid.0)
            .with_msg_mode(mode)
            .with_msg_cst(cst)
            .with_opcode(value.opcode.into())
    }
}

impl From<&PeArithMsgHex> for PeArithMsgInsn {
    fn from(value: &PeArithMsgHex) -> Self {
        let msg_cst = match value.msg_mode() {
            IMM_CST => ImmId::Cst(value.msg_cst()),
            IMM_VAR => ImmId::new_var((value.msg_cst() >> 8) as u8, (value.msg_cst() & 0xff) as u8),
        };

        Self {
            dst_rid: RegId(value.dst_rid()),
            src_rid: RegId(value.src_rid()),
            msg_cst,
            opcode: Opcode::from(value.opcode()),
        }
    }
}

/// PeMem instructions
/// LD/St operation with one register and one memory slot
#[bitfield(u32)]
pub struct PeMemHex {
    #[bits(7)]
    rid: u8,
    #[bits(1)]
    _pad: u8,
    #[bits(2)]
    mode: u8,
    #[bits(16)]
    slot: u16,
    #[bits(6)]
    opcode: u8,
}

// Define encoding for mem_mode
const MEM_ADDR: u8 = 0x0;
const MEM_HEAP: u8 = 0x1;
const MEM_SRC: u8 = 0x2;
const MEM_DST: u8 = 0x3;

impl From<&PeMemInsn> for PeMemHex {
    fn from(value: &PeMemInsn) -> Self {
        let (mode, slot) = match value.slot {
            MemId::Addr(ct_id) => (MEM_ADDR, ct_id.0),
            MemId::Heap { bid } => (MEM_HEAP, bid),
            MemId::Src { tid, bid } => (MEM_SRC, ((tid as u16) << 8) + bid as u16),
            MemId::Dst { tid, bid } => (MEM_DST, ((tid as u16) << 8) + bid as u16),
        };

        Self::new()
            .with_rid(value.rid.0)
            .with_mode(mode)
            .with_slot(slot)
            .with_opcode(value.opcode.into())
    }
}

impl From<&PeMemHex> for PeMemInsn {
    fn from(value: &PeMemHex) -> Self {
        let slot = if MEM_ADDR == value.mode() {
            MemId::Addr(crate::asm::CtId(value.slot()))
        } else if MEM_HEAP == value.mode() {
            MemId::Heap { bid: value.slot() }
        } else if MEM_SRC == value.mode() {
            MemId::Src {
                tid: (value.slot() >> 8) as u8,
                bid: (value.slot() & 0xff) as u8,
            }
        } else if MEM_DST == value.mode() {
            MemId::Dst {
                tid: (value.slot() >> 8) as u8,
                bid: (value.slot() & 0xff) as u8,
            }
        } else {
            panic!("Unsupported memory mode")
        };

        Self {
            rid: RegId(value.rid()),
            slot,
            opcode: Opcode::from(value.opcode()),
        }
    }
}

/// PePbs instructions
#[bitfield(u32)]
pub struct PePbsHex {
    #[bits(7)]
    dst_rid: u8,
    #[bits(7)]
    src_rid: u8,
    #[bits(12)]
    gid: u16,
    #[bits(6)]
    opcode: u8,
}

impl From<&PePbsInsn> for PePbsHex {
    fn from(value: &PePbsInsn) -> Self {
        Self::new()
            .with_dst_rid(value.dst_rid.0)
            .with_src_rid(value.src_rid.0)
            .with_gid(value.gid.0)
            .with_opcode(value.opcode.into())
    }
}
impl From<&PePbsHex> for PePbsInsn {
    fn from(value: &PePbsHex) -> Self {
        Self {
            dst_rid: RegId(value.dst_rid()),
            src_rid: RegId(value.src_rid()),
            gid: PbsGid(value.gid()),
            opcode: Opcode::from(value.opcode()),
        }
    }
}

/// PeSync instructions
#[bitfield(u32)]
pub struct PeSyncHex {
    #[bits(26)]
    sid: u32,
    #[bits(6)]
    opcode: u8,
}
impl From<&PeSyncInsn> for PeSyncHex {
    fn from(value: &PeSyncInsn) -> Self {
        Self::new()
            .with_sid(value.sid.0)
            .with_opcode(value.opcode.into())
    }
}
impl From<&PeSyncHex> for PeSyncInsn {
    fn from(value: &PeSyncHex) -> Self {
        Self {
            sid: SyncId(value.sid()),
            opcode: Opcode::from(value.opcode()),
        }
    }
}
