//!
//! Define binary format encoding of instructions
//! Rely on `deku` crate to define bit-accurate insn format and enable serde to byte-stream
//!
//! Also propose a `trait` that should be implemented by Op to be enable conversion between Op <->
//! byte-stream

use deku::prelude::*;

// Binary encoding of DOp
// See PeArithInsn/PeArithMsgInsn/PeMemInsn/PePbsInsn for subformat definition
pub mod dopcode {
    // Arith
    pub const ADD: u8 = 0b00_0001;
    pub const SUB: u8 = 0b00_0010;
    pub const MAC: u8 = 0b00_0101;

    // ArithMsg
    pub const ADDS: u8 = 0b00_1001;
    pub const SUBS: u8 = 0b00_1010;
    pub const SSUB: u8 = 0b00_1011;
    pub const MULS: u8 = 0b00_0100;

    //Sync
    pub const SYNC: u8 = 0b01_0000;

    // LD/ST and templated LD/ST
    pub const LD: u8 = 0b10_0000;
    pub const TLDA: u8 = 0b10_1000;
    pub const TLDB: u8 = 0b10_0100;
    pub const TLDH: u8 = 0b10_0010;
    pub const ST: u8 = 0b10_0001;
    pub const TSTD: u8 = 0b10_1001;
    pub const TSTH: u8 = 0b10_0101;

    // PBS
    pub const PBS: u8 = 0b11_0000;
    pub const PBS_F: u8 = 0b11_0001;
}

/// Opcode
/// Used to define instruction and associated format
#[derive(Debug, Clone, Copy, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub(super) struct Opcode(#[deku(bits = "6")] pub(super) u8);

/// Top-level type used to define an DOp
/// Contain the opcode and an enum with associated format
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
pub struct DOp {
    pub(super) opcode: Opcode,
    #[deku(ctx = "*opcode")]
    pub(super) fields: DOpField,
}

/// Match opcode with instruction name and format
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "opcode: Opcode", id = "opcode")]
#[allow(non_camel_case_types)]
pub(super) enum DOpField {
    #[deku(id = "Opcode(dopcode::ADD)")]
    ADD(PeArithInsn),
    #[deku(id = "Opcode(dopcode::SUB)")]
    SUB(PeArithInsn),
    #[deku(id = "Opcode(dopcode::MAC)")]
    MAC(PeArithInsn),

    #[deku(id = "Opcode(dopcode::ADDS)")]
    ADDS(PeArithMsgInsn),
    #[deku(id = "Opcode(dopcode::SUBS)")]
    SUBS(PeArithMsgInsn),
    #[deku(id = "Opcode(dopcode::SSUB)")]
    SSUB(PeArithMsgInsn),
    #[deku(id = "Opcode(dopcode::MULS)")]
    MULS(PeArithMsgInsn),

    #[deku(id = "Opcode(dopcode::SYNC)")]
    SYNC(PeSyncInsn),

    #[deku(id = "Opcode(dopcode::LD)")]
    LD(PeMemInsn),
    #[deku(id = "Opcode(dopcode::TLDA)")]
    TLDA(PeMemInsn),
    #[deku(id = "Opcode(dopcode::TLDB)")]
    TLDB(PeMemInsn),
    #[deku(id = "Opcode(dopcode::TLDH)")]
    TLDH(PeMemInsn),
    #[deku(id = "Opcode(dopcode::ST)")]
    ST(PeMemInsn),
    #[deku(id = "Opcode(dopcode::TSTD)")]
    TSTD(PeMemInsn),
    #[deku(id = "Opcode(dopcode::TSTH)")]
    TSTH(PeMemInsn),

    #[deku(id = "Opcode(dopcode::PBS)")]
    PBS(PePbsInsn),
    #[deku(id = "Opcode(dopcode::PBS_F)")]
    PBS_F(PePbsInsn),
}

/// PeArith instructions
/// Pe arithmetics format specialized for MAC insn
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub(super) struct PeArithInsn {
    #[deku(bits = "5")]
    pub(super) mul_factor: u8,
    #[deku(bits = "7")]
    pub(super) src1_rid: u8,
    #[deku(bits = "7")]
    pub(super) src0_rid: u8,
    #[deku(bits = "7")]
    pub(super) dst_rid: u8,
}

/// PeaMsg instructions
/// Pe arithmetics format specialized for MAC insn
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub(super) struct PeArithMsgInsn {
    #[deku(bits = "12")]
    pub(super) msg_cst: u16,
    #[deku(bits = "7")]
    pub(super) src_rid: u8,
    #[deku(bits = "7")]
    pub(super) dst_rid: u8,
}

/// PeMem instructions
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub(super) struct PeMemInsn {
    #[deku(bits = "3")]
    pub(super) ct_ofst: u8,
    #[deku(bits = "16")]
    pub(super) cid: u16,
    #[deku(bits = "7")]
    pub(super) rid: u8,
}

/// PePbs instructions
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub(super) struct PePbsInsn {
    #[deku(bits = "12")]
    pub(super) gid: u32,
    #[deku(bits = "7")]
    pub(super) src_rid: u8,
    #[deku(bits = "7")]
    pub(super) dst_rid: u8,
}

/// PeSync instructions
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub(super) struct PeSyncInsn {
    #[deku(bits = "26")]
    pub(super) sid: u32,
}
