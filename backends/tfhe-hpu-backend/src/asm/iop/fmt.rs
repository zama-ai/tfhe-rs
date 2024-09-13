//!
//! Define binary format encoding of instructions
//! Rely on `deku` crate to define bit-accurate insn format and enable serde to byte-stream
//!
//! Also propose a `trait` that should be implemented by Op to be enable conversion between Op <->
//! byte-stream

use deku::prelude::*;

// Binary encoding of IOp
// See PeArithInsn/PeArithMsgInsn/PeMemInsn/PePbsInsn for subformat definition
pub mod iopcode {
    // Ct x Imm
    pub const ADDS: u8 = 0x80;
    pub const SUBS: u8 = 0x81;
    pub const SSUB: u8 = 0x82;
    pub const MULS: u8 = 0x83;

    // Ct x Ct
    pub const ADD: u8 = 0x10;
    pub const SUB: u8 = 0x11;
    pub const MUL: u8 = 0x12;

    pub const BW_AND: u8 = 0x20;
    pub const BW_OR: u8 = 0x21;
    pub const BW_XOR: u8 = 0x22;

    pub const CMP_GT: u8 = 0x40;
    pub const CMP_GTE: u8 = 0x41;
    pub const CMP_LT: u8 = 0x42;
    pub const CMP_LTE: u8 = 0x43;
    pub const CMP_EQ: u8 = 0x44;
    pub const CMP_NEQ: u8 = 0x45;

    // Custom IOp used for validation/debug purpose
    // 4 LSB is used for custom iop id encoding
    pub const CUST_0: u8 = 0x30;
    pub const CUST_1: u8 = 0x31;
    pub const CUST_2: u8 = 0x32;
    pub const CUST_3: u8 = 0x33;
    pub const CUST_4: u8 = 0x34;
    pub const CUST_5: u8 = 0x35;
    pub const CUST_6: u8 = 0x36;
    pub const CUST_7: u8 = 0x37;
    pub const CUST_8: u8 = 0x38;
    pub const CUST_9: u8 = 0x39;
    pub const CUST_A: u8 = 0x3a;
    pub const CUST_B: u8 = 0x3b;
    pub const CUST_C: u8 = 0x3c;
    pub const CUST_D: u8 = 0x3d;
    pub const CUST_E: u8 = 0x3e;
    pub const CUST_F: u8 = 0x3f;

    pub const CUSTI_0: u8 = 0xa0;
    pub const CUSTI_1: u8 = 0xa1;
    pub const CUSTI_2: u8 = 0xa2;
    pub const CUSTI_3: u8 = 0xa3;
    pub const CUSTI_4: u8 = 0xa4;
    pub const CUSTI_5: u8 = 0xa5;
    pub const CUSTI_6: u8 = 0xa6;
    pub const CUSTI_7: u8 = 0xa7;
    pub const CUSTI_8: u8 = 0xa8;
    pub const CUSTI_9: u8 = 0xa9;
    pub const CUSTI_A: u8 = 0xaa;
    pub const CUSTI_B: u8 = 0xab;
    pub const CUSTI_C: u8 = 0xac;
    pub const CUSTI_D: u8 = 0xad;
    pub const CUSTI_E: u8 = 0xae;
    pub const CUSTI_F: u8 = 0xaf;

    // --> Controller config
    pub const CTL_WR: u8 = 0xc0;
    pub const CTL_RD: u8 = 0xc1;
}

/// Opcode
/// Used to define instruction and associated format
#[derive(Debug, Clone, Copy, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub(super) struct Opcode(#[deku(bits = "8")] pub(super) u8);

/// Top-level type used to define an IOp
/// Contain the opcode and an enum with associated format
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
pub struct IOp {
    pub(super) opcode: Opcode,
    #[deku(ctx = "*opcode")]
    pub(super) fields: IOpField,
}

/// Match opcode with instruction name and format
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "opcode: Opcode", id = "opcode")]
#[allow(non_camel_case_types)]
pub(super) enum IOpField {
    #[deku(id = "Opcode(iopcode::ADDS)")]
    ADDS(CtImmInsn),
    #[deku(id = "Opcode(iopcode::SUBS)")]
    SUBS(CtImmInsn),
    #[deku(id = "Opcode(iopcode::SSUB)")]
    SSUB(CtImmInsn),
    #[deku(id = "Opcode(iopcode::MULS)")]
    MULS(CtImmInsn),

    #[deku(id = "Opcode(iopcode::ADD)")]
    ADD(CtCtInsn),
    #[deku(id = "Opcode(iopcode::SUB)")]
    SUB(CtCtInsn),
    #[deku(id = "Opcode(iopcode::MUL)")]
    MUL(CtCtInsn),

    #[deku(id = "Opcode(iopcode::BW_AND)")]
    BW_AND(CtCtInsn),
    #[deku(id = "Opcode(iopcode::BW_OR)")]
    BW_OR(CtCtInsn),
    #[deku(id = "Opcode(iopcode::BW_XOR)")]
    BW_XOR(CtCtInsn),

    #[deku(id = "Opcode(iopcode::CMP_GT)")]
    CMP_GT(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CMP_GTE)")]
    CMP_GTE(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CMP_LT)")]
    CMP_LT(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CMP_LTE)")]
    CMP_LTE(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CMP_EQ)")]
    CMP_EQ(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CMP_NEQ)")]
    CMP_NEQ(CtCtInsn),

    // Custom CtxCt
    #[deku(id = "Opcode(iopcode::CUST_0)")]
    CUST_0(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_1)")]
    CUST_1(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_2)")]
    CUST_2(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_3)")]
    CUST_3(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_4)")]
    CUST_4(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_5)")]
    CUST_5(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_6)")]
    CUST_6(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_7)")]
    CUST_7(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_8)")]
    CUST_8(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_9)")]
    CUST_9(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_A)")]
    CUST_A(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_B)")]
    CUST_B(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_C)")]
    CUST_C(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_D)")]
    CUST_D(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_E)")]
    CUST_E(CtCtInsn),
    #[deku(id = "Opcode(iopcode::CUST_F)")]
    CUST_F(CtCtInsn),

    // Custom CtxImm
    #[deku(id = "Opcode(iopcode::CUSTI_0)")]
    CUSTI_0(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_1)")]
    CUSTI_1(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_2)")]
    CUSTI_2(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_3)")]
    CUSTI_3(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_4)")]
    CUSTI_4(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_5)")]
    CUSTI_5(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_6)")]
    CUSTI_6(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_7)")]
    CUSTI_7(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_8)")]
    CUSTI_8(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_9)")]
    CUSTI_9(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_A)")]
    CUSTI_A(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_B)")]
    CUSTI_B(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_C)")]
    CUSTI_C(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_D)")]
    CUSTI_D(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_E)")]
    CUSTI_E(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CUSTI_F)")]
    CUSTI_F(CtImmInsn),

    // Ublaze configuration command
    #[deku(id = "Opcode(iopcode::CTL_WR)")]
    CTL_WR(CtImmInsn),
    #[deku(id = "Opcode(iopcode::CTL_RD)")]
    CTL_RD(CtImmInsn),
}

/// Ct x Imm instructions
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub(super) struct CtImmInsn {
    #[deku(bits = "4")]
    pub(super) pad_0: u8,
    #[deku(bits = "2")]
    pub(super) src_ofst: u8,
    #[deku(bits = "2")]
    pub(super) dst_ofst: u8,
    #[deku(bits = "16")]
    pub(super) dst_cid: u16,

    #[deku(bits = "8")]
    pub(super) pad_1: u8,
    #[deku(bits = "8")]
    pub(super) imm_len: u8,
    #[deku(bits = "16")]
    pub(super) src_cid: u16,

    #[deku(count = "imm_len")]
    pub(super) imm_val: Vec<u32>,
}

/// Ct x Ct instructions
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub(super) struct CtCtInsn {
    #[deku(bits = "2")]
    pub(super) pad_0: u8,
    #[deku(bits = "2")]
    pub(super) src_0_ofst: u8,
    #[deku(bits = "2")]
    pub(super) src_1_ofst: u8,
    #[deku(bits = "2")]
    pub(super) dst_ofst: u8,
    #[deku(bits = "16")]
    pub(super) dst_cid: u16,

    #[deku(bits = "16")]
    pub(super) src_1_cid: u16,
    #[deku(bits = "16")]
    pub(super) src_0_cid: u16,
}
