//!
//! Define hex encoding for a subset of known IOp
//! NB: Start from highest IOpcode to reduce the likelihood to clash with user custom operation on
//! extensions
//!
//! Current Opcode space could be viewed as follow:
//! | Range      | Categories                |
//! | ---------- | ------------------------- |
//! | 0x00.. 0x7f| User custom operations    |
//! | 0x80.. 0xff| Fw generated operations   |
//! | 0b1xyz_0000| x: Ct x Ct Operation      |
//! |            | !x: Ct x Imm Operation    |
//! |            | y!z: ARITH operations     |
//! |            | !yz: BW operations        |
//! |            | !y!z: CMP operations      |
//! | ---------- | ------------------------- |

pub const USER_RANGE_LB: u8 = 0x0;
pub const USER_RANGE_UB: u8 = 0x7f;

// Ct x Imm -------------------------------------------------------------------
pub const ADDS: u8 = 0xA0;
pub const SUBS: u8 = 0xA1;
pub const SSUB: u8 = 0xA2;
pub const MULS: u8 = 0xA3;

// Ct x Ct -------------------------------------------------------------------
// Arith operations
pub const ADD: u8 = 0xE0;
pub const SUB: u8 = 0xE1;
pub const MUL: u8 = 0xE2;

// BW operations
pub const BW_AND: u8 = 0xD0;
pub const BW_OR: u8 = 0xD1;
pub const BW_XOR: u8 = 0xD2;

// Cmp operations
pub const CMP_GT: u8 = 0xC0;
pub const CMP_GTE: u8 = 0xC1;
pub const CMP_LT: u8 = 0xC2;
pub const CMP_LTE: u8 = 0xC3;
pub const CMP_EQ: u8 = 0xC4;
pub const CMP_NEQ: u8 = 0xC5;
