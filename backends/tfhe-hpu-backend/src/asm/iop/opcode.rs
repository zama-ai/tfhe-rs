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
//! | ---------- | ------------------------- |

pub const USER_RANGE_LB: u8 = 0x0;
pub const USER_RANGE_UB: u8 = 0x7f;

// Ct x Imm -------------------------------------------------------------------
// Arith operations
pub const ADDS: u8 = 0xA0;
pub const SUBS: u8 = 0xA1;
pub const SSUB: u8 = 0xA2;
pub const MULS: u8 = 0xA3;
pub const DIVS: u8 = 0xA4;
pub const MODS: u8 = 0xA5;
// Overflowing Arith
pub const OVF_ADDS: u8 = 0xA8;
pub const OVF_SUBS: u8 = 0xA9;
pub const OVF_SSUB: u8 = 0xAA;
pub const OVF_MULS: u8 = 0xAB;

// Rotation and Shift
pub const SHIFTS_R: u8 = 0xAC;
pub const SHIFTS_L: u8 = 0xAD;
pub const ROTS_R: u8 = 0xAE;
pub const ROTS_L: u8 = 0xAF;

// Ct x Ct -------------------------------------------------------------------
// Arith operations
pub const ADD: u8 = 0xE0;
pub const SUB: u8 = 0xE2;
pub const MUL: u8 = 0xE4;
pub const DIV: u8 = 0xE5;
pub const MOD: u8 = 0xE6;

// Overflowing Arith
pub const OVF_ADD: u8 = 0xE8;
pub const OVF_SUB: u8 = 0xEA;
pub const OVF_MUL: u8 = 0xEC;

// BW operations
pub const BW_AND: u8 = 0xD0;
pub const BW_OR: u8 = 0xD1;
pub const BW_XOR: u8 = 0xD2;

// Rotation and shift
pub const SHIFT_R: u8 = 0xDC;
pub const SHIFT_L: u8 = 0xDD;
pub const ROT_R: u8 = 0xDE;
pub const ROT_L: u8 = 0xDF;

// Cmp operations
pub const CMP_GT: u8 = 0xC0;
pub const CMP_GTE: u8 = 0xC1;
pub const CMP_LT: u8 = 0xC2;
pub const CMP_LTE: u8 = 0xC3;
pub const CMP_EQ: u8 = 0xC4;
pub const CMP_NEQ: u8 = 0xC5;

// Ternary operations
// IfThenZero -> Select or force to 0
// Take 1Ct and a Boolean Ct as input
pub const IF_THEN_ZERO: u8 = 0xCA;
// IfThenElse -> Select operation
// Take 2Ct and a Boolean Ct as input
pub const IF_THEN_ELSE: u8 = 0xCB;

// Custom algorithm
// ERC20 -> Found xfer algorithm
// 2Ct <- func(3Ct)
pub const ERC_20: u8 = 0x80;

// Count bits
pub const COUNT0: u8 = 0x81;
pub const COUNT1: u8 = 0x82;
pub const ILOG2: u8 = 0x83;
pub const LEAD0: u8 = 0x84;
pub const LEAD1: u8 = 0x85;
pub const TRAIL0: u8 = 0x86;
pub const TRAIL1: u8 = 0x87;

// SIMD for maximum throughput
pub const ADD_SIMD: u8 = 0xF0;
pub const ERC_20_SIMD: u8 = 0xF1;
//
// Utility operations
// Used to handle real clone of ciphertext already uploaded in the Hpu memory
pub const MEMCPY: u8 = 0xFF;
