pub mod arg;
mod dop_macro;
pub mod field;
pub mod fmt;
mod opcode;
mod pbs_macro;

use lazy_static::lazy_static;
use std::collections::HashMap;

use crate::{dop, impl_dop, impl_dop_parser};
pub use arg::{FromAsm, ParsingError, ToAsm};
pub use field::{
    ImmId, MemId, MulFactor, Opcode, PbsGid, PeArithInsn, PeArithMsgInsn, PeMemInsn, PePbsInsn,
    PeSyncInsn, RegId, SyncId,
};
pub use fmt::{
    DOpRawHex, DOpRepr, PeArithHex, PeArithMsgHex, PeMemHex, PePbsHex, PeSyncHex, ToHex,
};

dop!(
    // Arith operation
    ["ADD", opcode::ADD, PeArithInsn],
    ["SUB", opcode::SUB, PeArithInsn],
    ["MAC", opcode::MAC, PeArithInsn{mul_factor}],

    // ArithMsg operation
    ["ADDS", opcode::ADDS, PeArithMsgInsn],
    ["SUBS", opcode::SUBS, PeArithMsgInsn],
    ["SSUB", opcode::SSUB, PeArithMsgInsn],
    ["MULS", opcode::MULS, PeArithMsgInsn],

    // Ld/st operation
    ["LD", opcode::LD, PeMemInsn{ld}],
    ["ST", opcode::ST, PeMemInsn{st}]

    // Pbs operation
    ["PBS", opcode::PBS, PePbsInsn],
    ["PBS_ML2", opcode::PBS_ML2, PePbsInsn],
    ["PBS_ML4", opcode::PBS_ML4, PePbsInsn],
    ["PBS_ML8", opcode::PBS_ML8, PePbsInsn],

    // Pbs flush operation
    ["PBS_F", opcode::PBS_F, PePbsInsn],
    ["PBS_ML2_F", opcode::PBS_ML2_F, PePbsInsn],
    ["PBS_ML4_F", opcode::PBS_ML4_F, PePbsInsn],
    ["PBS_ML8_F", opcode::PBS_ML8_F, PePbsInsn],

    // Sync operation
    ["SYNC", opcode::SYNC, PeSyncInsn],
);

#[derive(Debug, Clone, Copy)]
pub struct DigitParameters {
    pub msg_w: usize,
    pub carry_w: usize,
}

impl DigitParameters {
    /// Msg field only
    pub fn msg_mask(&self) -> usize {
        (1 << self.msg_w) - 1
    }
    /// Carry field only
    pub fn carry_mask(&self) -> usize {
        ((1 << (self.carry_w)) - 1) << self.msg_w
    }
    /// Carry field only
    pub fn padding_mask(&self) -> usize {
        1 << (self.carry_w + self.msg_w)
    }

    /// carry + msg fields only
    pub fn data_mask(&self) -> usize {
        self.carry_mask() | self.msg_mask()
    }
    /// Padding + carry + msg fields
    pub fn raw_mask(&self) -> usize {
        self.padding_mask() | self.data_mask()
    }

    /// Message range (used for neg operation)
    pub fn msg_range(&self) -> usize {
        1 << self.msg_w
    }

    /// Compute available linear operation based on carry_w/msg_w
    /// TODO: Find a proper way to have nu < carry_w (i.e ManyLutPbs case)
    pub fn nu(&self) -> usize {
        (self.carry_mask() + self.msg_mask()) / self.msg_mask()
    }
}

/// Base trait to depict an Pbs function
/// Provides a set of method to raison about pbs
#[enum_dispatch]
pub trait PbsLut {
    fn name(&self) -> &'static str;
    fn gid(&self) -> PbsGid;
    fn eval(&self, params: &DigitParameters, val: usize) -> usize;
    fn degree(&self, params: &DigitParameters, deg: usize) -> usize;
}

use crate::{impl_pbs, pbs};
use enum_dispatch::enum_dispatch;
use pbs_macro::{CMP_EQUAL, CMP_INFERIOR, CMP_SUPERIOR};

pbs!(
["None" => 0 [
    |_params: &DigitParameters, val | val,
    |_params: &DigitParameters, deg| deg,
]],
["MsgOnly" => 1 [
    |params: &DigitParameters, val | val & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]],
["CarryOnly" => 2 [
    |params: &DigitParameters, val | val & params.carry_mask(),
    |params: &DigitParameters, _deg| params.carry_mask(),
]],
["CarryInMsg" => 3 [
    |params: &DigitParameters, val | (val & params.carry_mask()) >> params.msg_w,
    |params: &DigitParameters, _deg| params.msg_mask(),
]]
["MultCarryMsg" => 4 [
    |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) & params.data_mask(),
    |params: &DigitParameters, _deg| params.data_mask(),
]],
["MultCarryMsgLsb" => 5 [
    |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]],
["MultCarryMsgMsb" => 6 [
    |params: &DigitParameters, val | ((((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) >> params.msg_w) & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]],
["BwAnd" => 7 [
    |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) & (val & params.msg_mask())) & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]],
["BwOr" => 8 [
    |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) | (val & params.msg_mask())) & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]],
["BwXor" => 9 [
    |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) ^ (val & params.msg_mask())) & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]],

["CmpSign" => 10 [
    |params: &DigitParameters, val | {
        // Signed comparaison with 0. Based on behavior of negacyclic function.
        // Example for Padding| 4bit digits (i.e 2msg2Carry)
        // 1|xxxx -> SignLut -> -1 -> 0|1111
        // x|0000 -> SignLut ->  0 -> 0|0000
        // 0|xxxx -> SignLut ->  1 -> 0|0001
        if val != 0 {
            if 0b1 ==  val >> (params.msg_w + params.carry_w) {
                params.data_mask()
            } else {
                1
            }
        } else {0}
    },
    // WARN: in practice return value with padding that could encode -1, 0, 1
    //       But should always be follow by an add to reach back range 0, 1, 2
    //       To ease degree handling considered an output degree of 1 to obtain
    //       degree 2 after add
    // Not a perfect solution but the easiest to prevent degree error
    |_params: &DigitParameters, _deg| 1,
]],
["CmpReduce" => 11 [
    |params: &DigitParameters, val | {
        // Carry contain MSB cmp result, msg LSB cmp result
        // Reduction is made from lsb to msb as follow
        // MSB      | LSB | Out
        // Inferior | x   | Inferior
        // Equal    | x   | x
        // Superior | x   | Superior
        let carry_field = (val & params.carry_mask()) >> params.msg_w;
        let msg_field = val & params.msg_mask();

        match (carry_field, msg_field) {
            (CMP_EQUAL, lsb_cmp) => lsb_cmp,
            _ => carry_field
        }
    },
    |_params: &DigitParameters, _deg| 2,
]]

["CmpGt" => 12 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_SUPERIOR => 1,
        _ => 0,
    },
    |_params: &DigitParameters, _deg| 1,
]],
["CmpGte" => 13 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_SUPERIOR | CMP_EQUAL => 1,
        _ => 0,
    },
    |_params: &DigitParameters, _deg| 1,
]],
// Could be merge with Gt/Gte
["CmpLt" => 14 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_INFERIOR => 1,
        _ => 0,
    },
    |_params: &DigitParameters, _deg| 1,
]],
["CmpLte" => 15 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_INFERIOR | CMP_EQUAL => 1,
        _ => 0,
    },
    |_params: &DigitParameters, _deg| 1,
]],
["CmpEq" => 16 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_EQUAL => 1,
        _ => 0,
    },
    |_params: &DigitParameters, _deg| 1,
]],
["CmpNeq" => 17 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_EQUAL => 0,
        _ => 1,
    },
    |_params: &DigitParameters, _deg| 1,
]],
);
