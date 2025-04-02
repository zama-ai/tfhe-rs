pub mod arg;
mod dop_macro;
pub mod field;
pub mod fmt;
mod opcode;
pub mod pbs_macro;

use lazy_static::lazy_static;
use std::collections::HashMap;

use crate::{dop, impl_dop, impl_dop_parser};
pub use arg::{FromAsm, IsFlush, ParsingError, ToAsm, ToFlush};
pub use field::{
    ImmId, MemId, MulFactor, PbsGid, PeArithInsn, PeArithMsgInsn, PeMemInsn, PePbsInsn, PeSyncInsn,
    RegId, SyncId,
};
pub use fmt::{
    DOpRawHex, DOpRepr, PeArithHex, PeArithMsgHex, PeMemHex, PePbsHex, PeSyncHex, ToHex,
};
pub use opcode::{DOpType, Opcode};

dop!(
    // Arith operation
    ["ADD", opcode::Opcode::ADD(), PeArithInsn],
    ["SUB", opcode::Opcode::SUB(), PeArithInsn],
    ["MAC", opcode::Opcode::MAC(), PeArithInsn{mul_factor}],

    // ArithMsg operation
    ["ADDS", opcode::Opcode::ADDS(), PeArithMsgInsn],
    ["SUBS", opcode::Opcode::SUBS(), PeArithMsgInsn],
    ["SSUB", opcode::Opcode::SSUB(), PeArithMsgInsn],
    ["MULS", opcode::Opcode::MULS(), PeArithMsgInsn],

    // Ld/st operation
    ["LD", opcode::Opcode::LD(), PeMemInsn{ld}],
    ["ST", opcode::Opcode::ST(), PeMemInsn{st}]

    // Pbs operation
    ["PBS", opcode::Opcode::PBS(1), PePbsInsn, "_F"],
    ["PBS_ML2", opcode::Opcode::PBS(2), PePbsInsn, "_F"],
    ["PBS_ML4", opcode::Opcode::PBS(4), PePbsInsn, "_F"],
    ["PBS_ML8", opcode::Opcode::PBS(8), PePbsInsn, "_F"],

    // Pbs flush operation
    ["PBS_F", opcode::Opcode::PBS_F(1), PePbsInsn],
    ["PBS_ML2_F", opcode::Opcode::PBS_F(2), PePbsInsn],
    ["PBS_ML4_F", opcode::Opcode::PBS_F(4), PePbsInsn],
    ["PBS_ML8_F", opcode::Opcode::PBS_F(8), PePbsInsn],

    // Sync operation
    ["SYNC", opcode::Opcode::SYNC(), PeSyncInsn],
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

    pub fn total_width(&self) -> usize {
        self.msg_w + self.carry_w
    }
}

/// Base trait to depict an Pbs function
/// Provides a set of method to reason about pbs
#[enum_dispatch]
pub trait PbsLut {
    fn name(&self) -> &'static str;
    fn gid(&self) -> PbsGid;
    fn lut_nb(&self) -> u8;
    fn lut_lg(&self) -> u8;
    fn fn_at(&self, pos: usize, params: &DigitParameters, val: usize) -> usize;
    fn deg_at(&self, pos: usize, params: &DigitParameters, deg: usize) -> usize;
    // Blanket implementation
    fn lut_msk(&self) -> usize {
        usize::MAX << self.lut_lg()
    }
}

use crate::{impl_pbs, pbs};
use enum_dispatch::enum_dispatch;
use pbs_macro::{CMP_EQUAL, CMP_INFERIOR, CMP_SUPERIOR};

pbs!(
["None" => 0 [
    @0 =>{
        |_params: &DigitParameters, val | val;
        |_params: &DigitParameters, deg| deg;
    }
]],
["MsgOnly" => 1 [
    @0 =>{
        |params: &DigitParameters, val | val & params.msg_mask();
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
["CarryOnly" => 2 [
    @0 =>{
        |params: &DigitParameters, val | val & params.carry_mask();
        |params: &DigitParameters, _deg| params.carry_mask();
    }
]],
["CarryInMsg" => 3 [
    @0 =>{
        |params: &DigitParameters, val | (val & params.carry_mask()) >> params.msg_w;
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]]
["MultCarryMsg" => 4 [
    @0 =>{
        |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) & params.data_mask();
        |params: &DigitParameters, _deg| params.data_mask();
    }
]],
["MultCarryMsgLsb" => 5 [
    @0 =>{
        |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) & params.msg_mask();
        |params: &DigitParameters, _deg| params.msg_mask();
    },
]],
["MultCarryMsgMsb" => 6 [
    @0 =>{
        |params: &DigitParameters, val | ((((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) >> params.msg_w) & params.msg_mask();
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
["BwAnd" => 7 [
    @0 =>{
        |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) & (val & params.msg_mask())) & params.msg_mask();
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
["BwOr" => 8 [
    @0 =>{
        |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) | (val & params.msg_mask())) & params.msg_mask();
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
["BwXor" => 9 [
    @0 =>{
        |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) ^ (val & params.msg_mask())) & params.msg_mask();
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],

["CmpSign" => 10 [
    @0 =>{
        |_params: &DigitParameters, val | {
            // Signed comparison with 0. Based on behavior of negacyclic function.
            // Example for Padding| 4bit digits (i.e 2msg2Carry)
            // 1|xxxx -> SignLut -> -1 -> 0|1111
            // x|0000 -> SignLut ->  0 -> 0|0000
            // 0|xxxx -> SignLut ->  1 -> 0|0001
            if val != 0 {1} else {0}
        };
        // WARN: in practice return value with padding that could encode -1, 0, 1
        //       But should always be follow by an add to reach back range 0, 1, 2
        //       To ease degree handling considered an output degree of 1 to obtain
        //       degree 2 after add
        // Not a perfect solution but the easiest to prevent degree error
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CmpReduce" => 11 [
    @0 =>{
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
        };
        |_params: &DigitParameters, _deg| 2;
    }
]]

["CmpGt" => 12 [
    @0 =>{
        |params: &DigitParameters, val | match val & params.msg_mask() {
            CMP_SUPERIOR => 1,
            _ => 0,
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CmpGte" => 13 [
    @0 =>{
        |params: &DigitParameters, val | match val & params.msg_mask() {
            CMP_SUPERIOR | CMP_EQUAL => 1,
            _ => 0,
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
// Could be merge with Gt/Gte
["CmpLt" => 14 [
    @0 =>{
        |params: &DigitParameters, val | match val & params.msg_mask() {
            CMP_INFERIOR => 1,
            _ => 0,
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CmpLte" => 15 [
    @0 =>{
        |params: &DigitParameters, val | match val & params.msg_mask() {
            CMP_INFERIOR | CMP_EQUAL => 1,
            _ => 0,
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CmpEq" => 16 [
    @0 =>{
        |params: &DigitParameters, val | match val & params.msg_mask() {
            CMP_EQUAL => 1,
            _ => 0,
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CmpNeq" => 17 [
    @0 =>{
        |params: &DigitParameters, val | match val & params.msg_mask() {
            CMP_EQUAL => 0,
            _ => 1,
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["ManyGenProp" => 18 [ // Turns carry save into a generate/propagate pair and message with manyLUT
    @0 =>{
        |params: &DigitParameters, val| { val & params.msg_mask()};
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |params: &DigitParameters, val| {
               ((val & params.carry_mask()) >> (params.msg_w)) << 1|       // Generate
               (((val & params.msg_mask()) == params.msg_mask()) as usize) // Propagate
           };
        |_params: &DigitParameters, _deg| 3;
    }
]],
["ReduceCarry2" => 19 [ // Reduces a carry propagation add to two bits from an
                        // input in which the carry is in the second bit.
    @0 =>{
        |_params: &DigitParameters, val | {
            let carry = val >> 2;
            let prop = (val & 3 == 3) as usize;
            (carry << 1) | prop
       };
        |_params: &DigitParameters, _deg| 3;
    }
]],
["ReduceCarry3" => 20 [ // Reduces a carry propagation add to two bits from an
                        // input in which the carry is in the third bit.
    @0 =>{
        |_params: &DigitParameters, val | {
            let carry = val >> 3;
            let prop = (val & 7 == 7) as usize;
            (carry << 1) | prop
       };
        |_params: &DigitParameters, _deg| 3;
    }
]],
["ReduceCarryPad" => 21 [ // Reduces a carry propagation add to two bits from an
                          // input in which the carry is in the padding bit.
    @0 =>{
        |params: &DigitParameters, val | {
            if val == params.data_mask() {
                0
            } else {
                params.raw_mask()
            }
       };
        |params: &DigitParameters, _deg| params.raw_mask();
    }
]],
["GenPropAdd" => 22 [ // Adds a generate/propagate pair with a message modulus message
    @0 =>{
        |params: &DigitParameters, val | {
           let lhs =  val & params.msg_mask();
           let rhs = (val & params.carry_mask()) >> params.msg_w;
           let rhs_gen = rhs >> 1;
           (lhs + rhs_gen) & params.msg_mask()
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],

["IfTrueZeroed" => 23 [ // Ct must contain CondCt in Carry and ValueCt in Msg. If condition it's *TRUE*, value ct is forced to 0
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & params.msg_mask();
           let cond = (val & params.carry_mask()) >> params.msg_w;
           if cond != 0 {0} else {value}
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
["IfFalseZeroed" => 24 [ // Ct must contain CondCt in Carry and ValueCt in Msg. If condition it's *FALSE*, value ct is forced to 0
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & params.msg_mask();
           let cond = (val & params.carry_mask()) >> params.msg_w;
           if cond != 0 {value} else {0}
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],

// Below Pbs are defined for Test only
["TestMany2" => 128 [
    @0 =>{
        |_params: &DigitParameters, val | val;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |_params: &DigitParameters, val | val +1;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
]],
["TestMany4" => 129 [
    @0 =>{
        |_params: &DigitParameters, val | val;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |_params: &DigitParameters, val | val +1;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @2 =>{
        |_params: &DigitParameters, val | val +2;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @3 =>{
        |_params: &DigitParameters, val | val +3;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
]],
["TestMany8" => 130 [
    @0 =>{
        |_params: &DigitParameters, val | val;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |_params: &DigitParameters, val | val +1;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @2 =>{
        |_params: &DigitParameters, val | val +2;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @3 =>{
        |_params: &DigitParameters, val | val +3;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @4 =>{
        |_params: &DigitParameters, val | val +4;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @5 =>{
        |_params: &DigitParameters, val | val +5;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @6 =>{
        |_params: &DigitParameters, val | val +6;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @7 =>{
        |_params: &DigitParameters, val | val +7;
        |params: &DigitParameters, _deg| params.msg_mask();
    },
]],
["ManyCarryMsg" => 26 [ // Turns carry save into carry and message with manyLUT
    @0 =>{
        |params: &DigitParameters, val| { val & params.msg_mask()};
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |params: &DigitParameters, val| { val >> params.msg_w };
        |params: &DigitParameters, _deg| ((1 << (params.carry_w - 1)) - 1);
    }
]],
["CmpGtMrg" => 27 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            let msg_field = val & params.msg_mask();

            match (carry_field, msg_field) {
                (CMP_SUPERIOR, _) |
                (CMP_EQUAL, CMP_SUPERIOR) => 1,
                _ => 0,
            }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CmpGteMrg" => 28 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            let msg_field = val & params.msg_mask();

            match (carry_field, msg_field) {
                (CMP_SUPERIOR, _) |
                (CMP_EQUAL, CMP_SUPERIOR) |
                (CMP_EQUAL, CMP_EQUAL) => 1,
                _ => 0,
            }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CmpLtMrg" => 29 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            let msg_field = val & params.msg_mask();

            match (carry_field, msg_field) {
                (CMP_INFERIOR, _) |
                (CMP_EQUAL, CMP_INFERIOR) => 1,
                _ => 0,
            }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CmpLteMrg" => 30 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            let msg_field = val & params.msg_mask();

            match (carry_field, msg_field) {
                (CMP_INFERIOR, _) |
                (CMP_EQUAL, CMP_INFERIOR) |
                (CMP_EQUAL, CMP_EQUAL) => 1,
                _ => 0,
            }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CmpEqMrg" => 31 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            let msg_field = val & params.msg_mask();

            match (carry_field, msg_field) {
                (CMP_EQUAL, CMP_EQUAL) => 1,
                _ => 0,
            }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CmpNeqMrg" => 32 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            let msg_field = val & params.msg_mask();

            match (carry_field, msg_field) {
                (CMP_EQUAL, CMP_EQUAL) => 0,
                _ => 1,
            }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
);

pub(crate) fn ceil_ilog2(value: &u8) -> u8 {
    (value.ilog2() + u32::from(!value.is_power_of_two())) as u8
}
