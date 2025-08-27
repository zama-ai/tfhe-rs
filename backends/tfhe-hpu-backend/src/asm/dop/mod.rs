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
    /// Padding bit only
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
    // TODO: Find a proper way to have nu < carry_w (i.e ManyLutPbs case)
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
        |params: &DigitParameters, val| {
               ((val & params.carry_mask()) >> (params.msg_w)) << 1|       // Generate
               (((val & params.msg_mask()) == params.msg_mask()) as usize) // Propagate
           };
        |_params: &DigitParameters, _deg| 3;
    },
    @1 =>{
        |params: &DigitParameters, val| { val & params.msg_mask()};
        |params: &DigitParameters, _deg| params.msg_mask();
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
        // This corresponds to the accumulated propagation status
        // of 4 consecutive blocks.
        // !! The padding bit is used.
        // +1 must be done after this PBS to retrieve the propagation status value.
        // 0_1111 => 0_0000 + 1 => 1 Propagate
        // 0_xxxx -> 1_1111 + 1 => 0 No carry
        // 1_xxxx -> 0_0001 + 1 => 2 Generate
    @0 =>{
        |params: &DigitParameters, val | {
            if val == params.data_mask() {
                0
            } else {
                params.raw_mask()
            }
       };
        |_params: &DigitParameters, _deg| 1;
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
["Ripple2GenProp" => 25 [ // Converts from Ripple carry to GenProp
    @0 =>{
        |params: &DigitParameters, val | {
           (val & params.msg_mask()) * 2
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
        |params: &DigitParameters, _deg| (1 << (params.carry_w - 1)) - 1;
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
["IsSome" => 33 [
    @0 =>{
        |_params: &DigitParameters, val | {
            if val != 0 { 1 } else { 0 }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CarryIsSome" => 34 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            if carry_field != 0 { 1 } else { 0 }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["CarryIsNone" => 35 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            if carry_field == 0 { 1 } else { 0 }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["MultCarryMsgIsSome" => 36 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_x_msg = (((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) & params.data_mask();
            if carry_x_msg != 0 { 1 } else { 0 }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["MultCarryMsgMsbIsSome" => 37 [
    @0 =>{
        |params: &DigitParameters, val | {
            let mul_msb = ((((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) >> params.msg_w) & params.msg_mask();
            if mul_msb != 0 { 1} else {0}
        };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
["IsNull" => 38 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            let msg_field = val & params.msg_mask();

            match (carry_field,msg_field) {
                (0,0) => 1,
                _ => 0,
            }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["IsNullPos1" => 39 [ // Output boolean at bit position 1 instead of 0
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            let msg_field = val & params.msg_mask();

            match (carry_field,msg_field) {
                (0,0) => 1 << 1,
                _ => 0,
            }
        };
        |_params: &DigitParameters, _deg| 1 << 1;
    }
]],
["NotNull" => 40 [
    @0 =>{
        |params: &DigitParameters, val | {
            let carry_field = (val & params.carry_mask()) >> params.msg_w;
            let msg_field = val & params.msg_mask();

            match (carry_field,msg_field) {
                (0,0) => 0,
                _ => 1,
            }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["MsgNotNull" => 41 [
    @0 =>{
        |params: &DigitParameters, val | {
            let msg_field = val & params.msg_mask();

            match msg_field {
                0 => 0,
                _ => 1,
            }
        };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["MsgNotNullPos1" => 42 [ // Return the null (0) or not null (1)
        // status of the msg part.
        // Put the result at position 1.
    @0 =>{
        |params: &DigitParameters, val | {
            let msg_field = val & params.msg_mask();

            match msg_field {
                0 => 0,
                _ => 1 << 1,
            }
        };
        |_params: &DigitParameters, _deg| 1 << 1;
    }
]],
["ManyMsgSplitShift1" => 43 [ // Use manyLUT : split msg in halves, inverse their position
        // in the message, and  output them separately.
    @0 =>{
        |params: &DigitParameters, val| {
                let lsb_size = params.msg_w.div_ceil(2);
                let msg_lsb = val & ((1 << lsb_size)-1);
                msg_lsb << lsb_size
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                ((1 << lsb_size)-1) << lsb_size
        };
    },
    @1 =>{
        |params: &DigitParameters, val| {
                let lsb_size = params.msg_w.div_ceil(2);
                (val & params.msg_mask()) >> lsb_size // msg_msb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                let msb_size = params.msg_w - lsb_size;
                (1 << msb_size)-1
        };
    }
]],
["SolvePropGroupFinal0" => 44 [ // Solve the propagation status of
        // of 4 blocks.
        // The input contains the sum of the propagate status
        // of (position + 1) blocks + the carry of previous group.
        // The result depends on the position to solve. Here we solve position 0.
        // The output value is then directly the carry.
        // 1/0 + [0]
        // 0x => NO_CARRY(0)
        // 1x => GENERATE(1)
    @0 =>{
        |_params: &DigitParameters, val | {
            let position = 0;
            let pos_w = position + 2;
            (val >> (pos_w-1)) & 1_usize // msb
       };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["SolvePropGroupFinal1" => 45 [ // Solve the propagation status of
        // of 4 blocks.
        // The input contains the sum of the propagate status
        // of (position + 1) blocks + the carry of previous group.
        // The result depends on the position to solve. Here we solve position 1.
        // The output value is then directly the carry.
        // 1/0 + + [0] + [1] << 1
        // 0xx => NO_CARRY(0)
        // 1xx => GENERATE(1)
    @0 =>{
        |_params: &DigitParameters, val | {
            let position = 1;
            let pos_w = position + 2;
            (val >> (pos_w-1)) & 1_usize // msb
       };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["SolvePropGroupFinal2" => 46 [ // Solve the propagation status of
        // of 4 blocks.
        // The input contains the sum of the propagate status
        // of (position + 1) blocks + the carry of previous group.
        // The result depends on the position to solve. Here we solve position 2.
        // The output value is then directly the carry.
        // 1/0 + + [0] + [1] << 1 + [2] << 2
        // 0xxx => NO_CARRY(0)
        // 1xxx => GENERATE(1)
    @0 =>{
        |_params: &DigitParameters, val | {
            let position = 2;
            let pos_w = position + 2;
            (val >> (pos_w-1)) & 1_usize // msb
       };
        |_params: &DigitParameters, _deg| 1;
    }
]],
["ExtractPropGroup0" => 47 [ // Extract propagation status and
        // set the value at the correct position location.
        // Here the position is 0.
    @0 =>{
        |params: &DigitParameters, val | {
            let position = 0;
            let msg   = val & params.msg_mask();
            let carry = (val >> params.msg_w) & 1_usize;
            if carry == 1 {
                2 << position // Generate
            } else if msg == params.msg_mask() {
                1 << position // Propagate
            } else {
                0 << position // No carry
            }
       };
        |_params: &DigitParameters, _deg| {
                let position = 0;
                2 << position
        };
    }
]],
["ExtractPropGroup1" => 48 [ // Extract propagation status and
        // set the value at the correct position location.
        // Here the position is 1.
    @0 =>{
        |params: &DigitParameters, val | {
            let position = 1;
            let msg   = val & params.msg_mask();
            let carry = (val >> params.msg_w) & 1_usize;
            if carry == 1 {
                2 << position // Generate
            } else if msg == params.msg_mask() {
                1 << position // Propagate
            } else {
                0 << position // No carry
            }
       };
        |_params: &DigitParameters, _deg| {
                let position = 1;
                2 << position
        };
    }
]],
["ExtractPropGroup2" => 49 [ // Extract propagation status and
        // set the value at the correct position location.
        // Here the position is 2.
    @0 =>{
        |params: &DigitParameters, val | {
            let position = 2;
            let msg   = val & params.msg_mask();
            let carry = (val >> params.msg_w) & 1_usize;
            if carry == 1 {
                2 << position // Generate
            } else if msg == params.msg_mask() {
                1 << position // Propagate
            } else {
                0 << position // No carry
            }
       };
        |_params: &DigitParameters, _deg| {
                let position = 2;
                2 << position
        };
    }
]],
["ExtractPropGroup3" => 50 [ // Extract propagation status and
        // set the value at the correct position location.
        // Here the position is 3.
    @0 =>{
        |params: &DigitParameters, val | {
            let position = 3;
            let msg   = val & params.msg_mask();
            let carry = (val >> params.msg_w) & 1_usize;
            if carry == 1 {
                2 << position // Generate
            } else if msg == params.msg_mask() {
                1 << position // Propagate
            } else {
                0 << position // No carry
            }
       };
        |_params: &DigitParameters, _deg| {
                let position = 3;
                2 << position
        };
    }
]],
["SolveProp" => 51 [ // Solve the propagation status.
        // 2 propagation status are stored in the input:
        // MSB : propagation to solved
        // LSB : neighbor's propagation
    @0 =>{
        |params: &DigitParameters, val | {
            let msb = (val >> params.msg_w) & params.msg_mask();
            let lsb = val & params.msg_mask();

            if msb == 1 { // Propagate
                lsb
            } else {
                msb
            }
       };
        |_params: &DigitParameters, _deg| 2;
    }
]],
["SolvePropCarry" => 52 [ // Solve the propagation status.
        // A propagation status and a carry are stored in the input:
        // Output a carry value.
        // MSB : propagation to solved
        // LSB : neighbor's carry bit
    @0 =>{
        |params: &DigitParameters, val | {
            let msb = (val >> params.msg_w) & params.msg_mask();
            let lsb = val & params.msg_mask();

            if msb == 1 { // Propagate
                lsb
            } else {
                msb >> 1 // Since generate equals 2. Here we want a carry output
            }
       };
        |_params: &DigitParameters, _deg| 2;
    }
]],
["SolveQuotient" => 53 [ // Solve the quotient of a division.
        // The input contains the sum of 4 bits, representing the comparison of current remaining
        // and the different multiples of the divider.
        // Note that the values form a multi-hot. Therefore, their sum
        // gives the value of the divider quotient, that corresponds to the remaining.
        // 'b0000 => 3 (sum = 0)
        // 'b1000 => 2 (sum = 1)
        // 'b1100 => 1 (sum = 2)
        // 'b1110 => 0 (sum = 3)
    @0 =>{
        |params: &DigitParameters, val | {
            let v = val & params.data_mask();

            match v {
                0  => 3,
                1  => 2,
                2  => 1,
                3  => 0,
                _  => 0,
                //_  => panic!("Unknown quotient value {}!",v) // should not end here
            }
       };
        |_params: &DigitParameters, _deg| 3;
    }
]],
["SolveQuotientPos1" => 54 [ // Solve the quotient of a division.
        // The input contains the sum of 4 bits, representing the comparison of current remaining
        // and the different multiples of the divider.
        // Note that the comparison stored in position 1 instead of 0.
        // Therefore the sum value is doubled.
        // Note that the values form a multi-hot. Therefore, their sum
        // gives the value of the divider quotient, that corresponds to the remaining.
        // 'b0000 => 3 (sum = 0*2)
        // 'b1000 => 2 (sum = 1*2)
        // 'b1100 => 1 (sum = 2*2)
        // 'b1110 => 0 (sum = 3*2)
    @0 =>{
        |params: &DigitParameters, val | {
            let v = val & params.data_mask();

            match v {
                0  => 3,
                2  => 2,
                4  => 1,
                6  => 0,
                _  => 0,
                //_  => panic!("Unknown quotient value {}!",v) // should not end here
            }
       };
        |_params: &DigitParameters, _deg| 3;
    }
]],
["IfPos1FalseZeroed" => 55 [ // Ct must contain CondCt in Carry bit 1 and ValueCt in Msg. If condition it's *FALSE*, value ct is forced to 0
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & params.msg_mask();
           let cond = (val >> (params.msg_w + 1)) & 1;
           if cond != 0 {value} else {0}
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
["IfPos1FalseZeroedMsgCarry1" => 56 [ // Ct must contain CondCt in Carry bit 1
        // and ValueCt in Msg + 1 carry bit. If condition it's *FALSE*, value ct is forced to 0
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & (params.msg_mask() * 2 + 1);
           let cond = (val >> (params.msg_w + 1)) & 1;
           if cond != 0 {value} else {0}
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],

// Shift related Pbs
["ShiftLeftByCarryPos0Msg" => 57 [ // Ct must contain shift amount only bit 1 considered
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & params.msg_mask();
           let shift = ((val & params.carry_mask()) >> params.msg_w) & 0x1;
           (value << shift) & params.msg_mask()
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
["ShiftLeftByCarryPos0MsgNext" => 58 [ // Ct must contain shift amount only bit 1 considered
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & params.msg_mask();
           let shift = ((val & params.carry_mask()) >> params.msg_w) & 0x1;
            ((value << shift) & params.carry_mask()) >> params.msg_w
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],

["ShiftRightByCarryPos0Msg" => 59 [ // Ct must contain shift amount only bit 1 considered
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & params.msg_mask();
           let shift = ((val & params.carry_mask()) >> params.msg_w) & 0x1;
           (value >> shift) & params.msg_mask()
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
["ShiftRightByCarryPos0MsgNext" => 60 [ // Ct must contain shift amount only bit 1 considered
    // NB: MsgNext with right shift is the content of blk at the right position (i.e. LSB side)
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & params.msg_mask();
           let shift = ((val & params.carry_mask()) >> params.msg_w) & 0x1;
           ((value << params.msg_w) >> shift) & params.msg_mask()
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
// If then zero with condition in Carry0 or Carry1
["IfPos0TrueZeroed" => 61 [ // Ct must contain CondCt in Carry[0] and ValueCt in Msg. If condition it's *TRUE*, value ct is forced to 0
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & params.msg_mask();
           let cond = ((val & params.carry_mask()) >> params.msg_w) & 0x1;
           if cond != 0 {0} else {value}
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
["IfPos0FalseZeroed" => 62 [ // Ct must contain CondCt in Carry[0] and ValueCt in Msg. If condition it's *FALSE*, value ct is forced to 0
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & params.msg_mask();
           let cond = ((val & params.carry_mask()) >> params.msg_w) & 0x1;
           if cond != 0 {value} else {0}
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
// If then zero with condition in Carry0 or Carry1
["IfPos1TrueZeroed" => 63 [ // Ct must contain CondCt in Carry[1] and ValueCt in Msg. If condition it's *TRUE*, value ct is forced to 0
    @0 =>{
        |params: &DigitParameters, val | {
           let value =  val & params.msg_mask();
           let cond = ((val & params.carry_mask()) >> params.msg_w) & 0x2;
           if cond != 0 {0} else {value}
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    }
]],
// NB: Lut IfPos1FalseZeroed already defined earlier
["ManyInv1CarryMsg" => 64 [ // Proceed Inv - ct
        // Extract message and carry using many LUT.
    @0 =>{
        |params: &DigitParameters, val | {
            let inv = 1;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value & params.msg_mask()
            }
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |params: &DigitParameters, val | {
            let inv = 1;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value >> params.msg_w
            }
       };
        |_params: &DigitParameters, _deg| 1;
    },
]],
["ManyInv2CarryMsg" => 65 [ // Proceed Inv - ct
        // Extract message and carry using many LUT.
    @0 =>{
        |params: &DigitParameters, val | {
            let inv = 2;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value & params.msg_mask()
            }
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |params: &DigitParameters, val | {
            let inv = 2;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value >> params.msg_w
            }
       };
        |_params: &DigitParameters, _deg| 1;
    },
]],

["ManyInv3CarryMsg" => 66 [ // Proceed Inv - ct
        // Extract message and carry using many LUT.
    @0 =>{
        |params: &DigitParameters, val | {
            let inv = 3;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value & params.msg_mask()
            }
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |params: &DigitParameters, val | {
            let inv = 3;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value >> params.msg_w
            }
       };
        |_params: &DigitParameters, _deg| 1;
    },
]],

["ManyInv4CarryMsg" => 67 [ // Proceed Inv - ct
        // Extract message and carry using many LUT.
    @0 =>{
        |params: &DigitParameters, val | {
            let inv = 4;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value & params.msg_mask()
            }
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |params: &DigitParameters, val | {
            let inv = 4;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value >> params.msg_w
            }
       };
        |_params: &DigitParameters, _deg| 1;
    },
]],

["ManyInv5CarryMsg" => 68 [ // Proceed Inv - ct
        // Extract message and carry using many LUT.
    @0 =>{
        |params: &DigitParameters, val | {
            let inv = 5;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value & params.msg_mask()
            }
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |params: &DigitParameters, val | {
            let inv = 5;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value >> params.msg_w
            }
       };
        |_params: &DigitParameters, _deg| 1;
    },
]],

["ManyInv6CarryMsg" => 69 [ // Proceed Inv - ct
        // Extract message and carry using many LUT.
    @0 =>{
        |params: &DigitParameters, val | {
            let inv = 6;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value & params.msg_mask()
            }
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |params: &DigitParameters, val | {
            let inv = 6;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value >> params.msg_w
            }
       };
        |_params: &DigitParameters, _deg| 1;
    },
]],

["ManyInv7CarryMsg" => 70 [ // Proceed Inv - ct
        // Extract message and carry using many LUT.
    @0 =>{
        |params: &DigitParameters, val | {
            let inv = 7;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value & params.msg_mask()
            }
       };
        |params: &DigitParameters, _deg| params.msg_mask();
    },
    @1 =>{
        |params: &DigitParameters, val | {
            let inv = 7;
            let mut value =  val & params.data_mask();
            if value > inv {
                0
            } else {
                value = inv - value;
                value >> params.msg_w
            }
       };
        |_params: &DigitParameters, _deg| 1;
    },
]],
["ManyMsgSplit" => 71 [ // Use manyLUT : split msg in halves
    @0 =>{
        |params: &DigitParameters, val| {
                let lsb_size = params.msg_w.div_ceil(2);
                val & ((1 << lsb_size)-1) // msg_lsb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                (1 << lsb_size)-1
        };
    },
    @1 =>{
        |params: &DigitParameters, val| {
                let lsb_size = params.msg_w.div_ceil(2);
                (val & params.msg_mask()) >> lsb_size // msg_msb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                let msb_size = params.msg_w - lsb_size;
                (1 << msb_size)-1
        };
    }
]],
["Manym2lPropBit1MsgSplit" => 72 [ // Use ManyLut
        // In carry part, contains the info if neighbor has a bit=1 (not null)
        // or not (null).
        // Propagate bits equal to 1 from msb to lsb.
        // Split resulting message part into 2. Put both in lsb.
    @0 =>{
        |params: &DigitParameters, val| {
                let mut c = val & params.carry_mask();
                let mut m = val & params.msg_mask();
                let mut exp = 0;
                // Expand from msb to lsb
                for idx in (0..params.msg_w).rev() {
                    let mut b = (m >> idx) & 1;
                    m &= (1 << idx)-1;
                    if c > 0 {b = 1;} // propagate to lsb
                    if b == 1 {c = 1;}
                    exp += b << idx;
                }
                let lsb_size = params.msg_w.div_ceil(2);
                exp & ((1 << lsb_size)-1) // msg_lsb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                (1 << lsb_size)-1
        };
    },
    @1 =>{
        |params: &DigitParameters, val| {
                let mut c = val & params.carry_mask();
                let mut m = val & params.msg_mask();
                let mut exp = 0;
                // Expand from msb to lsb
                for idx in (0..params.msg_w).rev() {
                    let mut b = (m >> idx) & 1;
                    m &= (1 << idx)-1;
                    if c > 0 {b = 1;} // propagate to lsb
                    if b == 1 {c = 1;}
                    exp += b << idx;
                }
                let lsb_size = params.msg_w.div_ceil(2);
                (exp & params.msg_mask()) >> lsb_size // msg_msb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                let msb_size = params.msg_w - lsb_size;
                (1 << msb_size)-1
        };
    }
]],
["Manym2lPropBit0MsgSplit" => 73 [ // Use ManyLut
        // In carry part, contains the info if neighbor has a bit=0 (not null)
        // or not (null).
        // Propagate bits equal to 0 from msb to lsb.
        // Split resulting message part into 2. Put both in lsb.
    @0 =>{
        |params: &DigitParameters, val| {
                let mut c = val & params.carry_mask();
                let mut m = val & params.msg_mask();
                let mut exp = 0;
                // Expand from msb to lsb
                for idx in (0..(params.msg_w)).rev() {
                    let mut b = (m >> idx) & 1;
                    m &= (1 << idx)-1;
                    if c > 0 {b = 0;} // propagate to lsb
                    if b == 0 {c = 1;}
                    exp += b << idx;
                }
                let lsb_size = params.msg_w.div_ceil(2);
                exp & ((1 << lsb_size)-1) // msg_lsb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                (1 << lsb_size)-1
        };
    },
    @1 =>{
        |params: &DigitParameters, val| {
                let mut c = val & params.carry_mask();
                let mut m = val & params.msg_mask();
                let mut exp = 0;
                // Expand from msb to lsb
                for idx in (0..(params.msg_w)).rev() {
                    let mut b = (m >> idx) & 1;
                    m &= (1 << idx)-1;
                    if c > 0 {b = 0;} // propagate to lsb
                    if b == 0 {c = 1;}
                    exp += b << idx;
                }
                let lsb_size = params.msg_w.div_ceil(2);
                (exp & params.msg_mask()) >> lsb_size // msg_msb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                let msb_size = params.msg_w - lsb_size;
                (1 << msb_size)-1
        };
    }
]],
["Manyl2mPropBit1MsgSplit" => 74 [ // Use ManyLut
        // In carry part, contains the info if neighbor has a bit=1 (not null)
        // or not (null).
        // Propagate bits equal to 1 from lsb to msb.
        // Split resulting message part into 2. Put both in lsb.
    @0 =>{
        |params: &DigitParameters, val| {
                let mut c = val & params.carry_mask();
                let mut m = val & params.msg_mask();
                let mut exp = 0;
                // Expand from lsb to msb
                for idx in 0..(params.msg_w) {
                    let mut b = m & 1;
                    m >>= 1;
                    if c > 0 {b = 1;} // propagate to msb
                    if b == 1 {c = 1;}
                    exp += b << idx;
                }
                let lsb_size = params.msg_w.div_ceil(2);
                exp & ((1 << lsb_size)-1) // msg_lsb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                (1 << lsb_size)-1
        };
    },
    @1 =>{
        |params: &DigitParameters, val| {
                let mut c = val & params.carry_mask();
                let mut m = val & params.msg_mask();
                let mut exp = 0;
                // Expand from lsb to msb
                for idx in 0..(params.msg_w) {
                    let mut b = m & 1;
                    m >>= 1;
                    if c > 0 {b = 1;} // propagate to msb
                    if b == 1 {c = 1;}
                    exp += b << idx;
                }
                let lsb_size = params.msg_w.div_ceil(2);
                (exp & params.msg_mask()) >> lsb_size // msg_msb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                let msb_size = params.msg_w - lsb_size;
                (1 << msb_size)-1
        };
    }
]],
["Manyl2mPropBit0MsgSplit" => 75 [ // Use ManyLut
        // In carry part, contains the info if neighbor has a bit=0 (not null)
        // or not (null).
        // Propagate bits equal to 0 from lsb to msb.
        // Split resulting message part into 2. Put both in lsb.
    @0 =>{
        |params: &DigitParameters, val| {
                let mut c = val & params.carry_mask();
                let mut m = val & params.msg_mask();
                let mut exp = 0;
                // Expand from lsb to msb
                for idx in 0..(params.msg_w) {
                    let mut b = m & 1;
                    m >>= 1;
                    if c > 0 {b = 0;} // propagate to msb
                    if b == 0 {c = 1;}
                    exp += b << idx;
                }
                let lsb_size = params.msg_w.div_ceil(2);
                exp & ((1 << lsb_size)-1) // msg_lsb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                (1 << lsb_size)-1
        };
    },
    @1 =>{
        |params: &DigitParameters, val| {
                let mut c = val & params.carry_mask();
                let mut m = val & params.msg_mask();
                let mut exp = 0;
                // Expand from lsb to msb
                for idx in 0..(params.msg_w) {
                    let mut b = m & 1;
                    m >>= 1;
                    if c > 0 {b = 0;} // propagate to msb
                    if b == 0 {c = 1;}
                    exp += b << idx;
                }
                let lsb_size = params.msg_w.div_ceil(2);
                (exp & params.msg_mask()) >> lsb_size // msg_msb
        };
        |params: &DigitParameters, _deg| {
                let lsb_size = params.msg_w.div_ceil(2);
                let msb_size = params.msg_w - lsb_size;
                (1 << msb_size)-1
        };
    }
]],
);

pub(crate) fn ceil_ilog2(value: &u8) -> u8 {
    (value.ilog2() + u32::from(!value.is_power_of_two())) as u8
}
