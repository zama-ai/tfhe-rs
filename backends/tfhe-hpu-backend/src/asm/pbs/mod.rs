use super::*;
mod pbs_macro;

use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumDiscriminants, EnumIter, EnumString};

use crate::pbs_lut;

pub const CMP_INFERIOR: usize = 0;
pub const CMP_EQUAL: usize = 1;
pub const CMP_SUPERIOR: usize = 2;

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct DigitParameters {
    pub msg_w: usize,
    pub carry_w: usize,
}

impl From<ArchProperties> for DigitParameters {
    fn from(value: ArchProperties) -> Self {
        Self {
            msg_w: value.msg_w,
            carry_w: value.carry_w,
        }
    }
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
#[enum_dispatch(Pbs)]
pub trait PbsLut {
    fn name(&self) -> &'static str;
    fn gid(&self) -> usize;
    fn eval(&self, params: &DigitParameters, val: usize) -> usize;
    fn degree(&self, params: &DigitParameters, deg: usize) -> usize;
}

/// Use enum dispatch for ease of writing and code reabability.
/// This enable to implement the targeted trait for each Lut and hide the matching logic over the
/// enum. It's not the best solution but it enhance the code locality.
#[enum_dispatch]
#[derive(Debug, Clone, Copy, EnumIter, EnumDiscriminants)]
#[strum_discriminants(
    name(PbsName),
    derive(Serialize, Deserialize, EnumIter, EnumString, Display)
)]
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub enum Pbs {
    None(PbsNone),
    MsgOnly(PbsMsgOnly),
    CarryOnly(PbsCarryOnly),
    CarryInMsg(PbsCarryInMsg),
    MultCarryMsg(PbsMultCarryMsg),
    MultCarryMsgLsb(PbsMultCarryMsgLsb),
    MultCarryMsgMsb(PbsMultCarryMsgMsb),
    BwAnd(PbsBwAnd),
    BwOr(PbsBwOr),
    BwXor(PbsBwXor),
    CmpSign(PbsCmpSign),
    CmpReduce(PbsCmpReduce),
    CmpGt(PbsCmpGt),
    CmpGte(PbsCmpGte),
    CmpLt(PbsCmpLt),
    CmpLte(PbsCmpLte),
    CmpEq(PbsCmpEq),
    CmpNeq(PbsCmpNeq),
}

/// Use for easy convertion between CLI arg and real IOp
impl From<PbsName> for Pbs {
    fn from(value: PbsName) -> Self {
        let pbs = Self::iter().find(|lut| lut.name() == value.to_string());
        pbs.unwrap()
    }
}

impl Pbs {
    pub fn from_gid(gid: usize) -> Self {
        for pbs in Self::iter() {
            if pbs.gid() == gid {
                return pbs;
            }
        }
        panic!("Error: Unmatched Pbs Gid {}", gid);
    }
}

// With help of macro define required PbsLut
pbs_lut!("None" => 0 [
    |_params: &DigitParameters, val | val,
    |_params: &DigitParameters, deg| deg,
]);

pbs_lut!("MsgOnly" => 1 [
    |params: &DigitParameters, val | val & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]);

pbs_lut!("CarryOnly" => 2 [
    |params: &DigitParameters, val | val & params.carry_mask(),
    |params: &DigitParameters, _deg| params.carry_mask(),
]);

pbs_lut!("CarryInMsg" => 3 [
    |params: &DigitParameters, val | (val & params.carry_mask()) >> params.msg_w,
    |params: &DigitParameters, _deg| params.msg_mask(),
]);

pbs_lut!("MultCarryMsg" => 4 [
    |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) & params.data_mask(),
    |params: &DigitParameters, _deg| params.data_mask(),
]);
pbs_lut!("MultCarryMsgLsb" => 5 [
    |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]);
pbs_lut!("MultCarryMsgMsb" => 6 [
    |params: &DigitParameters, val | ((((val & params.carry_mask()) >> params.msg_w) * (val & params.msg_mask())) >> params.msg_w) & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]);

pbs_lut!("BwAnd" => 7 [
    |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) & (val & params.msg_mask())) & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]);
pbs_lut!("BwOr" => 8 [
    |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) | (val & params.msg_mask())) & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]);
pbs_lut!("BwXor" => 9 [
    |params: &DigitParameters, val | (((val & params.carry_mask()) >> params.msg_w) ^ (val & params.msg_mask())) & params.msg_mask(),
    |params: &DigitParameters, _deg| params.msg_mask(),
]);

pbs_lut!("CmpSign" => 10 [
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
]);
pbs_lut!("CmpReduce" => 11 [
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
]);

pbs_lut!("CmpGt" => 12 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_SUPERIOR => 1,
        _ => 0,
    },
    |_params: &DigitParameters, _deg| 1,
]);
pbs_lut!("CmpGte" => 13 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_SUPERIOR | CMP_EQUAL => 1,
        _ => 0,
    },
    |_params: &DigitParameters, _deg| 1,
]);
// Could be merge with Gt/Gte
pbs_lut!("CmpLt" => 14 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_INFERIOR => 1,
        _ => 0,
    },
    |_params: &DigitParameters, _deg| 1,
]);
pbs_lut!("CmpLte" => 15 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_INFERIOR | CMP_EQUAL => 1,
        _ => 0,
    },
    |_params: &DigitParameters, _deg| 1,
]);
pbs_lut!("CmpEq" => 16 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_EQUAL => 1,
        _ => 0,
    },
    |_params: &DigitParameters, _deg| 1,
]);
pbs_lut!("CmpNeq" => 17 [
    |params: &DigitParameters, val | match val & params.msg_mask() {
        CMP_EQUAL => 0,
        _ => 1,
    },
    |_params: &DigitParameters, _deg| 1,
]);
