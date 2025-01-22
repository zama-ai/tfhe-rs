//!
//! IOp definition

mod field;
pub use field::{HexParsingError, IOp, IOpcode, Immediat, Operand, OperandKind};
mod fmt;
pub use fmt::{IOpRepr, IOpWordRepr};
mod iop_macro;
pub mod opcode;

mod arg;
pub use arg::{AsmIOpcode, ParsingError};

// TODO find a proper way to let this runtime properties
pub const MSG_WIDTH: u8 = 2;
pub const CARRY_WIDTH: u8 = 2;

use crate::iop;
use arg::IOpAlias;
use lazy_static::lazy_static;
use std::collections::HashMap;
iop!(
     ["ADDS"   ,    opcode::ADDS , |1,1| -> 1],
     ["SUBS"   ,    opcode::SUBS , |1,1| -> 1],
     ["SSUB"   ,    opcode::SSUB , |1,1| -> 1],
     ["MULS"   ,    opcode::MULS , |1,1| -> 1],

     ["ADD"    ,     opcode::ADD , |2,0| -> 1],
     ["ADDK"   ,     opcode::ADDK, |2,0| -> 1],
     ["SUB"    ,     opcode::SUB , |2,0| -> 1],
     ["SUBK"   ,     opcode::SUBK, |2,0| -> 1],
     ["MUL"    ,     opcode::MUL , |2,0| -> 1],

     ["BW_AND" ,  opcode::BW_AND , |2,0| -> 1],
     ["BW_OR"  ,   opcode::BW_OR , |2,0| -> 1],
     ["BW_XOR" ,  opcode::BW_XOR , |2,0| -> 1],

     ["CMP_GT" ,  opcode::CMP_GT , |2,0| -> 1],
     ["CMP_GTE", opcode::CMP_GTE , |2,0| -> 1],
     ["CMP_LT" ,  opcode::CMP_LT , |2,0| -> 1],
     ["CMP_LTE", opcode::CMP_LTE , |2,0| -> 1],
     ["CMP_EQ" ,  opcode::CMP_EQ , |2,0| -> 1],
     ["CMP_NEQ", opcode::CMP_NEQ , |2,0| -> 1],
);
