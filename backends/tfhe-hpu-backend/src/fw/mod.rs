//!
//! Top level abstraction of a Firmware
//!
//! Provide two concrete implementation of those traits
//! * DigitOperations (DOp)
//! * IntegerOperarions (IOp)

// pub mod impl;
pub mod program;
pub use program::Program;
pub mod fw_impl;
pub mod metavar;

use crate::asm;

use enum_dispatch::enum_dispatch;
use strum_macros::{EnumDiscriminants, EnumString};

/// Parameters that reflect the targeted architecture
/// Used to generate fw customized for the targeted architecture
#[derive(Debug, Clone)]
pub struct FwParameters {
    pub regs: usize,
    pub heap_size: usize,
    pub pbs_batch_w: usize,

    pub msg_w: usize,
    pub carry_w: usize,
    pub nu: usize,
    pub integer_w: usize,
}

impl FwParameters {
    pub fn blk_w(&self) -> usize {
        self.integer_w.div_ceil(self.msg_w)
    }
}

impl From<FwParameters> for asm::DigitParameters {
    fn from(value: FwParameters) -> Self {
        Self {
            msg_w: value.msg_w,
            carry_w: value.carry_w,
        }
    }
}

/// Fw trait abstraction
/// Use to handle Fw implemantion in an abstract way
#[enum_dispatch]
pub trait Fw {
    /// Expand a program of IOp into a program of DOp
    fn expand(&mut self, arch: &FwParameters, iopcode: &asm::AsmIOpcode) -> asm::Program<asm::DOp>;
}

/// Gather available Fw in a enum for selection at runtime by user
#[enum_dispatch(Fw)]
#[derive(EnumDiscriminants)]
#[strum_discriminants(name(FwName))]
#[strum_discriminants(derive(EnumString))]
pub enum AvlblFw {
    Ilp(fw_impl::ilp::Ilp),
}

impl AvlblFw {
    pub fn new(kind: &FwName) -> Self {
        match kind {
            FwName::Ilp => Self::Ilp(Default::default()),
        }
    }
}
