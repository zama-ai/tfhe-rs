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

use crate::asm::iop::IOp;
use crate::asm::ArchProperties;

use enum_dispatch::enum_dispatch;
use strum_macros::{EnumDiscriminants, EnumString};

/// Fw trait abstraction
/// Use to handle Fw implemantion in an abstract way
#[enum_dispatch(AvlblFw)]
pub trait Fw {
    /// Expand a stream of IOp into a stream of DOp
    fn expand(&mut self, arch: &ArchProperties, ops: &[IOp]) -> Program;
}

/// Gather available Fw in a enum for selection at runtime by user
#[enum_dispatch]
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
