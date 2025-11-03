//!
//! Top level abstraction of a Firmware
//!
//! Provide two concrete implementation of those traits
//! * DigitOperations (DOp)
//! * IntegerOperations (IOp)

pub mod fw_impl;
pub mod isc_sim;
pub mod metavar;
pub mod program;
pub mod rtl;

use crate::asm;
use enum_dispatch::enum_dispatch;
use strum_macros::{EnumDiscriminants, EnumIter, EnumString, VariantNames};

/// Parameters that reflect the targeted architecture
/// Used to generate fw customized for the targeted architecture
#[derive(Debug, Clone)]
pub struct FwParameters {
    pub register: usize,
    pub isc_depth: usize,
    pub heap_size: usize,
    pub min_iop_size: usize,
    pub min_pbs_batch_w: usize,
    pub pbs_batch_w: usize,
    pub total_pbs_nb: usize,

    pub msg_w: usize,
    pub carry_w: usize,
    pub nu: usize,
    pub integer_w: usize,
    pub use_ipip: bool,
    pub kogge_cfg: String,
    pub pe_cfg: isc_sim::PeConfigStore,
    pub op_cfg: rtl::config::RtlCfg,
    pub cur_op_cfg: rtl::config::OpCfg,
    pub op_name: Option<String>,
}

impl FwParameters {
    pub fn blk_w(&self) -> usize {
        self.integer_w.div_ceil(self.msg_w)
    }

    pub fn max_msg(&self) -> usize {
        (1 << self.msg_w) - 1
    }

    pub fn max_val(&self) -> usize {
        (1 << (self.msg_w + self.carry_w)) - 1
    }

    pub fn set_op(&mut self, opname: &str) {
        self.op_name = Some(opname.into());
        self.cur_op_cfg = self.op_cfg.get(opname);
    }

    pub fn op_cfg(&self) -> rtl::config::OpCfg {
        self.cur_op_cfg
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
/// Use to handle Fw implementation in an abstract way
#[enum_dispatch]
pub trait Fw {
    /// Expand a program of IOp into a program of DOp
    fn expand(&self, params: &FwParameters, iopcode: &asm::AsmIOpcode) -> asm::Program<asm::DOp>;
}

/// Gather available Fw in a enum for selection at runtime by user
#[enum_dispatch(Fw)]
#[derive(EnumDiscriminants, VariantNames)]
#[strum_discriminants(name(FwName))]
#[strum_discriminants(derive(EnumIter))]
#[strum_discriminants(derive(EnumString))]
pub enum AvlblFw {
    Ilp(fw_impl::ilp::Ilp),
    Llt(fw_impl::llt::Llt),
    Demo(fw_impl::demo::Demo),
}

impl AvlblFw {
    pub fn new(kind: &FwName) -> Self {
        match kind {
            FwName::Ilp => Self::Ilp(Default::default()),
            FwName::Llt => Self::Llt(Default::default()),
            FwName::Demo => Self::Demo(Default::default()),
        }
    }
}
