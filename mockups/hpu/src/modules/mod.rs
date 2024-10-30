//! Hpu Simulation model

pub(crate) mod hbm;
pub(crate) use hbm::{HbmBank, HBM_BANK_NB};

// mod regfile;
pub(crate) mod regmap;
pub(crate) use regmap::{RegisterEvent, RegisterMap};

pub(crate) mod isc;
pub(crate) use isc::InstructionScheduler;

pub(crate) mod ucore;
pub(crate) use ucore::UCore;
