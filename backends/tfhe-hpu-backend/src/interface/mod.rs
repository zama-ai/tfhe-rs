mod cluster;
pub use cluster::HpuClusterWrapped;
mod cmd;
mod node;
use std::sync::Arc;

pub use cmd::{HpuCmd, HpuImm};
mod config;
mod device;
mod memory;
pub mod rtl;
mod variable;

#[cfg(feature = "io-dump")]
pub mod io_dump;

use thiserror::Error;

// Publicly export some types
pub const ACKQ_EMPTY: u32 = 0xdeadc0de;
pub const FW_TABLE_ENTRY: usize = 128;
pub use config::{BoardConfig, FFIMode, HpuConfig, QueueConfig, ShellString};
pub use device::HpuDevice;
pub use memory::page_align;
pub use variable::HpuVarWrapped;

use crate::prelude::HpuParameters;

/// Common error type exposed to user
#[derive(Error, Clone, Debug)]
pub enum HpuError {
    // Recoreverable errors
    #[error("Couldn't sync yet. Operation is pending")]
    SyncPending(variable::HpuVarWrapped),
}

/// Error related to Hpu creation
#[derive(Error, Clone, Debug)]
pub enum HpuInstError {
    // Invalid parameters, since all Hpu in a HpuDevice work together, they must have same
    // parameters set
    #[error("Instanciated HpuNode have at least two distinct parameters [A: {0:?}, B: {1:?}]")]
    InvalidParams(Arc<HpuParameters>, Arc<HpuParameters>),
    #[error("Instanciate an Empty HpuDevice. Device must contains at least one node")]
    EmptyDevice,
}
