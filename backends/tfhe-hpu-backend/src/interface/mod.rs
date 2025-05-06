mod backend;
mod cmd;
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
pub use config::{BoardConfig, FFIMode, HpuConfig, ShellString};
pub use device::HpuDevice;
pub use memory::page_align;
pub use variable::HpuVarWrapped;

/// Common error type reported by Hpu
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub(crate) enum HpuInternalError {
    #[error("Couldn't sync uninitialized variable.")]
    UninitData,

    // Recoreverable errors
    #[error("Couldn't sync yet. Operation is pending")]
    OperationPending,
}

/// Common error type exposed to user
#[derive(Error, Clone, Debug)]
pub enum HpuError {
    // Recoreverable errors
    #[error("Couldn't sync yet. Operation is pending")]
    SyncPending(variable::HpuVarWrapped),
}
