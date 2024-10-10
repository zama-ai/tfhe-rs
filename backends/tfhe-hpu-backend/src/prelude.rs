/// Load entities and type related stuff
pub use super::entities::*;

/// Export Hw_hpu for asm definition
pub use super::asm as hpu_asm;

/// Load Hw-interface stuff
/// Warn: Enabling this feature required xrt for build and run
pub use super::interface::{HpuConfig, HpuDevice, HpuError, HpuVarWrapped, ACKQ_EMPTY};

#[cfg(feature = "io-dump")]
/// Expose io_dump init function
pub use super::interface::io_dump::set_hpu_io_dump;

#[cfg(not(feature = "hw-xrt"))]
/// Expose simulation traits for extern implementation
pub use super::ffi::sim::HpuOps;
