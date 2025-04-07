/// Load entities and type related stuff
pub use super::entities::*;

/// Export Hw_hpu for asm definition
pub use super::asm as hpu_asm;

/// Export hw_regmap.
/// Prevent version mismatch between user code and backend
pub use hw_regmap as hpu_regmap;

/// Load Hw-interface stuff
/// Warn: Enabling this feature required xrt for build and run
pub use super::interface::{
    page_align, BoardConfig, FFIMode, HpuCmd, HpuConfig, HpuDevice, HpuError, HpuImm,
    HpuVarWrapped, ShellString, ACKQ_EMPTY,
};

#[cfg(feature = "io-dump")]
/// Expose io_dump init function
pub use super::interface::io_dump::set_hpu_io_dump;

#[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
/// Expose simulation interface
pub use super::ffi::{
    sim::ipc::{IpcSim, MemoryAck, MemoryReq, MemorySim, RegisterAck, RegisterReq, RegisterSim},
    MemKind, SyncMode,
};
