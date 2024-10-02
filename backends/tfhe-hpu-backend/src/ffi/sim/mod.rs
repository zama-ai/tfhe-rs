//! Implement a simple mockup interface for ffi.
//! It enable to simulate the tfhe-hpu-backend behavior without the real HW

mod hpu_hw;
pub(crate) use hpu_hw::HpuHw;

mod mem_zone;
pub(crate) use mem_zone::MemZone;
