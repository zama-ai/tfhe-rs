// Should be removed when we raise MSRV above 1.87
#![allow(clippy::manual_is_multiple_of)]

#[cfg(all(feature = "hw-v80", feature = "hw-xrt"))]
compile_error! {"hw-v80 and hw-xrt features are used to select the targeted fpga family. Only one fpga family can be used at a time thus these features are mutually exclusive. Only enable one of them at a time. "}

mod entities;

#[cfg(not(feature = "utils"))]
mod ffi;
#[cfg(feature = "utils")]
pub mod ffi;
#[cfg(feature = "utils")]
pub mod isc_trace;

pub mod interface;

pub mod asm;
pub mod fw;

pub mod prelude;
