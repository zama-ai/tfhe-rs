// Should be removed when we raise MSRV above 1.87
#![allow(clippy::manual_is_multiple_of)]

mod entities;

#[cfg(not(feature = "utils"))]
mod ffi;
#[cfg(feature = "utils")]
pub mod ffi;
#[cfg(feature = "utils")]
pub mod insn_trace;
#[cfg(feature = "utils")]
pub mod isc_trace;

pub mod interface;

pub mod asm;
pub mod fw;

pub mod prelude;
