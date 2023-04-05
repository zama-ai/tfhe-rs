#![allow(clippy::missing_safety_doc)]
#[cfg(feature = "boolean-c-api")]
pub mod boolean;
pub mod buffer;
#[cfg(feature = "shortint-c-api")]
pub mod shortint;
#[cfg(any(feature = "boolean", feature = "integer"))]
pub mod typed_api;
pub(crate) mod utils;
