mod entities;

#[cfg(all(feature = "hw-itf", not(feature = "debug")))]
mod ffi;
#[cfg(all(feature = "hw-itf", feature = "debug"))]
pub mod ffi;

#[cfg(all(feature = "hw-itf", not(feature = "debug")))]
mod interface;
#[cfg(all(feature = "hw-itf", feature = "debug"))]
pub mod interface;

pub mod prelude;
