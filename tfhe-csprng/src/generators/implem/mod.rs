#[cfg(target_arch = "x86_64")]
mod aesni;
#[cfg(target_arch = "x86_64")]
pub use aesni::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(feature = "software_prng")]
mod soft;
#[cfg(feature = "software_prng")]
pub use soft::*;
