#[cfg(target_arch = "x86_64")]
mod aesni;
#[cfg(target_arch = "x86_64")]
pub use aesni::*;

#[cfg(feature = "generator_aarch64_aes")]
mod aarch64;
#[cfg(feature = "generator_aarch64_aes")]
pub use aarch64::*;

#[cfg(feature = "software_prng")]
mod soft;
#[cfg(feature = "software_prng")]
pub use soft::*;
