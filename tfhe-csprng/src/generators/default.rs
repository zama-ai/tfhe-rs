use crate::generators::{AesBackend, AnyAesBlockCipher};

#[cfg(all(target_arch = "x86_64", not(feature = "software-prng")))]
pub type DefaultRandomGenerator = super::AesniRandomGenerator;
#[cfg(all(target_arch = "aarch64", not(feature = "software-prng")))]
pub type DefaultRandomGenerator = super::NeonAesRandomGenerator;
#[cfg(any(
    feature = "software-prng",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub type DefaultRandomGenerator = super::SoftwareRandomGenerator;

/// The [`AesBackend`] selected for this target and feature set.
#[cfg(all(target_arch = "x86_64", not(feature = "software-prng")))]
pub type DefaultAesBackend = super::Aesni;
#[cfg(all(target_arch = "aarch64", not(feature = "software-prng")))]
pub type DefaultAesBackend = super::Arm;
#[cfg(any(
    feature = "software-prng",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub type DefaultAesBackend = super::Software;

/// The Aes-128 block cipher of the [`DefaultAesBackend`].
pub type DefaultAes128BlockCipher = <DefaultAesBackend as AesBackend>::Aes128BlockCipher;
/// The Aes-256 block cipher of the [`DefaultAesBackend`].
pub type DefaultAes256BlockCipher = <DefaultAesBackend as AesBackend>::Aes256BlockCipher;
/// The block cipher of the [`DefaultAesBackend`], with the Aes variant chosen at runtime.
pub type DefaultAesBlockCipher = AnyAesBlockCipher<DefaultAesBackend>;
