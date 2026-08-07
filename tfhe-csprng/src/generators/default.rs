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
///
/// This is the only place the target cascade is spelled out: the block cipher aliases below are
/// projections of this backend, so adding an Aes variant does not multiply the number of `cfg`
/// blocks.
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
pub type DefaultBlockCipher128 = <DefaultAesBackend as AesBackend>::Aes128BlockCipher;

/// The Aes-256 block cipher of the [`DefaultAesBackend`].
pub type DefaultBlockCipher256 = <DefaultAesBackend as AesBackend>::Aes256BlockCipher;

/// The block cipher of the [`DefaultAesBackend`], with the Aes variant chosen at runtime.
///
/// Its key is an [`AnyAesKey`](super::AnyAesKey), so which of Aes-128 or Aes-256 drives the stream
/// is decided by the key it is built from. Prefer [`DefaultBlockCipher128`] or
/// [`DefaultBlockCipher256`] when the variant is known statically.
pub type DefaultBlockCipher = AnyAesBlockCipher<DefaultAesBackend>;
