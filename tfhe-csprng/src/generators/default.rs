#[cfg(all(target_arch = "x86_64", not(feature = "software-prng")))]
pub type DefaultRandomGenerator = super::AesniRandomGenerator;
#[cfg(all(target_arch = "aarch64", not(feature = "software-prng")))]
pub type DefaultRandomGenerator = super::NeonAesRandomGenerator;
#[cfg(any(
    feature = "software-prng",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub type DefaultRandomGenerator = super::SoftwareRandomGenerator;

#[cfg(all(target_arch = "x86_64", not(feature = "software-prng")))]
pub type DefaultBlockCipher = super::implem::AesniBlockCipher;
#[cfg(all(target_arch = "aarch64", not(feature = "software-prng")))]
pub type DefaultBlockCipher = super::implem::ArmAesBlockCipher;
#[cfg(any(
    feature = "software-prng",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub type DefaultBlockCipher = super::SoftwareBlockCipher;
