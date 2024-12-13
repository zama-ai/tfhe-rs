#[cfg(all(target_arch = "x86_64", not(feature = "software-prng")))]
use super::AesniRandomGenerator;
#[cfg(all(target_arch = "aarch64", not(feature = "software-prng")))]
use super::NeonAesRandomGenerator;
#[cfg(any(
    feature = "software-prng",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
use super::SoftwareRandomGenerator;

#[cfg(all(target_arch = "x86_64", not(feature = "software-prng")))]
pub type DefaultRandomGenerator = AesniRandomGenerator;
#[cfg(all(target_arch = "aarch64", not(feature = "software-prng")))]
pub type DefaultRandomGenerator = NeonAesRandomGenerator;
#[cfg(any(
    feature = "software-prng",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub type DefaultRandomGenerator = SoftwareRandomGenerator;
