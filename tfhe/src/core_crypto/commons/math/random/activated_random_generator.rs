#[cfg(all(target_arch = "x86_64", not(feature = "software-prng")))]
use tfhe_csprng::generators::AesniRandomGenerator;
#[cfg(all(target_arch = "aarch64", not(feature = "software-prng")))]
use tfhe_csprng::generators::NeonAesRandomGenerator;
#[cfg(any(
    feature = "software-prng",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
use tfhe_csprng::generators::SoftwareRandomGenerator;

#[cfg(all(target_arch = "x86_64", not(feature = "software-prng")))]
pub type ActivatedRandomGenerator = AesniRandomGenerator;
#[cfg(all(target_arch = "aarch64", not(feature = "software-prng")))]
pub type ActivatedRandomGenerator = NeonAesRandomGenerator;
#[cfg(any(
    feature = "software-prng",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub type ActivatedRandomGenerator = SoftwareRandomGenerator;
