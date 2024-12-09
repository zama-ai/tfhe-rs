#[cfg(all(target_arch = "x86_64", not(feature = "software_prng")))]
use tfhe_csprng::generators::AesniRandomGenerator;
#[cfg(all(target_arch = "aarch64", not(feature = "software_prng")))]
use tfhe_csprng::generators::NeonAesRandomGenerator;
#[cfg(feature = "software_prng")]
use tfhe_csprng::generators::SoftwareRandomGenerator;

#[cfg(all(target_arch = "x86_64", not(feature = "software_prng")))]
pub type ActivatedRandomGenerator = AesniRandomGenerator;
#[cfg(all(target_arch = "aarch64", not(feature = "software_prng")))]
pub type ActivatedRandomGenerator = NeonAesRandomGenerator;
#[cfg(feature = "software_prng")]
pub type ActivatedRandomGenerator = SoftwareRandomGenerator;
