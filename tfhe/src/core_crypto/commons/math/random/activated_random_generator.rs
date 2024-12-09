#[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
use tfhe_csprng::generators::AesniRandomGenerator;
#[cfg(feature = "generator_aarch64_aes")]
use tfhe_csprng::generators::NeonAesRandomGenerator;
#[cfg(all(
    not(all(target_arch = "x86_64", target_feature = "aes")),
    not(feature = "generator_aarch64_aes")
))]
use tfhe_csprng::generators::SoftwareRandomGenerator;

#[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
pub type ActivatedRandomGenerator = AesniRandomGenerator;
#[cfg(feature = "generator_aarch64_aes")]
pub type ActivatedRandomGenerator = NeonAesRandomGenerator;
#[cfg(all(
    not(all(target_arch = "x86_64", target_feature = "aes")),
    not(feature = "generator_aarch64_aes")
))]
pub type ActivatedRandomGenerator = SoftwareRandomGenerator;
