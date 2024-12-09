#[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
use tfhe_csprng::generators::AesniRandomGenerator;
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
use tfhe_csprng::generators::NeonAesRandomGenerator;
#[cfg(all(
    not(all(target_arch = "x86_64", target_feature = "aes")),
    not(all(target_arch = "aarch64", target_feature = "neon"))
))]
use tfhe_csprng::generators::SoftwareRandomGenerator;

#[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
pub type ActivatedRandomGenerator = AesniRandomGenerator;
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub type ActivatedRandomGenerator = NeonAesRandomGenerator;
#[cfg(all(
    not(all(target_arch = "x86_64", target_feature = "aes")),
    not(all(target_arch = "aarch64", target_feature = "neon"))
))]
pub type ActivatedRandomGenerator = SoftwareRandomGenerator;
