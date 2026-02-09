//! Module containing expanded (standard domain) key types and expand methods.
//!
//! The difference between `decompress()` and `expand()`:
//! - `decompress()`: Returns keys in Fourier domain (ready for computation)
//! - `expand()`: Returns keys in standard domain (before Fourier conversion)

use crate::core_crypto::prelude::*;

use crate::integer::ciphertext::NoiseSquashingCompressionKey;
use crate::integer::compression_keys::CompressionKey;

use crate::shortint::noise_squashing::atomic_pattern::compressed::CompressedAtomicPatternNoiseSquashingKey;

use crate::high_level_api::keys::cpk_re_randomization::ReRandomizationKeySwitchingKey;
use crate::integer::compression_keys::CompressedDecompressionKey;
use crate::integer::noise_squashing::CompressedNoiseSquashingKey;

use crate::shortint::atomic_pattern::expanded::{
    ExpandedAtomicPatternServerKey, ExpandedKS32AtomicPatternServerKey,
    ExpandedStandardAtomicPatternServerKey,
};
pub use crate::shortint::noise_squashing::atomic_pattern::ExpandedAtomicPatternNoiseSquashingKey;
pub use crate::shortint::noise_squashing::ExpandedNoiseSquashingKey;
pub use crate::shortint::server_key::expanded::{
    ShortintExpandedBootstrappingKey, ShortintExpandedServerKey,
};

pub struct ExpandedDecompressionKey {
    pub bsk: ShortintExpandedBootstrappingKey<u64, u64>,
    pub lwe_per_glwe: LweCiphertextCount,
}

pub struct IntegerExpandedServerKey {
    pub compute_key: ShortintExpandedServerKey,
    pub cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
    pub compression_key: Option<CompressionKey>,
    pub decompression_key: Option<ExpandedDecompressionKey>,
    pub noise_squashing_key: Option<ExpandedNoiseSquashingKey>,
    pub noise_squashing_compression_key: Option<NoiseSquashingCompressionKey>,
    pub cpk_re_randomization_key_switching_key_material: Option<ReRandomizationKeySwitchingKey>,
}

impl IntegerExpandedServerKey {
    pub fn convert_to_cpu(self) -> crate::high_level_api::keys::IntegerServerKey {
        use crate::high_level_api::keys::IntegerServerKey;
        use crate::shortint::atomic_pattern::{
            AtomicPatternServerKey, KS32AtomicPatternServerKey, StandardAtomicPatternServerKey,
        };
        use crate::shortint::noise_squashing::atomic_pattern::ks32::KS32AtomicPatternNoiseSquashingKey;
        use crate::shortint::noise_squashing::atomic_pattern::standard::StandardAtomicPatternNoiseSquashingKey;
        use crate::shortint::noise_squashing::atomic_pattern::AtomicPatternNoiseSquashingKey;

        let Self {
            compute_key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key_switching_key_material,
        } = self;

        let atomic_pattern_key = match compute_key.atomic_pattern {
            ExpandedAtomicPatternServerKey::Standard(std_ap) => {
                let ExpandedStandardAtomicPatternServerKey {
                    key_switching_key,
                    bootstrapping_key,
                    pbs_order,
                } = std_ap;

                let bootstrapping_key = bootstrapping_key.into_fourier();

                AtomicPatternServerKey::Standard(StandardAtomicPatternServerKey {
                    key_switching_key,
                    bootstrapping_key,
                    pbs_order,
                })
            }
            ExpandedAtomicPatternServerKey::KeySwitch32(ks32_ap) => {
                let ExpandedKS32AtomicPatternServerKey {
                    key_switching_key,
                    bootstrapping_key,
                    ciphertext_modulus,
                } = ks32_ap;

                let bootstrapping_key = bootstrapping_key.into_fourier();

                AtomicPatternServerKey::KeySwitch32(KS32AtomicPatternServerKey {
                    key_switching_key,
                    bootstrapping_key,
                    ciphertext_modulus,
                })
            }
        };

        let key =
            crate::integer::ServerKey::from_raw_parts(crate::shortint::ServerKey::from_raw_parts(
                atomic_pattern_key,
                compute_key.message_modulus,
                compute_key.carry_modulus,
                compute_key.max_degree,
                compute_key.max_noise_level,
            ));

        let noise_squashing_key = noise_squashing_key.map(|ns_key| {
            let (ap, msg_mod, carry_mod, ct_mod) = ns_key.into_raw_parts();
            let ap = match ap {
                ExpandedAtomicPatternNoiseSquashingKey::Standard(bootstrapping_key) => {
                    let bootstrapping_key = bootstrapping_key.into_fourier();
                    AtomicPatternNoiseSquashingKey::Standard(
                        StandardAtomicPatternNoiseSquashingKey::from_raw_parts(bootstrapping_key),
                    )
                }
                ExpandedAtomicPatternNoiseSquashingKey::KeySwitch32(bootstrapping_key) => {
                    let bootstrapping_key = bootstrapping_key.into_fourier();
                    AtomicPatternNoiseSquashingKey::KeySwitch32(
                        KS32AtomicPatternNoiseSquashingKey::from_raw_parts(bootstrapping_key),
                    )
                }
            };
            crate::integer::noise_squashing::NoiseSquashingKey::from_raw_parts(
                crate::shortint::noise_squashing::NoiseSquashingKey::from_raw_parts(
                    ap, msg_mod, carry_mod, ct_mod,
                ),
            )
        });

        let decompression_key = decompression_key.map(|key| {
            let ExpandedDecompressionKey { bsk, lwe_per_glwe } = key;
            let bsk = bsk.into_fourier();
            crate::integer::compression_keys::DecompressionKey::from_raw_parts(
                crate::shortint::list_compression::DecompressionKey { bsk, lwe_per_glwe },
            )
        });

        IntegerServerKey {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key_switching_key_material,
        }
    }
}

#[cfg(feature = "gpu")]
impl IntegerExpandedServerKey {
    pub fn convert_to_gpu(
        &self,
        streams: &crate::core_crypto::gpu::CudaStreams,
    ) -> crate::Result<crate::high_level_api::keys::inner::IntegerCudaServerKey> {
        use crate::high_level_api::keys::cpk_re_randomization::{
            CudaReRandomizationKeySwitchingKey, ReRandomizationKeySwitchingKey,
        };
        use crate::integer::gpu::key_switching_key::CudaKeySwitchingKeyMaterial;
        use crate::integer::gpu::list_compression::server_keys::{
            CudaCompressionKey, CudaDecompressionKey, CudaNoiseSquashingCompressionKey,
        };
        use crate::integer::gpu::noise_squashing::keys::CudaNoiseSquashingKey;
        use crate::integer::gpu::CudaServerKey;

        // Destructure to ensure all fields are handled
        let Self {
            compute_key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key_switching_key_material,
        } = self;

        let key = CudaServerKey::from_expanded_server_key(compute_key, streams)?;

        let cpk_key_switching_key_material = cpk_key_switching_key_material.as_ref().map(|ksk| {
            CudaKeySwitchingKeyMaterial::from_key_switching_key_material(&ksk.as_view(), streams)
        });

        let compression_key = compression_key
            .as_ref()
            .map(|ck| CudaCompressionKey::from_compression_key(ck, streams));

        let decompression_key = decompression_key
            .as_ref()
            .map(|dk| {
                CudaDecompressionKey::from_expanded_decompression_key(
                    dk,
                    compute_key.glwe_dimension(),
                    compute_key.polynomial_size(),
                    compute_key.message_modulus,
                    compute_key.carry_modulus,
                    compute_key.ciphertext_modulus,
                    streams,
                )
            })
            .transpose()?;

        let noise_squashing_key = noise_squashing_key
            .as_ref()
            .map(|nsk| CudaNoiseSquashingKey::from_expanded_noise_squashing_key(nsk, streams));

        let noise_squashing_compression_key =
            noise_squashing_compression_key.as_ref().map(|nsck| {
                CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
                    nsck, streams,
                )
            });

        let cpk_re_randomization_key_switching_key_material =
            cpk_re_randomization_key_switching_key_material
                .as_ref()
                .map(|re_rand_ksk| match re_rand_ksk {
                    ReRandomizationKeySwitchingKey::UseCPKEncryptionKSK => {
                        CudaReRandomizationKeySwitchingKey::UseCPKEncryptionKSK
                    }
                    ReRandomizationKeySwitchingKey::DedicatedKSK(ksk) => {
                        CudaReRandomizationKeySwitchingKey::DedicatedKSK(
                            CudaKeySwitchingKeyMaterial::from_key_switching_key_material(
                                &ksk.as_view(),
                                streams,
                            ),
                        )
                    }
                });

        Ok(crate::high_level_api::keys::inner::IntegerCudaServerKey {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key_switching_key_material,
        })
    }
}

impl CompressedDecompressionKey {
    /// Expand to standard domain without Fourier conversion.
    pub fn expand(&self) -> ExpandedDecompressionKey {
        ExpandedDecompressionKey {
            bsk: self.key.bsk.expand(),
            lwe_per_glwe: self.key.lwe_per_glwe,
        }
    }
}

impl CompressedNoiseSquashingKey {
    /// Expand to standard domain without Fourier conversion.
    pub fn expand(&self) -> ExpandedNoiseSquashingKey {
        let expanded_ap = match self.key.atomic_pattern() {
            CompressedAtomicPatternNoiseSquashingKey::Standard(compressed_std) => {
                ExpandedAtomicPatternNoiseSquashingKey::Standard(
                    compressed_std.bootstrapping_key().expand(),
                )
            }
            CompressedAtomicPatternNoiseSquashingKey::KeySwitch32(compressed_ks32) => {
                ExpandedAtomicPatternNoiseSquashingKey::KeySwitch32(
                    compressed_ks32.bootstrapping_key().expand(),
                )
            }
        };

        ExpandedNoiseSquashingKey::from_raw_parts(
            expanded_ap,
            self.key.message_modulus(),
            self.key.carry_modulus(),
            self.key.output_ciphertext_modulus(),
        )
    }
}
