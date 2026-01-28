//! Module containing expanded (standard domain) key types and expand methods.
//!
//! The difference between `decompress()` and `expand()`:
//! - `decompress()`: Returns keys in Fourier domain (ready for computation)
//! - `expand()`: Returns keys in standard domain (before Fourier conversion)

use crate::core_crypto::prelude::*;

use crate::integer::ciphertext::NoiseSquashingCompressionKey;
use crate::integer::compression_keys::CompressionKey;

use crate::shortint::atomic_pattern::compressed::{
    CompressedAtomicPatternServerKey, CompressedKS32AtomicPatternServerKey,
    CompressedStandardAtomicPatternServerKey,
};
use crate::shortint::noise_squashing::atomic_pattern::compressed::CompressedAtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::{
    CompressedShortint128BootstrappingKey, GenericNoiseSquashingKey, Shortint128BootstrappingKey,
};
use crate::shortint::server_key::{
    GenericServerKey, ModulusSwitchConfiguration, ShortintBootstrappingKey,
    ShortintCompressedBootstrappingKey,
};

use crate::high_level_api::keys::cpk_re_randomization::ReRandomizationKeySwitchingKey;
use crate::integer::compression_keys::CompressedDecompressionKey;
use crate::integer::noise_squashing::CompressedNoiseSquashingKey;

/// Bootstrapping Key with elements in the standard (i.e not fourier) domain
pub(in crate::high_level_api) enum ShortintExpandedBootstrappingKey<Scalar, ModSwitchScalar>
where
    Scalar: UnsignedInteger,
    ModSwitchScalar: UnsignedInteger,
{
    Classic {
        bsk: LweBootstrapKey<Vec<Scalar>>,
        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration<ModSwitchScalar>,
    },
    MultiBit {
        bsk: LweMultiBitBootstrapKey<Vec<Scalar>>,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

impl<ModSwitchScalar> ShortintExpandedBootstrappingKey<u64, ModSwitchScalar>
where
    ModSwitchScalar: UnsignedInteger,
{
    pub(in crate::high_level_api) fn into_fourier(
        self,
    ) -> ShortintBootstrappingKey<ModSwitchScalar> {
        match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let mut fourier_bsk = FourierLweBootstrapKey::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                );
                par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);
                ShortintBootstrappingKey::Classic {
                    bsk: fourier_bsk,
                    modulus_switch_noise_reduction_key,
                }
            }
            Self::MultiBit {
                bsk,
                thread_count,
                deterministic_execution,
            } => {
                let mut fourier_bsk = FourierLweMultiBitBootstrapKeyOwned::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                    bsk.grouping_factor(),
                );
                par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);
                ShortintBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution,
                }
            }
        }
    }
}

impl<ModSwitchScalar> ShortintExpandedBootstrappingKey<u128, ModSwitchScalar>
where
    ModSwitchScalar: UnsignedInteger,
{
    pub(in crate::high_level_api) fn into_fourier(
        self,
    ) -> Shortint128BootstrappingKey<ModSwitchScalar> {
        match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let mut fourier_bsk = Fourier128LweBootstrapKeyOwned::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                );
                par_convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk, &mut fourier_bsk);
                Shortint128BootstrappingKey::Classic {
                    bsk: fourier_bsk,
                    modulus_switch_noise_reduction_key,
                }
            }
            Self::MultiBit {
                bsk,
                thread_count,
                deterministic_execution,
            } => {
                let mut fourier_bsk = Fourier128LweMultiBitBootstrapKey::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                    bsk.grouping_factor(),
                );

                par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_128(
                    &bsk,
                    &mut fourier_bsk,
                );

                Shortint128BootstrappingKey::MultiBit {
                    bsk: fourier_bsk,
                    thread_count,
                    deterministic_execution,
                }
            }
        }
    }
}

pub(in crate::high_level_api) struct ExpandedDecompressionKey {
    pub bsk: ShortintExpandedBootstrappingKey<u64, u64>,
    pub lwe_per_glwe: LweCiphertextCount,
}

pub(in crate::high_level_api) struct ExpandedStandardAtomicPatternServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintExpandedBootstrappingKey<u64, u64>,
    pub pbs_order: PBSOrder,
}

pub(in crate::high_level_api) struct ExpandedKS32AtomicPatternServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u32>,
    pub bootstrapping_key: ShortintExpandedBootstrappingKey<u64, u32>,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

pub(in crate::high_level_api) enum ExpandedAtomicPatternServerKey {
    Standard(ExpandedStandardAtomicPatternServerKey),
    KeySwitch32(ExpandedKS32AtomicPatternServerKey),
}

pub(in crate::high_level_api) type ShortintExpandedServerKey =
    GenericServerKey<ExpandedAtomicPatternServerKey>;

pub(in crate::high_level_api) enum ExpandedAtomicPatternNoiseSquashingKey {
    Standard(ShortintExpandedBootstrappingKey<u128, u64>),
    KeySwitch32(ShortintExpandedBootstrappingKey<u128, u32>),
}

pub(in crate::high_level_api) type ExpandedNoiseSquashingKey =
    GenericNoiseSquashingKey<ExpandedAtomicPatternNoiseSquashingKey>;

pub(in crate::high_level_api) struct IntegerExpandedServerKey {
    pub compute_key: ShortintExpandedServerKey,
    pub cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
    pub compression_key: Option<CompressionKey>,
    pub decompression_key: Option<ExpandedDecompressionKey>,
    pub noise_squashing_key: Option<ExpandedNoiseSquashingKey>,
    pub noise_squashing_compression_key: Option<NoiseSquashingCompressionKey>,
    pub cpk_re_randomization_key_switching_key_material: Option<
        ReRandomizationKeySwitchingKey<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
    >,
}

impl IntegerExpandedServerKey {
    pub(in crate::high_level_api) fn convert_to_cpu(
        self,
    ) -> crate::high_level_api::keys::IntegerServerKey {
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

// =============================================================================
// Expand implementations for compressed types (NOT using pre-seeded generators)
// =============================================================================

impl<ModSwitchScalar> ShortintCompressedBootstrappingKey<ModSwitchScalar>
where
    ModSwitchScalar: UnsignedTorus,
{
    /// Expand the compressed bootstrapping key to the standard (non-Fourier) domain.
    pub(in crate::high_level_api) fn expand(
        &self,
    ) -> ShortintExpandedBootstrappingKey<u64, ModSwitchScalar> {
        match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let core_bsk = bsk.as_view().par_decompress_into_lwe_bootstrap_key();
                let modulus_switch_noise_reduction_key =
                    modulus_switch_noise_reduction_key.decompress();
                ShortintExpandedBootstrappingKey::Classic {
                    bsk: core_bsk,
                    modulus_switch_noise_reduction_key,
                }
            }
            Self::MultiBit {
                seeded_bsk,
                deterministic_execution,
            } => {
                let core_bsk = seeded_bsk
                    .as_view()
                    .par_decompress_into_lwe_multi_bit_bootstrap_key();

                let thread_count =
                    crate::shortint::engine::ShortintEngine::get_thread_count_for_multi_bit_pbs(
                        core_bsk.input_lwe_dimension(),
                        core_bsk.glwe_size().to_glwe_dimension(),
                        core_bsk.polynomial_size(),
                        core_bsk.decomposition_base_log(),
                        core_bsk.decomposition_level_count(),
                        core_bsk.grouping_factor(),
                    );

                ShortintExpandedBootstrappingKey::MultiBit {
                    bsk: core_bsk,
                    thread_count,
                    deterministic_execution: *deterministic_execution,
                }
            }
        }
    }
}

impl<ModSwitchScalar> CompressedShortint128BootstrappingKey<ModSwitchScalar>
where
    ModSwitchScalar: UnsignedTorus,
{
    /// Expand the compressed 128-bit bootstrapping key to the standard (non-Fourier) domain.
    pub(in crate::high_level_api) fn expand(
        &self,
    ) -> ShortintExpandedBootstrappingKey<u128, ModSwitchScalar> {
        match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let core_bsk = bsk.as_view().par_decompress_into_lwe_bootstrap_key();
                let modulus_switch_noise_reduction_key =
                    modulus_switch_noise_reduction_key.decompress();
                ShortintExpandedBootstrappingKey::Classic {
                    bsk: core_bsk,
                    modulus_switch_noise_reduction_key,
                }
            }
            Self::MultiBit {
                bsk,
                thread_count,
                deterministic_execution,
            } => {
                let core_bsk = bsk
                    .as_view()
                    .par_decompress_into_lwe_multi_bit_bootstrap_key();

                ShortintExpandedBootstrappingKey::MultiBit {
                    bsk: core_bsk,
                    thread_count: *thread_count,
                    deterministic_execution: *deterministic_execution,
                }
            }
        }
    }
}

impl CompressedStandardAtomicPatternServerKey {
    /// Expand to standard domain without Fourier conversion.
    pub(in crate::high_level_api) fn expand(&self) -> ExpandedStandardAtomicPatternServerKey {
        let key_switching_key = self
            .key_switching_key()
            .as_view()
            .par_decompress_into_lwe_keyswitch_key();
        let bootstrapping_key = self.bootstrapping_key().expand();

        ExpandedStandardAtomicPatternServerKey {
            key_switching_key,
            bootstrapping_key,
            pbs_order: self.pbs_order(),
        }
    }
}

impl CompressedKS32AtomicPatternServerKey {
    /// Expand to standard domain without Fourier conversion.
    pub(in crate::high_level_api) fn expand(&self) -> ExpandedKS32AtomicPatternServerKey {
        let ciphertext_modulus = self.bootstrapping_key().ciphertext_modulus();

        let key_switching_key = self
            .key_switching_key()
            .as_view()
            .par_decompress_into_lwe_keyswitch_key();
        let bootstrapping_key = self.bootstrapping_key().expand();

        ExpandedKS32AtomicPatternServerKey {
            key_switching_key,
            bootstrapping_key,
            ciphertext_modulus,
        }
    }
}

impl CompressedAtomicPatternServerKey {
    /// Expand to standard domain without Fourier conversion.
    pub(in crate::high_level_api) fn expand(&self) -> ExpandedAtomicPatternServerKey {
        match self {
            Self::Standard(std) => ExpandedAtomicPatternServerKey::Standard(std.expand()),
            Self::KeySwitch32(ks32) => ExpandedAtomicPatternServerKey::KeySwitch32(ks32.expand()),
        }
    }
}

impl CompressedDecompressionKey {
    /// Expand to standard domain without Fourier conversion.
    pub(in crate::high_level_api) fn expand(&self) -> ExpandedDecompressionKey {
        ExpandedDecompressionKey {
            bsk: self.key.bsk.expand(),
            lwe_per_glwe: self.key.lwe_per_glwe,
        }
    }
}

impl CompressedNoiseSquashingKey {
    /// Expand to standard domain without Fourier conversion.
    pub(in crate::high_level_api) fn expand(&self) -> ExpandedNoiseSquashingKey {
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
