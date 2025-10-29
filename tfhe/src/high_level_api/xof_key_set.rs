use crate::backward_compatibility::xof_key_set::CompressedXofKeySetVersions;
use crate::core_crypto::commons::generators::MaskRandomGenerator;

use crate::core_crypto::entities::{LweCompactPublicKey, LweKeyswitchKey};
use crate::core_crypto::prelude::*;

use crate::integer::ciphertext::{
    CompressedNoiseSquashingCompressionKey, NoiseSquashingCompressionKey,
};
use crate::integer::noise_squashing::CompressedNoiseSquashingKey;

use crate::named::Named;

use crate::shortint::atomic_pattern::{
    AtomicPatternServerKey, KS32AtomicPatternServerKey, StandardAtomicPatternServerKey,
};

use crate::shortint::noise_squashing::atomic_pattern::ks32::KS32AtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::atomic_pattern::standard::StandardAtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::atomic_pattern::AtomicPatternNoiseSquashingKey;
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, CompressedModulusSwitchNoiseReductionKey,
    ModulusSwitchConfiguration, ModulusSwitchNoiseReductionKey, ShortintBootstrappingKey,
    ShortintCompressedBootstrappingKey,
};
use crate::{
    integer, shortint, CompactPublicKey, CompressedCompactPublicKey,
    CompressedReRandomizationKeySwitchingKey, CompressedServerKey, ReRandomizationKeySwitchingKey,
    ServerKey,
};
use aligned_vec::ABox;
use serde::{Deserialize, Serialize};

use tfhe_csprng::seeders::XofSeed;
use tfhe_fft::c64;
use tfhe_versionable::Versionize;

use crate::high_level_api::backward_compatibility::xof_key_set::XofKeySetVersions;
use crate::integer::compression_keys::CompressionKey;
use crate::integer::key_switching_key::{
    CompressedKeySwitchingKeyMaterial, KeySwitchingKeyMaterial,
};
use crate::shortint::atomic_pattern::compressed::{
    CompressedAtomicPatternServerKey, CompressedKS32AtomicPatternServerKey,
    CompressedStandardAtomicPatternServerKey,
};
use crate::shortint::noise_squashing::atomic_pattern::compressed::CompressedAtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::{
    CompressedShortint128BootstrappingKey, Shortint128BootstrappingKey,
};

#[cfg(test)]
mod cfg_test_imports {
    pub(super) use crate::core_crypto::commons::generators::NoiseRandomGenerator;
    pub(super) use crate::core_crypto::commons::math::random::{
        CompressionSeed, Distribution, Uniform,
    };
    pub(super) use crate::core_crypto::prelude::CiphertextModulus as CoreCiphertextModulus;
    pub(super) use crate::high_level_api::keys::CompactPrivateKey;
    pub(super) use crate::integer::compression_keys::CompressionPrivateKeys;
    pub(super) use crate::integer::noise_squashing::NoiseSquashingPrivateKey;
    pub(super) use crate::shortint::ciphertext::MaxDegree;
    pub(super) use crate::shortint::client_key::atomic_pattern::{
        AtomicPatternClientKey, KS32AtomicPatternClientKey, StandardAtomicPatternClientKey,
    };
    pub(super) use crate::shortint::key_switching_key::KeySwitchingKeyDestinationAtomicPattern;
    pub(super) use crate::shortint::noise_squashing::atomic_pattern::compressed::standard::CompressedStandardAtomicPatternNoiseSquashingKey;
    pub(super) use crate::shortint::parameters::{
        ModulusSwitchNoiseReductionParams, ModulusSwitchType, NoiseSquashingParameters,
    };
    pub(super) use crate::shortint::{
        ClassicPBSParameters, MultiBitPBSParameters, PBSParameters, ShortintParameterSet,
    };
    pub(super) use tfhe_csprng::seeders::Seed;

    pub(super) use crate::high_level_api::keys::ReRandomizationKeyGenerationInfo;
    pub(super) use crate::Tag;
}
#[cfg(test)]
use cfg_test_imports::*;

// Generation order:
//
// 1) Public key (enc params)
// 2) Compression key
// 3) Decompression key
// 4) KSK (compute params)
// 5) BSK (compute params)
// 6) Mod Switch Key (compute params)
// 7) BSK (SnS params)
// 8) Mod Switch Key (SnS params)
// 9) KSK (encryption params to compute params)
// 10) Re-Rand KSK
// 11) SNS Compression Key

/// Compressed KeySet which respects the [Threshold (Fully) Homomorphic Encryption]
/// regarding the random generator used, and the order of key generation
///
/// [Threshold (Fully) Homomorphic Encryption]: https://eprint.iacr.org/2025/699
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(CompressedXofKeySetVersions)]
pub struct CompressedXofKeySet {
    seed: XofSeed,
    compressed_public_key: CompressedCompactPublicKey,
    compressed_server_key: CompressedServerKey,
}

impl Named for CompressedXofKeySet {
    const NAME: &'static str = "high_level_api::CompressedXofKeySet";
}

impl CompressedXofKeySet {
    /// Decompress the KeySet
    pub fn decompress(self) -> crate::Result<XofKeySet> {
        let mut mask_generator = MaskRandomGenerator::<DefaultRandomGenerator>::new(self.seed);

        let public_key = {
            self.compressed_public_key
                .decompress_with_with_pre_seeded_generator(&mut mask_generator)
        };

        let compression_key = self
            .compressed_server_key
            .integer_key
            .compression_key
            .map(|k| k.decompress_with_pre_seeded_generator(&mut mask_generator));

        let decompression_key = self
            .compressed_server_key
            .integer_key
            .decompression_key
            .map(|k| k.decompress_with_pre_seeded_generator(&mut mask_generator));

        let shortint_sk = &self.compressed_server_key.integer_key.key.key;

        let atomic_pattern_key = shortint_sk
            .compressed_ap_server_key
            .decompress_with_pre_seeded_generator(&mut mask_generator);

        let shortint_sk = shortint::ServerKey::from_raw_parts(
            atomic_pattern_key,
            shortint_sk.message_modulus,
            shortint_sk.carry_modulus,
            shortint_sk.max_degree,
            shortint_sk.max_noise_level,
        );

        let integer_sk = integer::ServerKey::from_raw_parts(shortint_sk);

        let noise_squashing_key = self
            .compressed_server_key
            .integer_key
            .noise_squashing_key
            .as_ref()
            .map(|compressed_nsk| {
                compressed_nsk.decompress_with_pre_seeded_generator(&mut mask_generator)
            });

        let integer_cpk_ksk = self
            .compressed_server_key
            .integer_key
            .cpk_key_switching_key_material
            .map(|k| k.decompress_with_pre_seeded_generator(&mut mask_generator));

        let integer_cpk_re_rand_ksk = self
            .compressed_server_key
            .integer_key
            .cpk_re_randomization_key_switching_key_material
            .map(|k| match k {
                super::CompressedReRandomizationKeySwitchingKey::UseCPKEncryptionKSK => {
                    ReRandomizationKeySwitchingKey::UseCPKEncryptionKSK
                }
                super::CompressedReRandomizationKeySwitchingKey::DedicatedKSK(key) => {
                    ReRandomizationKeySwitchingKey::DedicatedKSK(
                        key.decompress_with_pre_seeded_generator(&mut mask_generator),
                    )
                }
            });

        let noise_squashing_compression_key = self
            .compressed_server_key
            .integer_key
            .noise_squashing_compression_key
            .map(|ns_comp_key| {
                ns_comp_key.decompress_with_pre_seeded_generator(&mut mask_generator)
            });

        let server_key = ServerKey::from_raw_parts(
            integer_sk,
            integer_cpk_ksk,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            integer_cpk_re_rand_ksk,
            self.compressed_server_key.tag,
        );

        Ok(XofKeySet {
            public_key,
            server_key,
        })
    }

    pub fn from_raw_parts(
        pub_seed: XofSeed,
        compressed_public_key: CompressedCompactPublicKey,
        compressed_server_key: CompressedServerKey,
    ) -> Self {
        Self {
            seed: pub_seed,
            compressed_public_key,
            compressed_server_key,
        }
    }

    pub fn into_raw_parts(self) -> (XofSeed, CompressedCompactPublicKey, CompressedServerKey) {
        let Self {
            seed,
            compressed_public_key,
            compressed_server_key,
        } = self;

        (seed, compressed_public_key, compressed_server_key)
    }
}

/// KeySet which contains the public material (public key and server key)
/// of the [Threshold (Fully) Homomorphic Encryption]
///
/// To create such key set, first create a [CompressedXofKeySet] then decompress it
///
/// [Threshold (Fully) Homomorphic Encryption]: https://eprint.iacr.org/2025/699
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(XofKeySetVersions)]
pub struct XofKeySet {
    public_key: CompactPublicKey,
    server_key: ServerKey,
}

impl Named for XofKeySet {
    const NAME: &'static str = "high_level_api::XofKeySet";
}

impl XofKeySet {
    pub fn into_raw_parts(self) -> (CompactPublicKey, ServerKey) {
        (self.public_key, self.server_key)
    }
}

impl CompressedCompactPublicKey {
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        private_key: &CompactPrivateKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
        tag: Tag,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        let public_key_parameters = private_key.0.key.parameters();

        let mut core_pk = SeededLweCompactPublicKeyOwned::new(
            0u64,
            public_key_parameters.encryption_lwe_dimension,
            CompressionSeed::from(Seed(0)), // This is not the seed that is actually used
            public_key_parameters.ciphertext_modulus,
        );

        generate_seeded_lwe_compact_public_key_with_pre_seeded_generator(
            &private_key.0.key.key(),
            &mut core_pk,
            public_key_parameters.encryption_noise_distribution,
            generator,
        );

        Self::from_raw_parts(
            integer::CompressedCompactPublicKey::from_raw_parts(
                shortint::CompressedCompactPublicKey::from_raw_parts(
                    core_pk,
                    private_key.0.key.parameters(),
                ),
            ),
            tag,
        )
    }

    fn decompress_with_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> CompactPublicKey
    where
        Gen: ByteRandomGenerator,
    {
        let shortint_cpk = &self.key.key.key;
        let compressed_pk = &shortint_cpk.key;
        let mut pk = LweCompactPublicKey::new(
            0u64,
            compressed_pk.lwe_dimension(),
            compressed_pk.ciphertext_modulus(),
        );

        decompress_seeded_lwe_compact_public_key_with_pre_seeded_generator(
            &mut pk,
            compressed_pk,
            generator,
        );

        let shortint_pk = shortint::CompactPublicKey::from_raw_parts(pk, shortint_cpk.parameters);
        let integer_pk = integer::CompactPublicKey::from_raw_parts(shortint_pk);
        CompactPublicKey::from_raw_parts(integer_pk, self.tag.clone())
    }
}

impl integer::compression_keys::CompressedCompressionKey {
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        private_compression_key: &CompressionPrivateKeys,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        ciphertext_modulus: CiphertextModulus<u64>,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        let compression_params = private_compression_key.key.params;
        let mut packing_key_switching_key = SeededLwePackingKeyswitchKey::new(
            0u64,
            compression_params.packing_ks_base_log(),
            compression_params.packing_ks_level(),
            glwe_secret_key.as_lwe_secret_key().lwe_dimension(),
            compression_params.packing_ks_glwe_dimension(),
            compression_params.packing_ks_polynomial_size(),
            CompressionSeed::from(Seed(0)),
            ciphertext_modulus,
        );

        generate_seeded_lwe_packing_keyswitch_key_with_pre_seeded_generator(
            &glwe_secret_key.as_lwe_secret_key(),
            &private_compression_key.key.post_packing_ks_key,
            &mut packing_key_switching_key,
            compression_params.packing_ks_key_noise_distribution(),
            generator,
        );

        Self {
            key: shortint::list_compression::CompressedCompressionKey {
                packing_key_switching_key,
                lwe_per_glwe: compression_params.lwe_per_glwe(),
                storage_log_modulus: compression_params.storage_log_modulus(),
            },
        }
    }

    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> CompressionKey
    where
        Gen: ByteRandomGenerator,
    {
        let packing_key_switching_key = self
            .key
            .packing_key_switching_key
            .decompress_to_lwe_packing_keyswitch_key_with_pre_seeded_generator(generator);

        CompressionKey {
            key: shortint::list_compression::CompressionKey {
                packing_key_switching_key,
                lwe_per_glwe: self.key.lwe_per_glwe,
                storage_log_modulus: self.key.storage_log_modulus,
            },
        }
    }
}

impl integer::compression_keys::CompressedDecompressionKey {
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        private_compression_key: &CompressionPrivateKeys,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        computation_parameters: ShortintParameterSet,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        let compression_params = private_compression_key.key.params;

        let core_bsk = allocate_and_generate_lwe_bootstrapping_key_with_pre_seeded_generator(
            &private_compression_key
                .key
                .post_packing_ks_key
                .as_lwe_secret_key(),
            glwe_secret_key,
            compression_params.br_base_log(),
            compression_params.br_level(),
            computation_parameters.glwe_noise_distribution(),
            computation_parameters.ciphertext_modulus(),
            generator,
        );

        Self {
            key: crate::shortint::list_compression::CompressedDecompressionKey {
                bsk: ShortintCompressedBootstrappingKey::Classic {
                    bsk: core_bsk,
                    modulus_switch_noise_reduction_key:
                        CompressedModulusSwitchConfiguration::Standard,
                },
                lwe_per_glwe: compression_params.lwe_per_glwe(),
            },
        }
    }

    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> integer::compression_keys::DecompressionKey
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        let crate::shortint::list_compression::CompressedDecompressionKey {
            ref bsk,
            lwe_per_glwe,
        } = self.key;

        integer::compression_keys::DecompressionKey {
            key: crate::shortint::list_compression::DecompressionKey {
                bsk: bsk.decompress_with_pre_seeded_generator(generator),
                lwe_per_glwe,
            },
        }
    }
}

impl CompressedNoiseSquashingKey {
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        private_noise_squashing_key: &integer::noise_squashing::NoiseSquashingPrivateKey,
        ap_client_key: &AtomicPatternClientKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        let noise_squashing_parameters = private_noise_squashing_key.noise_squashing_parameters();

        let shortint_key = match ap_client_key {
            AtomicPatternClientKey::Standard(std_ap) => {
                let bsk = CompressedShortint128BootstrappingKey::generate_with_pre_seeded_generator(
                    &std_ap.lwe_secret_key,
                    std_ap.parameters.ciphertext_modulus(),
                    std_ap.parameters.lwe_noise_distribution(),
                    private_noise_squashing_key,
                    generator,
                );

                CompressedAtomicPatternNoiseSquashingKey::Standard(
                    CompressedStandardAtomicPatternNoiseSquashingKey::from_raw_parts(bsk),
                )
            }
            AtomicPatternClientKey::KeySwitch32(ks32_ap) => {
                use crate::shortint::noise_squashing::atomic_pattern::compressed::ks32::CompressedKS32AtomicPatternNoiseSquashingKey;
                let bsk = CompressedShortint128BootstrappingKey::generate_with_pre_seeded_generator(
                    &ks32_ap.lwe_secret_key,
                    ks32_ap.parameters.post_keyswitch_ciphertext_modulus,
                    ks32_ap.parameters.lwe_noise_distribution,
                    private_noise_squashing_key,
                    generator,
                );

                CompressedAtomicPatternNoiseSquashingKey::KeySwitch32(
                    CompressedKS32AtomicPatternNoiseSquashingKey::from_raw_parts(bsk),
                )
            }
        };

        Self::from_raw_parts(
            shortint::noise_squashing::CompressedNoiseSquashingKey::from_raw_parts(
                shortint_key,
                noise_squashing_parameters.message_modulus(),
                noise_squashing_parameters.carry_modulus(),
                noise_squashing_parameters.ciphertext_modulus(),
            ),
        )
    }

    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> integer::noise_squashing::NoiseSquashingKey
    where
        Gen: ByteRandomGenerator,
    {
        let decompressed = match self.key.atomic_pattern() {
            CompressedAtomicPatternNoiseSquashingKey::Standard(compressed_std) => {
                AtomicPatternNoiseSquashingKey::Standard(
                    StandardAtomicPatternNoiseSquashingKey::from_raw_parts(
                        compressed_std
                            .bootstrapping_key()
                            .decompress_with_pre_seeded_generator(generator),
                    ),
                )
            }
            CompressedAtomicPatternNoiseSquashingKey::KeySwitch32(compressed_ks32) => {
                AtomicPatternNoiseSquashingKey::KeySwitch32(
                    KS32AtomicPatternNoiseSquashingKey::from_raw_parts(
                        compressed_ks32
                            .bootstrapping_key()
                            .decompress_with_pre_seeded_generator(generator),
                    ),
                )
            }
        };

        integer::noise_squashing::NoiseSquashingKey::from_raw_parts(
            shortint::noise_squashing::NoiseSquashingKey::from_raw_parts(
                decompressed,
                self.key.message_modulus(),
                self.key.carry_modulus(),
                self.key.output_ciphertext_modulus(),
            ),
        )
    }
}

#[cfg(test)]
struct ShortintClassicCompressedBootstrappingKeyParts {
    core_bsk: SeededLweBootstrapKeyOwned<u64>,
    modulus_switch_noise_reduction_config: CompressedModulusSwitchConfiguration<u64>,
}

#[cfg(test)]
impl ShortintClassicCompressedBootstrappingKeyParts {
    fn generate_with_pre_seeded_generator<Gen>(
        client_key: &StandardAtomicPatternClientKey,
        pbs_params: ClassicPBSParameters,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        let core_bsk = allocate_and_generate_lwe_bootstrapping_key_with_pre_seeded_generator(
            &client_key.lwe_secret_key,
            &client_key.glwe_secret_key,
            pbs_params.pbs_base_log,
            pbs_params.pbs_level,
            pbs_params.glwe_noise_distribution,
            pbs_params.ciphertext_modulus,
            generator,
        );

        let modulus_switch_noise_reduction_config =
            CompressedModulusSwitchConfiguration::generate_with_pre_seeded_generator(
                &pbs_params.modulus_switch_noise_reduction_params,
                &client_key.lwe_secret_key,
                pbs_params.lwe_noise_distribution,
                pbs_params.ciphertext_modulus,
                generator,
            );

        Self {
            core_bsk,
            modulus_switch_noise_reduction_config,
        }
    }
}

impl<Scalar> CompressedShortint128BootstrappingKey<Scalar>
where
    Scalar: UnsignedTorus,
{
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        lwe_secret_key: &LweSecretKey<Vec<Scalar>>,
        ciphertext_modulus: CoreCiphertextModulus<Scalar>,
        lwe_noise_distribution: DynamicDistribution<Scalar>,
        private_noise_squashing_key: &NoiseSquashingPrivateKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
        Scalar: Encryptable<Uniform, DynamicDistribution<Scalar>>,
    {
        let noise_squashing_parameters = private_noise_squashing_key.noise_squashing_parameters();

        match noise_squashing_parameters {
            NoiseSquashingParameters::Classic(ns_params) => {
                let core_bsk =
                    allocate_and_generate_lwe_bootstrapping_key_with_pre_seeded_generator(
                        lwe_secret_key,
                        private_noise_squashing_key
                            .key
                            .post_noise_squashing_secret_key(),
                        ns_params.decomp_base_log,
                        ns_params.decomp_level_count,
                        ns_params.glwe_noise_distribution,
                        ns_params.ciphertext_modulus,
                        generator,
                    );

                let compressed_mod_switch_config =
                    CompressedModulusSwitchConfiguration::generate_with_pre_seeded_generator(
                        &ns_params.modulus_switch_noise_reduction_params,
                        lwe_secret_key,
                        lwe_noise_distribution,
                        ciphertext_modulus,
                        generator,
                    );

                Self::Classic {
                    bsk: core_bsk,
                    modulus_switch_noise_reduction_key: compressed_mod_switch_config,
                }
            }
            NoiseSquashingParameters::MultiBit(_) => {
                panic!("Multibit NoiseSquashing is not supported");
            }
        }
    }

    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> shortint::noise_squashing::Shortint128BootstrappingKey<Scalar>
    where
        Gen: ByteRandomGenerator,
    {
        let Self::Classic {
            bsk: compressed_bsk,
            modulus_switch_noise_reduction_key,
        } = self
        else {
            panic!("Noise squashing key is not a classic key")
        };

        let mut core_bsk = LweBootstrapKeyOwned::new(
            0u128,
            compressed_bsk.glwe_size(),
            compressed_bsk.polynomial_size(),
            compressed_bsk.decomposition_base_log(),
            compressed_bsk.decomposition_level_count(),
            compressed_bsk.input_lwe_dimension(),
            compressed_bsk.ciphertext_modulus(),
        );

        decompress_seeded_lwe_bootstrap_key_with_pre_seeded_generator(
            &mut core_bsk,
            compressed_bsk,
            generator,
        );

        let mut core_fourier_bsk = Fourier128LweBootstrapKeyOwned::new(
            core_bsk.input_lwe_dimension(),
            core_bsk.glwe_size(),
            core_bsk.polynomial_size(),
            core_bsk.decomposition_base_log(),
            core_bsk.decomposition_level_count(),
        );

        par_convert_standard_lwe_bootstrap_key_to_fourier_128(&core_bsk, &mut core_fourier_bsk);

        let ms_nrk =
            modulus_switch_noise_reduction_key.decompress_with_pre_seeded_generator(generator);

        Shortint128BootstrappingKey::Classic {
            bsk: core_fourier_bsk,
            modulus_switch_noise_reduction_key: ms_nrk,
        }
    }
}

#[cfg(test)]
struct ShortintMultibitCompressedBootstrappingKeyParts {
    core_bsk: SeededLweMultiBitBootstrapKeyOwned<u64>,
    deterministic_execution: bool,
}

#[cfg(test)]
impl ShortintMultibitCompressedBootstrappingKeyParts {
    fn generate_with_pre_seeded_generator<Gen>(
        client_key: &StandardAtomicPatternClientKey,
        multibit_params: MultiBitPBSParameters,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        let mut core_bsk = SeededLweMultiBitBootstrapKeyOwned::new(
            0u64,
            multibit_params.glwe_dimension.to_glwe_size(),
            multibit_params.polynomial_size,
            multibit_params.pbs_base_log,
            multibit_params.pbs_level,
            client_key.lwe_secret_key.lwe_dimension(),
            multibit_params.grouping_factor,
            CompressionSeed::from(Seed(0)),
            multibit_params.ciphertext_modulus,
        );

        generate_seeded_lwe_multi_bit_bootstrap_key_with_pre_seeded_generator(
            &client_key.lwe_secret_key,
            &client_key.glwe_secret_key,
            &mut core_bsk,
            multibit_params.glwe_noise_distribution,
            generator,
        );

        Self {
            core_bsk,
            deterministic_execution: multibit_params.deterministic_execution,
        }
    }
}

impl CompressedKS32AtomicPatternServerKey {
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        client_key_ap: &KS32AtomicPatternClientKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        let core_ksk = allocate_and_generate_lwe_key_switching_key_with_pre_seeded_generator(
            &client_key_ap.large_lwe_secret_key(),
            &client_key_ap.small_lwe_secret_key(),
            client_key_ap.parameters.ks_base_log,
            client_key_ap.parameters.ks_level,
            client_key_ap.parameters.lwe_noise_distribution,
            client_key_ap.parameters.post_keyswitch_ciphertext_modulus,
            generator,
        );

        let core_bsk = allocate_and_generate_lwe_bootstrapping_key_with_pre_seeded_generator(
            &client_key_ap.lwe_secret_key,
            &client_key_ap.glwe_secret_key,
            client_key_ap.parameters.pbs_base_log,
            client_key_ap.parameters.pbs_level,
            client_key_ap.parameters.glwe_noise_distribution,
            client_key_ap.parameters.ciphertext_modulus,
            generator,
        );

        let modulus_switch_noise_reduction_config =
            CompressedModulusSwitchConfiguration::generate_with_pre_seeded_generator(
                &client_key_ap
                    .parameters
                    .modulus_switch_noise_reduction_params,
                &client_key_ap.lwe_secret_key,
                client_key_ap.parameters.lwe_noise_distribution,
                client_key_ap.parameters.post_keyswitch_ciphertext_modulus,
                generator,
            );

        let shortint_bsk = ShortintCompressedBootstrappingKey::Classic {
            bsk: core_bsk,
            modulus_switch_noise_reduction_key: modulus_switch_noise_reduction_config,
        };

        Self::from_raw_parts(core_ksk, shortint_bsk)
    }

    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        mask_generator: &mut MaskRandomGenerator<Gen>,
    ) -> KS32AtomicPatternServerKey
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        let mut core_ksk = LweKeyswitchKey::new(
            0u32,
            self.key_switching_key().decomposition_base_log(),
            self.key_switching_key().decomposition_level_count(),
            self.key_switching_key().input_key_lwe_dimension(),
            self.key_switching_key().output_key_lwe_dimension(),
            self.key_switching_key().ciphertext_modulus(),
        );
        decompress_seeded_lwe_keyswitch_key_with_pre_seeded_generator(
            &mut core_ksk,
            self.key_switching_key(),
            mask_generator,
        );

        let shortint_bsk = self
            .bootstrapping_key()
            .decompress_with_pre_seeded_generator(mask_generator);

        KS32AtomicPatternServerKey::from_raw_parts(
            core_ksk,
            shortint_bsk,
            self.bootstrapping_key().ciphertext_modulus(),
        )
    }
}

impl CompressedAtomicPatternServerKey {
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        client_key_ap: &AtomicPatternClientKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        match client_key_ap {
            AtomicPatternClientKey::Standard(ap) => Self::Standard(
                CompressedStandardAtomicPatternServerKey::generate_with_pre_seeded_generator(
                    ap, generator,
                ),
            ),
            AtomicPatternClientKey::KeySwitch32(ap) => Self::KeySwitch32(
                CompressedKS32AtomicPatternServerKey::generate_with_pre_seeded_generator(
                    ap, generator,
                ),
            ),
        }
    }

    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        mask_generator: &mut MaskRandomGenerator<Gen>,
    ) -> AtomicPatternServerKey
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        match self {
            Self::Standard(std_ap) => AtomicPatternServerKey::Standard(
                std_ap.decompress_with_pre_seeded_generator(mask_generator),
            ),
            Self::KeySwitch32(ks32_ap) => AtomicPatternServerKey::KeySwitch32(
                ks32_ap.decompress_with_pre_seeded_generator(mask_generator),
            ),
        }
    }
}

impl<Scalar> ShortintCompressedBootstrappingKey<Scalar>
where
    Scalar: UnsignedTorus,
{
    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        mask_generator: &mut MaskRandomGenerator<Gen>,
    ) -> ShortintBootstrappingKey<Scalar>
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let core_fourier_bsk =
                    par_decompress_bootstrap_key_to_fourier_with_pre_seeded_generator(
                        bsk,
                        mask_generator,
                    );

                let modulus_switch_noise_reduction_key = modulus_switch_noise_reduction_key
                    .decompress_with_pre_seeded_generator(mask_generator);

                ShortintBootstrappingKey::Classic {
                    bsk: core_fourier_bsk,
                    modulus_switch_noise_reduction_key,
                }
            }
            Self::MultiBit {
                seeded_bsk,
                deterministic_execution,
            } => {
                let core_fourier_bsk = par_decompress_seeded_lwe_multi_bit_bootstrap_key_to_fourier_with_pre_seeded_generator(
                        seeded_bsk,
                        mask_generator
                    );

                let thread_count =
                    crate::shortint::engine::ShortintEngine::get_thread_count_for_multi_bit_pbs(
                        seeded_bsk.input_lwe_dimension(),
                        seeded_bsk.glwe_size().to_glwe_dimension(),
                        seeded_bsk.polynomial_size(),
                        seeded_bsk.decomposition_base_log(),
                        seeded_bsk.decomposition_level_count(),
                        seeded_bsk.grouping_factor(),
                    );

                ShortintBootstrappingKey::MultiBit {
                    fourier_bsk: core_fourier_bsk,
                    thread_count,
                    deterministic_execution: *deterministic_execution,
                }
            }
        }
    }
}

impl CompressedStandardAtomicPatternServerKey {
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        client_key: &StandardAtomicPatternClientKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        match client_key.parameters {
            PBSParameters::PBS(classic_pbs_parameters) => {
                let core_ksk =
                    allocate_and_generate_lwe_key_switching_key_with_pre_seeded_generator(
                        &client_key.glwe_secret_key.as_lwe_secret_key(),
                        &client_key.lwe_secret_key,
                        classic_pbs_parameters.ks_base_log,
                        classic_pbs_parameters.ks_level,
                        classic_pbs_parameters.lwe_noise_distribution,
                        classic_pbs_parameters.ciphertext_modulus,
                        generator,
                    );

                let ShortintClassicCompressedBootstrappingKeyParts {
                    core_bsk,
                    modulus_switch_noise_reduction_config,
                } = ShortintClassicCompressedBootstrappingKeyParts::generate_with_pre_seeded_generator(
                    client_key,
                    classic_pbs_parameters,
                    generator
                );

                let shortint_bsk = ShortintCompressedBootstrappingKey::Classic {
                    bsk: core_bsk,
                    modulus_switch_noise_reduction_key: modulus_switch_noise_reduction_config,
                };

                Self::from_raw_parts(
                    core_ksk,
                    shortint_bsk,
                    classic_pbs_parameters.encryption_key_choice.into(),
                )
            }
            PBSParameters::MultiBitPBS(multi_bit_pbs_parameters) => {
                let core_ksk =
                    allocate_and_generate_lwe_key_switching_key_with_pre_seeded_generator(
                        &client_key.glwe_secret_key.as_lwe_secret_key(),
                        &client_key.lwe_secret_key,
                        multi_bit_pbs_parameters.ks_base_log,
                        multi_bit_pbs_parameters.ks_level,
                        multi_bit_pbs_parameters.lwe_noise_distribution,
                        multi_bit_pbs_parameters.ciphertext_modulus,
                        generator,
                    );

                let ShortintMultibitCompressedBootstrappingKeyParts {
                    core_bsk,
                    deterministic_execution,
                } = ShortintMultibitCompressedBootstrappingKeyParts::generate_with_pre_seeded_generator(
                    client_key,
                    multi_bit_pbs_parameters,
                    generator
                );

                let shortint_bsk = ShortintCompressedBootstrappingKey::MultiBit {
                    seeded_bsk: core_bsk,
                    deterministic_execution,
                };

                Self::from_raw_parts(
                    core_ksk,
                    shortint_bsk,
                    multi_bit_pbs_parameters.encryption_key_choice.into(),
                )
            }
        }
    }

    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        mask_generator: &mut MaskRandomGenerator<Gen>,
    ) -> StandardAtomicPatternServerKey
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        let mut core_ksk = LweKeyswitchKey::new(
            0u64,
            self.key_switching_key().decomposition_base_log(),
            self.key_switching_key().decomposition_level_count(),
            self.key_switching_key().input_key_lwe_dimension(),
            self.key_switching_key().output_key_lwe_dimension(),
            self.key_switching_key().ciphertext_modulus(),
        );
        decompress_seeded_lwe_keyswitch_key_with_pre_seeded_generator(
            &mut core_ksk,
            self.key_switching_key(),
            mask_generator,
        );

        let shortint_bsk = self
            .bootstrapping_key()
            .decompress_with_pre_seeded_generator(mask_generator);

        shortint::atomic_pattern::StandardAtomicPatternServerKey::from_raw_parts(
            core_ksk,
            shortint_bsk,
            self.pbs_order(),
        )
    }
}

impl CompressedNoiseSquashingCompressionKey {
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        private_compression_noise_squashing_key: &integer::ciphertext::NoiseSquashingCompressionPrivateKey,
        private_noise_squashing_key: &NoiseSquashingPrivateKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        let compression_params = private_compression_noise_squashing_key.key.params;
        let mut packing_key_switching_key = SeededLwePackingKeyswitchKey::new(
            0u128,
            compression_params.packing_ks_base_log,
            compression_params.packing_ks_level,
            private_noise_squashing_key
                .key
                .post_noise_squashing_lwe_secret_key()
                .lwe_dimension(),
            compression_params.packing_ks_glwe_dimension,
            compression_params.packing_ks_polynomial_size,
            CompressionSeed::from(Seed(0)),
            compression_params.ciphertext_modulus,
        );

        generate_seeded_lwe_packing_keyswitch_key_with_pre_seeded_generator(
            &private_noise_squashing_key
                .key
                .post_noise_squashing_lwe_secret_key(),
            &private_compression_noise_squashing_key
                .key
                .post_packing_ks_key,
            &mut packing_key_switching_key,
            compression_params.packing_ks_key_noise_distribution,
            generator,
        );

        let key =
            shortint::list_compression::CompressedNoiseSquashingCompressionKey::from_raw_parts(
                packing_key_switching_key,
                compression_params.lwe_per_glwe,
            );

        Self { key }
    }

    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> NoiseSquashingCompressionKey
    where
        Gen: ByteRandomGenerator,
    {
        let packing_key_switching_key = self
            .key
            .packing_key_switching_key
            .decompress_to_lwe_packing_keyswitch_key_with_pre_seeded_generator(generator);

        NoiseSquashingCompressionKey {
            key: shortint::list_compression::NoiseSquashingCompressionKey::from_raw_parts(
                packing_key_switching_key,
                self.key.lwe_per_glwe,
            ),
        }
    }
}
impl CompressedKeySwitchingKeyMaterial {
    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> KeySwitchingKeyMaterial
    where
        Gen: ByteRandomGenerator,
    {
        let compressed_cpk_ksk = &self.material.key_switching_key;

        let mut key_switching_key = LweKeyswitchKey::new(
            0u64,
            compressed_cpk_ksk.decomposition_base_log(),
            compressed_cpk_ksk.decomposition_level_count(),
            compressed_cpk_ksk.input_key_lwe_dimension(),
            compressed_cpk_ksk.output_key_lwe_dimension(),
            compressed_cpk_ksk.ciphertext_modulus(),
        );
        decompress_seeded_lwe_keyswitch_key_with_pre_seeded_generator(
            &mut key_switching_key,
            compressed_cpk_ksk,
            generator,
        );
        let shortint_cpk_ksk = shortint::key_switching_key::KeySwitchingKeyMaterial {
            key_switching_key,
            cast_rshift: self.material.cast_rshift,
            destination_key: self.material.destination_key,
            destination_atomic_pattern: self.material.destination_atomic_pattern,
        };
        KeySwitchingKeyMaterial::from_raw_parts(shortint_cpk_ksk)
    }
}

impl CompressedReRandomizationKeySwitchingKey {
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        glwe_secret_key: &GlweSecretKeyOwned<u64>,
        noise_distribution: DynamicDistribution<u64>,
        ciphertext_modulus: CiphertextModulus<u64>,
        destination_atomic_pattern: KeySwitchingKeyDestinationAtomicPattern,
        key_gen_info: &ReRandomizationKeyGenerationInfo<'_>,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        match key_gen_info {
            ReRandomizationKeyGenerationInfo::UseCPKEncryptionKSK => Self::UseCPKEncryptionKSK,
            ReRandomizationKeyGenerationInfo::DedicatedKSK((
                input_cpk,
                cpk_re_randomization_ksk_params,
            )) => {
                let key_switching_key =
                    allocate_and_generate_lwe_key_switching_key_with_pre_seeded_generator(
                        &input_cpk.key.key(),
                        &glwe_secret_key.as_lwe_secret_key(),
                        cpk_re_randomization_ksk_params.ks_base_log,
                        cpk_re_randomization_ksk_params.ks_level,
                        noise_distribution,
                        ciphertext_modulus,
                        generator,
                    );

                let key = CompressedKeySwitchingKeyMaterial {
                    material: shortint::key_switching_key::CompressedKeySwitchingKeyMaterial {
                        key_switching_key,
                        cast_rshift: 0,
                        destination_key: EncryptionKeyChoice::Big,
                        destination_atomic_pattern,
                    },
                };

                Self::DedicatedKSK(key)
            }
        }
    }
}

impl<Scalar> CompressedModulusSwitchNoiseReductionKey<Scalar>
where
    Scalar: UnsignedInteger,
{
    /// Allocates and generates new `CompressedModulusSwitchNoiseReductionKey`
    ///
    /// This allocates then generates a new `CompressedModulusSwitchNoiseReductionKey`
    /// using the given `LweSecretKey` and `ModulusSwitchNoiseReductionParams`
    ///
    /// The internal seeded types will have their compression seed initialized to 0
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<NoiseDistribution, KeyCont, Gen>(
        params: &ModulusSwitchNoiseReductionParams,
        lwe_secret_key: &LweSecretKey<KeyCont>,
        noise_distribution: NoiseDistribution,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Scalar: Encryptable<Uniform, NoiseDistribution>,
        NoiseDistribution: Distribution,
        KeyCont: Container<Element = Scalar>,
        Gen: ByteRandomGenerator,
    {
        let mut modulus_switch_zeros = SeededLweCiphertextList::new(
            Scalar::ZERO,
            lwe_secret_key.lwe_dimension().to_lwe_size(),
            params.modulus_switch_zeros_count,
            CompressionSeed { seed: Seed(0) },
            ciphertext_modulus,
        );
        let plaintext_list = PlaintextList::new(
            Scalar::ZERO,
            PlaintextCount(params.modulus_switch_zeros_count.0),
        );
        encrypt_seeded_lwe_ciphertext_list_with_pre_seeded_generator(
            lwe_secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            noise_distribution,
            generator,
        );

        Self {
            modulus_switch_zeros,
            ms_bound: params.ms_bound,
            ms_r_sigma_factor: params.ms_r_sigma_factor,
            ms_input_variance: params.ms_input_variance,
        }
    }
}

impl<Scalar> CompressedModulusSwitchNoiseReductionKey<Scalar>
where
    Scalar: UnsignedTorus,
{
    /// Decompress using an existing generator, ignoring
    /// the seed(s) stored in the compressed type
    pub(crate) fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> ModulusSwitchNoiseReductionKey<Scalar>
    where
        Gen: ByteRandomGenerator,
    {
        let mut decompressed_list = LweCiphertextList::new(
            Scalar::ZERO,
            self.modulus_switch_zeros.lwe_size(),
            self.modulus_switch_zeros.lwe_ciphertext_count(),
            self.modulus_switch_zeros.ciphertext_modulus(),
        );

        decompress_seeded_lwe_ciphertext_list_with_pre_seeded_generator(
            &mut decompressed_list,
            &self.modulus_switch_zeros,
            generator,
        );

        ModulusSwitchNoiseReductionKey {
            modulus_switch_zeros: decompressed_list,
            ms_bound: self.ms_bound,
            ms_r_sigma_factor: self.ms_r_sigma_factor,
            ms_input_variance: self.ms_input_variance,
        }
    }
}

impl<Scalar> CompressedModulusSwitchConfiguration<Scalar>
where
    Scalar: UnsignedInteger,
{
    /// Generates using an existing generator
    ///
    /// The internal seeded types will have their compression seed initialized to 0
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<NoiseDistribution, Gen>(
        mod_switch_type: &ModulusSwitchType,
        lwe_secret_key: &LweSecretKeyOwned<Scalar>,
        noise_distribution: NoiseDistribution,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        encryption_rand_gen: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Scalar: Encryptable<Uniform, NoiseDistribution>,
        NoiseDistribution: Distribution,
        Gen: ByteRandomGenerator,
    {
        match mod_switch_type {
            ModulusSwitchType::Standard => Self::Standard,
            ModulusSwitchType::DriftTechniqueNoiseReduction(params) => {
                Self::DriftTechniqueNoiseReduction(
                    CompressedModulusSwitchNoiseReductionKey::generate_with_pre_seeded_generator(
                        params,
                        lwe_secret_key,
                        noise_distribution,
                        ciphertext_modulus,
                        encryption_rand_gen,
                    ),
                )
            }
            ModulusSwitchType::CenteredMeanNoiseReduction => Self::CenteredMeanNoiseReduction,
        }
    }
}

impl<Scalar> CompressedModulusSwitchConfiguration<Scalar>
where
    Scalar: UnsignedTorus,
{
    /// Decompress using an existing generator, ignoring
    /// the seed(s) stored in the compressed type
    pub(crate) fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> ModulusSwitchConfiguration<Scalar>
    where
        Gen: ByteRandomGenerator,
    {
        match self {
            Self::Standard => ModulusSwitchConfiguration::Standard,
            Self::CenteredMeanNoiseReduction => {
                ModulusSwitchConfiguration::CenteredMeanNoiseReduction
            }
            Self::DriftTechniqueNoiseReduction(key) => {
                ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                    key.decompress_with_pre_seeded_generator(generator),
                )
            }
        }
    }
}

fn par_decompress_bootstrap_key_to_fourier_with_pre_seeded_generator<Gen>(
    compressed_bsk: &SeededLweBootstrapKeyOwned<u64>,
    mask_generator: &mut MaskRandomGenerator<Gen>,
) -> FourierLweBootstrapKey<ABox<[c64]>>
where
    Gen: ByteRandomGenerator,
{
    let mut core_bsk = LweBootstrapKeyOwned::new(
        0u64,
        compressed_bsk.glwe_size(),
        compressed_bsk.polynomial_size(),
        compressed_bsk.decomposition_base_log(),
        compressed_bsk.decomposition_level_count(),
        compressed_bsk.input_lwe_dimension(),
        compressed_bsk.ciphertext_modulus(),
    );

    decompress_seeded_lwe_bootstrap_key_with_pre_seeded_generator(
        &mut core_bsk,
        compressed_bsk,
        mask_generator,
    );

    let mut core_fourier_bsk = FourierLweBootstrapKey::new(
        core_bsk.input_lwe_dimension(),
        core_bsk.glwe_size(),
        core_bsk.polynomial_size(),
        core_bsk.decomposition_base_log(),
        core_bsk.decomposition_level_count(),
    );

    par_convert_standard_lwe_bootstrap_key_to_fourier(&core_bsk, &mut core_fourier_bsk);

    core_fourier_bsk
}

fn par_decompress_seeded_lwe_multi_bit_bootstrap_key_to_fourier_with_pre_seeded_generator<Gen>(
    seeded_bsk: &SeededLweMultiBitBootstrapKeyOwned<u64>,
    mask_generator: &mut MaskRandomGenerator<Gen>,
) -> FourierLweMultiBitBootstrapKeyOwned
where
    Gen: ParallelByteRandomGenerator,
{
    let mut core_bsk = LweMultiBitBootstrapKeyOwned::new(
        0u64,
        seeded_bsk.glwe_size(),
        seeded_bsk.polynomial_size(),
        seeded_bsk.decomposition_base_log(),
        seeded_bsk.decomposition_level_count(),
        seeded_bsk.input_lwe_dimension(),
        seeded_bsk.grouping_factor(),
        seeded_bsk.ciphertext_modulus(),
    );

    par_decompress_seeded_lwe_multi_bit_bootstrap_key_with_pre_seeded_generator(
        &mut core_bsk,
        seeded_bsk,
        mask_generator,
    );

    let mut core_fourier_bsk = FourierLweMultiBitBootstrapKeyOwned::new(
        core_bsk.input_lwe_dimension(),
        core_bsk.glwe_size(),
        core_bsk.polynomial_size(),
        core_bsk.decomposition_base_log(),
        core_bsk.decomposition_level_count(),
        core_bsk.grouping_factor(),
    );

    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&core_bsk, &mut core_fourier_bsk);

    core_fourier_bsk
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::prelude::new_seeder;
    use crate::prelude::*;
    use crate::shortint::client_key::atomic_pattern::EncryptionAtomicPattern;
    use crate::xof_key_set::{CompressedXofKeySet, XofKeySet};
    use crate::*;

    impl CompressedXofKeySet {
        fn with_seed(pub_seed: XofSeed, priv_seed: XofSeed, ck: &ClientKey) -> crate::Result<Self> {
            let Some(dedicated_pk_key) = ck.key.dedicated_compact_private_key.as_ref() else {
                return Err(crate::error!("Dedicated compact private key is required"));
            };

            let mask_random_generator =
                MaskRandomGenerator::<DefaultRandomGenerator>::new(pub_seed.clone());
            let noise_random_generator = NoiseRandomGenerator::new_from_seed(priv_seed);
            let mut encryption_rand_gen = EncryptionRandomGenerator::from_raw_parts(
                mask_random_generator,
                noise_random_generator,
            );

            let computation_parameters: ShortintParameterSet = ck.key.key.parameters().into();
            let shortint_client_key = &ck.key.key.key;

            // First, the public key used to encrypt
            // It uses separate parameters from the computation ones
            let compressed_public_key =
                CompressedCompactPublicKey::generate_with_pre_seeded_generator(
                    dedicated_pk_key,
                    &mut encryption_rand_gen,
                    ck.tag.clone(),
                );

            let glwe_secret_key = match &shortint_client_key.atomic_pattern {
                AtomicPatternClientKey::Standard(ap) => &ap.glwe_secret_key,
                AtomicPatternClientKey::KeySwitch32(ks32_ap) => &ks32_ap.glwe_secret_key,
            };

            let compression_key = ck
                .key
                .compression_key
                .as_ref()
                .map(|private_compression_key| {
                    // Compression requires EncryptionKey::Big, but if that was not the case,
                    // the private_compression_key would not have been generated
                    integer::compression_keys::CompressedCompressionKey::generate_with_pre_seeded_generator(
                        private_compression_key,
                        glwe_secret_key,
                        computation_parameters.ciphertext_modulus(),
                        &mut encryption_rand_gen,
                    )
                });

            let decompression_key = ck
                .key
                .compression_key
                .as_ref()
                .map(|private_compression_key| {
                    integer::compression_keys::CompressedDecompressionKey::generate_with_pre_seeded_generator(
                        private_compression_key,
                        glwe_secret_key,
                        computation_parameters,
                        &mut encryption_rand_gen,
                    )
                });

            // Now, we generate the server key (ksk, then bsk)
            let integer_compressed_server_key = {
                let compressed_ap_server_key =
                    CompressedAtomicPatternServerKey::generate_with_pre_seeded_generator(
                        &shortint_client_key.atomic_pattern,
                        &mut encryption_rand_gen,
                    );

                let max_degree = MaxDegree::integer_radix_server_key(
                    computation_parameters.message_modulus(),
                    computation_parameters.carry_modulus(),
                );

                integer::CompressedServerKey::from_raw_parts(
                    shortint::CompressedServerKey::from_raw_parts(
                        compressed_ap_server_key,
                        computation_parameters.message_modulus(),
                        computation_parameters.carry_modulus(),
                        max_degree,
                        computation_parameters.max_noise_level(),
                    ),
                )
            };

            let noise_squashing_bs_key =
                ck.key
                    .noise_squashing_private_key
                    .as_ref()
                    .map(|noise_squashing_key| {
                        CompressedNoiseSquashingKey::generate_with_pre_seeded_generator(
                            noise_squashing_key,
                            &shortint_client_key.atomic_pattern,
                            &mut encryption_rand_gen,
                        )
                    });

            // Generate the key switching material that will allow going from
            // the public key's dedicated parameters to the computation parameters
            let pk_to_sk_ksk_params = dedicated_pk_key.1;

            let integer_ksk_material = {
                let noise_distrib = match pk_to_sk_ksk_params.destination_key {
                    EncryptionKeyChoice::Big => computation_parameters.glwe_noise_distribution(),
                    EncryptionKeyChoice::Small => computation_parameters.lwe_noise_distribution(),
                };

                let key_switching_key = match &ck.key.key.key.atomic_pattern {
                    AtomicPatternClientKey::Standard(std_ap) => {
                        let target_private_key = match pk_to_sk_ksk_params.destination_key {
                            EncryptionKeyChoice::Big => std_ap.glwe_secret_key.as_lwe_secret_key(),
                            EncryptionKeyChoice::Small => std_ap.lwe_secret_key.as_view(),
                        };

                        allocate_and_generate_lwe_key_switching_key_with_pre_seeded_generator(
                            &dedicated_pk_key.0.key.key(),
                            &target_private_key,
                            pk_to_sk_ksk_params.ks_base_log,
                            pk_to_sk_ksk_params.ks_level,
                            noise_distrib,
                            computation_parameters.ciphertext_modulus(),
                            &mut encryption_rand_gen,
                        )
                    }
                    AtomicPatternClientKey::KeySwitch32(ks32_ap) => {
                        match pk_to_sk_ksk_params.destination_key {
                            EncryptionKeyChoice::Big => {
                                allocate_and_generate_lwe_key_switching_key_with_pre_seeded_generator(
                                    &dedicated_pk_key.0.key.key(),
                                    &ks32_ap.glwe_secret_key.as_lwe_secret_key(),
                                    pk_to_sk_ksk_params.ks_base_log,
                                    pk_to_sk_ksk_params.ks_level,
                                    noise_distrib,
                                    computation_parameters.ciphertext_modulus(),
                                    &mut encryption_rand_gen,
                                )
                            }
                            EncryptionKeyChoice::Small => {
                                // TODO: here we copy full secret key.
                                // this should be reworked to avoid this copy once the spec is final
                                let u64_container = ks32_ap
                                    .lwe_secret_key
                                    .as_ref()
                                    .iter()
                                    .copied()
                                    .map(|v| v as u64)
                                    .collect::<Vec<_>>();
                                let lwe_secret_key_u64 =
                                    LweSecretKey::from_container(u64_container);
                                allocate_and_generate_lwe_key_switching_key_with_pre_seeded_generator(
                                    &dedicated_pk_key.0.key.key(),
                                    &lwe_secret_key_u64,
                                    pk_to_sk_ksk_params.ks_base_log,
                                    pk_to_sk_ksk_params.ks_level,
                                    noise_distrib,
                                    ks32_ap.parameters.post_keyswitch_ciphertext_modulus.try_to().unwrap(),
                                    &mut encryption_rand_gen,
                                )
                            }
                        }
                    }
                };

                CompressedKeySwitchingKeyMaterial {
                    material: shortint::key_switching_key::CompressedKeySwitchingKeyMaterial {
                        key_switching_key,
                        cast_rshift: 0,
                        destination_key: dedicated_pk_key.1.destination_key,
                        destination_atomic_pattern: ck.key.key.key.atomic_pattern.kind().into(),
                    },
                }
            };

            // Generate the key switching material that will allow going from
            // the public key's dedicated parameters to the re-rand
            let cpk_re_randomization_key_switching_key_material = ck
                .key
                .re_randomization_ksk_gen_info()?
                .as_ref()
                .map(|key_gen_info| {
                    CompressedReRandomizationKeySwitchingKey::generate_with_pre_seeded_generator(
                        glwe_secret_key,
                        computation_parameters.glwe_noise_distribution(),
                        computation_parameters.ciphertext_modulus(),
                        computation_parameters.atomic_pattern().into(),
                        key_gen_info,
                        &mut encryption_rand_gen,
                    )
                });

            let noise_squashing_compression_key =
                ck.key.noise_squashing_compression_private_key.as_ref().map(
                    |ns_compression_priv_key| {
                        CompressedNoiseSquashingCompressionKey::generate_with_pre_seeded_generator(
                            ns_compression_priv_key,
                            ck.key.noise_squashing_private_key.as_ref().unwrap(),
                            &mut encryption_rand_gen,
                        )
                    },
                );

            let compressed_server_key = CompressedServerKey::from_raw_parts(
                integer_compressed_server_key,
                Some(integer_ksk_material),
                compression_key,
                decompression_key,
                noise_squashing_bs_key,
                noise_squashing_compression_key,
                cpk_re_randomization_key_switching_key_material,
                ck.tag.clone(),
            );

            Ok(Self {
                seed: pub_seed,
                compressed_public_key,
                compressed_server_key,
            })
        }
    }

    #[test]
    fn test_xof_key_set_classic_params() {
        let params =
            shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let cpk_params = shortint::parameters::test_params::TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let casting_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let compression_params =
            shortint::parameters::test_params::TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let re_rand_ksk_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let config = ConfigBuilder::with_custom_parameters(params)
            .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
            .enable_noise_squashing(noise_squashing_params)
            .enable_noise_squashing_compression(noise_squashing_compression_params)
            .enable_compression(compression_params)
            .enable_ciphertext_re_randomization(re_rand_ksk_params)
            .build();

        let mut cks = ClientKey::generate(config);
        cks.tag_mut().set_data(b"classic 2_2");

        let mut seeder = new_seeder();
        let pub_seed = XofSeed::new_u128(
            seeder.seed().0,
            [b'T', b'F', b'H', b'E', b'_', b'G', b'E', b'N'],
        );
        let priv_seed = XofSeed::new_u128(
            seeder.seed().0,
            [b'T', b'F', b'H', b'E', b'K', b'G', b'e', b'n'],
        );

        let compressed_key_set = CompressedXofKeySet::with_seed(pub_seed, priv_seed, &cks).unwrap();
        assert_eq!(cks.tag(), compressed_key_set.compressed_public_key.tag());
        assert_eq!(cks.tag(), compressed_key_set.compressed_server_key.tag());
        test_xof_key_set(&compressed_key_set, config, &cks);
    }

    #[test]
    fn test_xof_key_set_ks32_params_big_pke() {
        let params =
            shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
        let cpk_params = shortint::parameters::test_params::TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;
        let casting_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let compression_params =
            shortint::parameters::test_params::TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let re_rand_ksk_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let config = ConfigBuilder::with_custom_parameters(params)
            .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
            .enable_noise_squashing(noise_squashing_params)
            .enable_noise_squashing_compression(noise_squashing_compression_params)
            .enable_compression(compression_params)
            .enable_ciphertext_re_randomization(re_rand_ksk_params)
            .build();

        let mut cks = ClientKey::generate(config);
        cks.tag_mut().set_data(b"ks32 big pke");

        let mut seeder = new_seeder();
        let pub_seed = XofSeed::new_u128(
            seeder.seed().0,
            [b'T', b'F', b'H', b'E', b'_', b'G', b'E', b'N'],
        );
        let priv_seed = XofSeed::new_u128(
            seeder.seed().0,
            [b'T', b'F', b'H', b'E', b'K', b'G', b'e', b'n'],
        );

        let compressed_key_set = CompressedXofKeySet::with_seed(pub_seed, priv_seed, &cks).unwrap();
        assert_eq!(cks.tag(), compressed_key_set.compressed_public_key.tag());
        assert_eq!(cks.tag(), compressed_key_set.compressed_server_key.tag());
        test_xof_key_set(&compressed_key_set, config, &cks);
    }

    #[test]
    fn test_xof_key_set_ks32_params_small_pke() {
        let params =
            shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
        let cpk_params = shortint::parameters::test_params::TEST_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;
        let casting_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let compression_params =
            shortint::parameters::test_params::TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let re_rand_ksk_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let config = ConfigBuilder::with_custom_parameters(params)
            .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
            .enable_noise_squashing(noise_squashing_params)
            .enable_noise_squashing_compression(noise_squashing_compression_params)
            .enable_compression(compression_params)
            .enable_ciphertext_re_randomization(re_rand_ksk_params)
            .build();

        let mut cks = ClientKey::generate(config);
        cks.tag_mut().set_data(b"ks32 small pke");

        let mut seeder = new_seeder();
        let pub_seed = XofSeed::new_u128(
            seeder.seed().0,
            [b'T', b'F', b'H', b'E', b'_', b'G', b'E', b'N'],
        );
        let priv_seed = XofSeed::new_u128(
            seeder.seed().0,
            [b'T', b'F', b'H', b'E', b'K', b'G', b'e', b'n'],
        );

        let compressed_key_set = CompressedXofKeySet::with_seed(pub_seed, priv_seed, &cks).unwrap();
        assert_eq!(cks.tag(), compressed_key_set.compressed_public_key.tag());
        assert_eq!(cks.tag(), compressed_key_set.compressed_server_key.tag());
        test_xof_key_set(&compressed_key_set, config, &cks);
    }

    fn test_xof_key_set(compressed_key_set: &CompressedXofKeySet, config: Config, cks: &ClientKey) {
        let compressed_size_limit = 1 << 30;
        let mut data = vec![];
        crate::safe_serialization::safe_serialize(
            compressed_key_set,
            &mut data,
            compressed_size_limit,
        )
        .unwrap();
        let compressed_key_set: CompressedXofKeySet =
            crate::safe_serialization::safe_deserialize(data.as_slice(), compressed_size_limit)
                .unwrap();

        let expected_pk_tag = compressed_key_set.compressed_public_key.tag().clone();
        let expected_sk_tag = compressed_key_set.compressed_server_key.tag().clone();
        let key_set = compressed_key_set.decompress().unwrap();

        let size_limit = 1 << 32;
        let mut data = vec![];
        crate::safe_serialization::safe_serialize(&key_set, &mut data, size_limit).unwrap();
        let key_set: XofKeySet =
            crate::safe_serialization::safe_deserialize(data.as_slice(), size_limit).unwrap();

        let (pk, sk) = key_set.into_raw_parts();
        assert_eq!(pk.tag(), &expected_pk_tag);
        assert_eq!(sk.tag(), &expected_sk_tag);

        assert!(sk.is_conformant(&config.into()));

        set_server_key(sk);

        let clear_a = rand::random::<u32>();
        let clear_b = rand::random::<u32>();

        let list = CompactCiphertextList::builder(&pk)
            .push(clear_a)
            .push(clear_b)
            .build();
        let expander = list.expand().unwrap();
        let mut a = expander.get::<FheUint32>(0).unwrap().unwrap();
        let mut b = expander.get::<FheUint32>(1).unwrap().unwrap();

        // Test re-randomization
        {
            // Simulate a 256 bits nonce
            let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
            let compact_public_encryption_domain_separator = *b"TFHE_Enc";
            let rerand_domain_separator = *b"TFHE_Rrd";

            let mut re_rand_context = ReRandomizationContext::new(
                rerand_domain_separator,
                // First is the function description, second is a nonce
                [b"FheUint32 bin ops".as_slice(), nonce.as_slice()],
                compact_public_encryption_domain_separator,
            );

            re_rand_context.add_ciphertext(&a);
            re_rand_context.add_ciphertext(&b);

            let mut seed_gen = re_rand_context.finalize();

            a.re_randomize(&pk, seed_gen.next_seed().unwrap()).unwrap();

            b.re_randomize(&pk, seed_gen.next_seed().unwrap()).unwrap();
        }

        let c = &a * &b;
        let d = &a & &b;

        let c_dec: u32 = c.decrypt(cks);
        let d_dec: u32 = d.decrypt(cks);

        assert_eq!(clear_a.wrapping_mul(clear_b), c_dec);
        assert_eq!(clear_a & clear_b, d_dec);

        let ns_c = c.squash_noise().unwrap();
        let ns_c_dec: u32 = ns_c.decrypt(cks);
        assert_eq!(clear_a.wrapping_mul(clear_b), ns_c_dec);

        let ns_d = d.squash_noise().unwrap();
        let ns_d_dec: u32 = ns_d.decrypt(cks);
        assert_eq!(clear_a & clear_b, ns_d_dec);

        let compressed_list = CompressedCiphertextListBuilder::new()
            .push(a)
            .push(b)
            .push(c)
            .push(d)
            .build()
            .unwrap();

        let a: FheUint32 = compressed_list.get(0).unwrap().unwrap();
        let da: u32 = a.decrypt(cks);
        assert_eq!(da, clear_a);
        let b: FheUint32 = compressed_list.get(1).unwrap().unwrap();
        let db: u32 = b.decrypt(cks);
        assert_eq!(db, clear_b);
        let c: FheUint32 = compressed_list.get(2).unwrap().unwrap();
        let dc: u32 = c.decrypt(cks);
        assert_eq!(dc, clear_a.wrapping_mul(clear_b));
        let d: FheUint32 = compressed_list.get(3).unwrap().unwrap();
        let db: u32 = d.decrypt(cks);
        assert_eq!(db, clear_a & clear_b);

        let ns_compressed_list = CompressedSquashedNoiseCiphertextListBuilder::new()
            .push(ns_c)
            .push(ns_d)
            .build()
            .unwrap();

        let ns_c: SquashedNoiseFheUint = ns_compressed_list.get(0).unwrap().unwrap();
        let dc: u32 = ns_c.decrypt(cks);
        assert_eq!(dc, clear_a.wrapping_mul(clear_b));
        let ns_d: SquashedNoiseFheUint = ns_compressed_list.get(1).unwrap().unwrap();
        let db: u32 = ns_d.decrypt(cks);
        assert_eq!(db, clear_a & clear_b);
    }
}
