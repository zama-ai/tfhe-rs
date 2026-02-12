use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::math::random::{CompressionSeed, Distribution, Uniform};
use crate::core_crypto::prelude::*;

use crate::integer::ciphertext::{
    CompressedNoiseSquashingCompressionKey, NoiseSquashingCompressionKey,
};
use crate::integer::compression_keys::{CompressionKey, CompressionPrivateKeys};
use crate::integer::key_switching_key::{
    CompressedKeySwitchingKeyMaterial, KeySwitchingKeyMaterial,
};
use crate::integer::noise_squashing::{CompressedNoiseSquashingKey, NoiseSquashingPrivateKey};

use crate::shortint::atomic_pattern::compressed::{
    CompressedAtomicPatternServerKey, CompressedKS32AtomicPatternServerKey,
    CompressedStandardAtomicPatternServerKey,
};
use crate::shortint::client_key::atomic_pattern::{
    AtomicPatternClientKey, KS32AtomicPatternClientKey, StandardAtomicPatternClientKey,
};
use crate::shortint::noise_squashing::atomic_pattern::compressed::CompressedAtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::CompressedShortint128BootstrappingKey;
use crate::shortint::parameters::{
    CompactPublicKeyEncryptionParameters, CompressionParameters,
    NoiseSquashingCompressionParameters, NoiseSquashingParameters, ShortintKeySwitchingParameters,
};
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, CompressedModulusSwitchNoiseReductionKey,
    ModulusSwitchConfiguration, ModulusSwitchNoiseReductionKey, ShortintCompressedBootstrappingKey,
};
use crate::shortint::AtomicPatternParameters;
use crate::{
    integer, shortint, ClientKey, CompactPublicKey, CompressedCompactPublicKey,
    CompressedReRandomizationKeySwitchingKey, Config, ReRandomizationKeySwitchingKey, Tag,
};

use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus as CoreCiphertextModulus;
use crate::high_level_api::keys::expanded::{
    ExpandedAtomicPatternNoiseSquashingKey, ExpandedDecompressionKey, ExpandedNoiseSquashingKey,
    IntegerExpandedServerKey, ShortintExpandedBootstrappingKey, ShortintExpandedServerKey,
};
use crate::high_level_api::keys::{CompactPrivateKey, ReRandomizationKeyGenerationInfo};
use crate::shortint::atomic_pattern::expanded::{
    ExpandedAtomicPatternServerKey, ExpandedKS32AtomicPatternServerKey,
    ExpandedStandardAtomicPatternServerKey,
};
use crate::shortint::key_switching_key::KeySwitchingKeyDestinationAtomicPattern;
use crate::shortint::noise_squashing::atomic_pattern::compressed::standard::CompressedStandardAtomicPatternNoiseSquashingKey;
use crate::shortint::parameters::ModulusSwitchNoiseReductionParams;
use crate::shortint::prelude::ModulusSwitchType;
use crate::shortint::{
    ClassicPBSParameters, MultiBitPBSParameters, PBSParameters, ShortintParameterSet,
};
use tfhe_csprng::seeders::Seed;

impl crate::integer::CompactPrivateKey<Vec<u64>> {
    pub(super) fn generate_with_pre_seeded_generator<G>(
        params: CompactPublicKeyEncryptionParameters,
        max_norm_hwt: NormalizedHammingWeightBound,
        secret_generator: &mut SecretRandomGenerator<G>,
    ) -> crate::Result<Self>
    where
        G: ByteRandomGenerator,
    {
        let mut dedicated_pk_sk =
            LweSecretKey::new_empty_key(0u64, params.encryption_lwe_dimension);
        generate_binary_lwe_secret_key_with_bounded_hamming_weight(
            &mut dedicated_pk_sk,
            secret_generator,
            max_norm_hwt,
        );

        crate::shortint::CompactPrivateKey::from_raw_parts(dedicated_pk_sk, params)
            .map(|key| Self { key })
    }
}

impl crate::integer::ClientKey {
    pub(super) fn generate_with_pre_seeded_generator<G>(
        params: AtomicPatternParameters,
        max_norm_hwt: NormalizedHammingWeightBound,
        secret_generator: &mut SecretRandomGenerator<G>,
    ) -> Self
    where
        G: ByteRandomGenerator,
    {
        let shortint_ck = match params {
            shortint::AtomicPatternParameters::Standard(std_params) => {
                let mut lwe_secret_key =
                    LweSecretKey::new_empty_key(0u64, std_params.lwe_dimension());
                generate_binary_lwe_secret_key_with_bounded_hamming_weight(
                    &mut lwe_secret_key,
                    secret_generator,
                    max_norm_hwt,
                );

                let mut glwe_secret_key = GlweSecretKey::new_empty_key(
                    0u64,
                    std_params.glwe_dimension(),
                    std_params.polynomial_size(),
                );
                generate_binary_glwe_secret_key_with_bounded_hamming_weight(
                    &mut glwe_secret_key,
                    secret_generator,
                    max_norm_hwt,
                );

                shortint::ClientKey {
                    atomic_pattern: AtomicPatternClientKey::Standard(
                        StandardAtomicPatternClientKey {
                            glwe_secret_key,
                            lwe_secret_key,
                            parameters: std_params,
                        },
                    ),
                }
            }
            shortint::AtomicPatternParameters::KeySwitch32(ks32_params) => {
                let mut lwe_secret_key =
                    LweSecretKey::new_empty_key(0u32, ks32_params.lwe_dimension());
                generate_binary_lwe_secret_key_with_bounded_hamming_weight(
                    &mut lwe_secret_key,
                    secret_generator,
                    max_norm_hwt,
                );

                let mut glwe_secret_key = GlweSecretKey::new_empty_key(
                    0u64,
                    ks32_params.glwe_dimension(),
                    ks32_params.polynomial_size(),
                );
                generate_binary_glwe_secret_key_with_bounded_hamming_weight(
                    &mut glwe_secret_key,
                    secret_generator,
                    max_norm_hwt,
                );

                shortint::ClientKey {
                    atomic_pattern: AtomicPatternClientKey::KeySwitch32(
                        KS32AtomicPatternClientKey {
                            glwe_secret_key,
                            lwe_secret_key,
                            parameters: ks32_params,
                        },
                    ),
                }
            }
        };

        Self { key: shortint_ck }
    }
}

impl crate::integer::compression_keys::CompressionPrivateKeys {
    pub(super) fn generate_with_pre_seeded_generator<G>(
        params: CompressionParameters,
        max_norm_hwt: NormalizedHammingWeightBound,
        secret_generator: &mut SecretRandomGenerator<G>,
    ) -> Self
    where
        G: ByteRandomGenerator,
    {
        let mut post_packing_ks_key = GlweSecretKey::new_empty_key(
            0u64,
            params.packing_ks_glwe_dimension(),
            params.packing_ks_polynomial_size(),
        );
        generate_binary_glwe_secret_key_with_bounded_hamming_weight(
            &mut post_packing_ks_key,
            secret_generator,
            max_norm_hwt,
        );

        Self {
            key: crate::shortint::list_compression::CompressionPrivateKeys {
                post_packing_ks_key,
                params,
            },
        }
    }
}

impl crate::integer::noise_squashing::NoiseSquashingPrivateKey {
    pub(super) fn generate_with_pre_seeded_generator<G>(
        params: NoiseSquashingParameters,
        max_norm_hwt: NormalizedHammingWeightBound,
        secret_generator: &mut SecretRandomGenerator<G>,
    ) -> Self
    where
        G: ByteRandomGenerator,
    {
        let mut post_noise_squashing_secret_key =
            GlweSecretKey::new_empty_key(0u128, params.glwe_dimension(), params.polynomial_size());
        generate_binary_glwe_secret_key_with_bounded_hamming_weight(
            &mut post_noise_squashing_secret_key,
            secret_generator,
            max_norm_hwt,
        );

        Self {
            key: crate::shortint::noise_squashing::NoiseSquashingPrivateKey::from_raw_parts(
                post_noise_squashing_secret_key,
                params,
            ),
        }
    }
}

impl crate::integer::ciphertext::NoiseSquashingCompressionPrivateKey {
    pub(super) fn generate_with_pre_seeded_generator<G>(
        params: NoiseSquashingCompressionParameters,
        max_norm_hwt: NormalizedHammingWeightBound,
        secret_generator: &mut SecretRandomGenerator<G>,
    ) -> Self
    where
        G: ByteRandomGenerator,
    {
        let mut post_packing_ks_key = GlweSecretKey::new_empty_key(
            0u128,
            params.packing_ks_glwe_dimension,
            params.packing_ks_polynomial_size,
        );
        generate_binary_glwe_secret_key_with_bounded_hamming_weight(
            &mut post_packing_ks_key,
            secret_generator,
            max_norm_hwt,
        );

        Self {
            key: crate::shortint::list_compression::NoiseSquashingCompressionPrivateKey::from_raw_parts(post_packing_ks_key, params),
        }
    }
}

impl ClientKey {
    pub(super) fn generate_with_pre_seeded_generator<G>(
        config: Config,
        max_norm_hwt: NormalizedHammingWeightBound,
        tag: Tag,
        secret_generator: &mut SecretRandomGenerator<G>,
    ) -> crate::Result<Self>
    where
        G: ByteRandomGenerator,
    {
        let Some(dedicated_pk_params) = config.inner.dedicated_compact_public_key_parameters else {
            return Err(crate::error!(
                "Dedicated compact public key parameters are required"
            ));
        };

        let dedicated_compact_private_key =
            crate::integer::CompactPrivateKey::<Vec<u64>>::generate_with_pre_seeded_generator(
                dedicated_pk_params.0,
                max_norm_hwt,
                secret_generator,
            )?;

        let integer_ck = crate::integer::ClientKey::generate_with_pre_seeded_generator(
            config.inner.block_parameters,
            max_norm_hwt,
            secret_generator,
        );

        let integer_compression_private_key = config.inner.compression_parameters.map(|params| {
            crate::integer::compression_keys::CompressionPrivateKeys::generate_with_pre_seeded_generator(params, max_norm_hwt, secret_generator)
        });

        let integer_private_noise_squashing_key = config.inner.noise_squashing_parameters.map(|params| {
            crate::integer::noise_squashing::NoiseSquashingPrivateKey::generate_with_pre_seeded_generator(params, max_norm_hwt, secret_generator)
        });

        let integer_private_noise_squashing_compression_key = config.inner.noise_squashing_compression_parameters.map(|params| {
            crate::integer::ciphertext::NoiseSquashingCompressionPrivateKey::generate_with_pre_seeded_generator(params, max_norm_hwt, secret_generator)
        });

        Ok(Self {
            key: crate::high_level_api::keys::IntegerClientKey {
                key: integer_ck,
                dedicated_compact_private_key: Some((
                    dedicated_compact_private_key,
                    dedicated_pk_params.1,
                )),
                compression_key: integer_compression_private_key,
                noise_squashing_private_key: integer_private_noise_squashing_key,
                noise_squashing_compression_private_key:
                    integer_private_noise_squashing_compression_key,
                cpk_re_randomization_ksk_params: config.inner.cpk_re_randomization_ksk_params,
            },
            tag,
        })
    }
}

impl CompressedCompactPublicKey {
    pub(super) fn generate_with_pre_seeded_generator<Gen>(
        private_key: &CompactPrivateKey,
        tag: Tag,
        generator: &mut EncryptionRandomGenerator<Gen>,
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

    pub(super) fn decompress_with_pre_seeded_generator<Gen>(
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

impl crate::CompressedServerKey {
    pub(super) fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> IntegerExpandedServerKey
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        let compression_key = self
            .integer_key
            .compression_key
            .as_ref()
            .map(|k| k.decompress_with_pre_seeded_generator(generator));

        let decompression_key = self
            .integer_key
            .decompression_key
            .as_ref()
            .map(|k| k.decompress_with_pre_seeded_generator(generator));

        let shortint_sk = &self.integer_key.key.key;

        let atomic_pattern_key = shortint_sk
            .compressed_ap_server_key
            .decompress_with_pre_seeded_generator(generator);

        let compute_key = ShortintExpandedServerKey {
            atomic_pattern: atomic_pattern_key,
            message_modulus: shortint_sk.message_modulus,
            carry_modulus: shortint_sk.carry_modulus,
            max_degree: shortint_sk.max_degree,
            max_noise_level: shortint_sk.max_noise_level,
            ciphertext_modulus: shortint_sk.ciphertext_modulus(),
        };

        let noise_squashing_key = self
            .integer_key
            .noise_squashing_key
            .as_ref()
            .map(|compressed_nsk| compressed_nsk.decompress_with_pre_seeded_generator(generator));

        let cpk_key_switching_key_material = self
            .integer_key
            .cpk_key_switching_key_material
            .as_ref()
            .map(|k| k.decompress_with_pre_seeded_generator(generator));

        let cpk_re_randomization_key_switching_key_material = self
            .integer_key
            .cpk_re_randomization_key_switching_key_material
            .as_ref()
            .map(|k| match k {
                crate::CompressedReRandomizationKeySwitchingKey::UseCPKEncryptionKSK => {
                    ReRandomizationKeySwitchingKey::UseCPKEncryptionKSK
                }
                crate::CompressedReRandomizationKeySwitchingKey::DedicatedKSK(key) => {
                    ReRandomizationKeySwitchingKey::DedicatedKSK(
                        key.decompress_with_pre_seeded_generator(generator),
                    )
                }
            });

        let noise_squashing_compression_key = self
            .integer_key
            .noise_squashing_compression_key
            .as_ref()
            .map(|ns_comp_key| ns_comp_key.decompress_with_pre_seeded_generator(generator));

        IntegerExpandedServerKey {
            compute_key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key_switching_key_material,
        }
    }
}

impl integer::compression_keys::CompressedCompressionKey {
    pub(super) fn generate_with_pre_seeded_generator<Gen>(
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

    pub(super) fn decompress_with_pre_seeded_generator<Gen>(
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
    pub(super) fn generate_with_pre_seeded_generator<Gen>(
        private_compression_key: &CompressionPrivateKeys,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        computation_parameters: ShortintParameterSet,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        let compression_params = private_compression_key.key.params;

        let bsk = match compression_params {
            CompressionParameters::Classic(classic) => {
                let core_bsk =
                    allocate_and_generate_lwe_bootstrapping_key_with_pre_seeded_generator(
                        &private_compression_key
                            .key
                            .post_packing_ks_key
                            .as_lwe_secret_key(),
                        glwe_secret_key,
                        classic.br_base_log,
                        classic.br_level,
                        computation_parameters.glwe_noise_distribution(),
                        computation_parameters.ciphertext_modulus(),
                        generator,
                    );
                ShortintCompressedBootstrappingKey::Classic {
                    bsk: core_bsk,
                    modulus_switch_noise_reduction_key:
                        CompressedModulusSwitchConfiguration::Standard,
                }
            }
            CompressionParameters::MultiBit(multi_bit) => {
                let input_lwe_sk = private_compression_key
                    .key
                    .post_packing_ks_key
                    .as_lwe_secret_key();
                let mut bsk = SeededLweMultiBitBootstrapKeyOwned::new(
                    0u64,
                    glwe_secret_key.glwe_dimension().to_glwe_size(),
                    glwe_secret_key.polynomial_size(),
                    multi_bit.br_base_log,
                    multi_bit.br_level,
                    input_lwe_sk.lwe_dimension(),
                    multi_bit.decompression_grouping_factor,
                    CompressionSeed::from(Seed(0)),
                    computation_parameters.ciphertext_modulus(),
                );

                par_generate_seeded_lwe_multi_bit_bootstrap_key_with_pre_seeded_generator(
                    &input_lwe_sk,
                    glwe_secret_key,
                    &mut bsk,
                    computation_parameters.glwe_noise_distribution(),
                    generator,
                );
                ShortintCompressedBootstrappingKey::MultiBit {
                    seeded_bsk: bsk,
                    deterministic_execution: true,
                }
            }
        };

        Self {
            key: crate::shortint::list_compression::CompressedDecompressionKey {
                bsk,
                lwe_per_glwe: compression_params.lwe_per_glwe(),
            },
        }
    }

    pub(super) fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> ExpandedDecompressionKey
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        let crate::shortint::list_compression::CompressedDecompressionKey {
            ref bsk,
            lwe_per_glwe,
        } = self.key;

        ExpandedDecompressionKey {
            bsk: bsk.decompress_with_pre_seeded_generator(generator),
            lwe_per_glwe,
        }
    }
}

impl CompressedNoiseSquashingKey {
    pub(super) fn generate_with_pre_seeded_generator<Gen>(
        private_noise_squashing_key: &integer::noise_squashing::NoiseSquashingPrivateKey,
        ap_client_key: &AtomicPatternClientKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
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

    pub(super) fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> ExpandedNoiseSquashingKey
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        let decompressed = match self.key.atomic_pattern() {
            CompressedAtomicPatternNoiseSquashingKey::Standard(compressed_std) => {
                ExpandedAtomicPatternNoiseSquashingKey::Standard(
                    compressed_std
                        .bootstrapping_key()
                        .decompress_with_pre_seeded_generator(generator),
                )
            }
            CompressedAtomicPatternNoiseSquashingKey::KeySwitch32(compressed_ks32) => {
                ExpandedAtomicPatternNoiseSquashingKey::KeySwitch32(
                    compressed_ks32
                        .bootstrapping_key()
                        .decompress_with_pre_seeded_generator(generator),
                )
            }
        };

        ExpandedNoiseSquashingKey::from_raw_parts(
            decompressed,
            self.key.message_modulus(),
            self.key.carry_modulus(),
            self.key.output_ciphertext_modulus(),
        )
    }
}

struct ShortintClassicCompressedBootstrappingKeyParts {
    core_bsk: SeededLweBootstrapKeyOwned<u64>,
    modulus_switch_noise_reduction_config: CompressedModulusSwitchConfiguration<u64>,
}

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
    Scalar: UnsignedTorus + CastFrom<usize>,
{
    fn generate_with_pre_seeded_generator<Gen>(
        lwe_secret_key: &LweSecretKey<Vec<Scalar>>,
        ciphertext_modulus: CoreCiphertextModulus<Scalar>,
        lwe_noise_distribution: DynamicDistribution<Scalar>,
        private_noise_squashing_key: &NoiseSquashingPrivateKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
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
            NoiseSquashingParameters::MultiBit(params) => {
                let mut bsk = SeededLweMultiBitBootstrapKeyOwned::new(
                    0u128,
                    params.glwe_dimension.to_glwe_size(),
                    params.polynomial_size,
                    params.decomp_base_log,
                    params.decomp_level_count,
                    lwe_secret_key.lwe_dimension(),
                    params.grouping_factor,
                    CompressionSeed::from(Seed(0)),
                    params.ciphertext_modulus,
                );

                par_generate_seeded_lwe_multi_bit_bootstrap_key_with_pre_seeded_generator(
                    lwe_secret_key,
                    private_noise_squashing_key
                        .key
                        .post_noise_squashing_secret_key(),
                    &mut bsk,
                    params.glwe_noise_distribution,
                    generator,
                );

                let thread_count =
                    crate::shortint::engine::ShortintEngine::get_thread_count_for_multi_bit_pbs(
                        lwe_secret_key.lwe_dimension(),
                        params.glwe_dimension,
                        params.polynomial_size,
                        params.decomp_base_log,
                        params.decomp_level_count,
                        params.grouping_factor,
                    );

                Self::MultiBit {
                    bsk,
                    thread_count,
                    deterministic_execution: params.deterministic_execution,
                }
            }
        }
    }
}

struct ShortintMultibitCompressedBootstrappingKeyParts {
    core_bsk: SeededLweMultiBitBootstrapKeyOwned<u64>,
    deterministic_execution: bool,
}

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
    pub(super) fn generate_with_pre_seeded_generator<Gen>(
        client_key_ap: &KS32AtomicPatternClientKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        let core_ksk =
            allocate_and_generate_new_seeded_lwe_key_switching_key_with_pre_seeded_generator(
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

    pub(super) fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        mask_generator: &mut MaskRandomGenerator<Gen>,
    ) -> ExpandedKS32AtomicPatternServerKey
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

        ExpandedKS32AtomicPatternServerKey {
            key_switching_key: core_ksk,
            bootstrapping_key: shortint_bsk,
            ciphertext_modulus: self.bootstrapping_key().ciphertext_modulus(),
        }
    }
}

impl KS32AtomicPatternClientKey {
    pub(super) fn generate_seeded_key_switching_key_with_pre_seeded_generator<T, Gen>(
        &self,
        input_lwe_secret_key: &LweSecretKeyView<T>,
        ksk_params: &ShortintKeySwitchingParameters,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> SeededLweKeyswitchKeyOwned<u64>
    where
        T: UnsignedInteger,
        u32: CastFrom<T>,
        u64: CastFrom<T>,
        Gen: ByteRandomGenerator,
    {
        match ksk_params.destination_key {
            EncryptionKeyChoice::Big => {
                allocate_and_generate_new_seeded_lwe_key_switching_key_with_pre_seeded_generator(
                    input_lwe_secret_key,
                    &self.glwe_secret_key.as_lwe_secret_key(),
                    ksk_params.ks_base_log,
                    ksk_params.ks_level,
                    self.parameters.glwe_noise_distribution(),
                    self.parameters.ciphertext_modulus(),
                    generator,
                )
            }
            EncryptionKeyChoice::Small => {
                let ksk_32b = allocate_and_generate_new_seeded_lwe_key_switching_key_with_pre_seeded_generator(
                    input_lwe_secret_key,
                    &self.lwe_secret_key,
                    ksk_params.ks_base_log,
                    ksk_params.ks_level,
                    self.parameters.lwe_noise_distribution(),
                    self.parameters.post_keyswitch_ciphertext_modulus,
                    generator,
                );
                let shift = u64::BITS - u32::BITS;
                let ksk_64b = ksk_32b
                    .as_ref()
                    .iter()
                    .copied()
                    .map(|v| u64::from(v) << shift)
                    .collect::<Vec<_>>();
                SeededLweKeyswitchKey::from_container(
                    ksk_64b,
                    ksk_32b.decomposition_base_log(),
                    ksk_32b.decomposition_level_count(),
                    ksk_32b.output_lwe_size(),
                    ksk_32b.compression_seed(),
                    ksk_32b.ciphertext_modulus().try_to().unwrap(),
                )
            }
        }
    }
}

impl CompressedAtomicPatternServerKey {
    pub(super) fn generate_with_pre_seeded_generator<Gen>(
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

    pub(super) fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        mask_generator: &mut MaskRandomGenerator<Gen>,
    ) -> ExpandedAtomicPatternServerKey
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        match self {
            Self::Standard(std_ap) => ExpandedAtomicPatternServerKey::Standard(
                std_ap.decompress_with_pre_seeded_generator(mask_generator),
            ),
            Self::KeySwitch32(ks32_ap) => ExpandedAtomicPatternServerKey::KeySwitch32(
                ks32_ap.decompress_with_pre_seeded_generator(mask_generator),
            ),
        }
    }
}

impl<ModSwitchScalar> ShortintCompressedBootstrappingKey<ModSwitchScalar>
where
    ModSwitchScalar: UnsignedTorus,
{
    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        mask_generator: &mut MaskRandomGenerator<Gen>,
    ) -> ShortintExpandedBootstrappingKey<u64, ModSwitchScalar>
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let core_bsk =
                    decompress_bootstrap_key_with_pre_seeded_generator(bsk, mask_generator);

                let modulus_switch_noise_reduction_key = modulus_switch_noise_reduction_key
                    .decompress_with_pre_seeded_generator(mask_generator);

                ShortintExpandedBootstrappingKey::Classic {
                    bsk: core_bsk,
                    modulus_switch_noise_reduction_key,
                }
            }
            Self::MultiBit {
                seeded_bsk,
                deterministic_execution,
            } => {
                let core_bsk = par_decompress_seeded_lwe_multi_bit_bootstrap_key_to_new_with_pre_seeded_generator(
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
    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        mask_generator: &mut MaskRandomGenerator<Gen>,
    ) -> ShortintExpandedBootstrappingKey<u128, ModSwitchScalar>
    where
        Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
    {
        match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let core_bsk =
                    decompress_bootstrap_key_with_pre_seeded_generator(bsk, mask_generator);

                let modulus_switch_noise_reduction_key = modulus_switch_noise_reduction_key
                    .decompress_with_pre_seeded_generator(mask_generator);

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
                let core_bsk = par_decompress_seeded_lwe_multi_bit_bootstrap_key_to_new_with_pre_seeded_generator(
                        bsk,
                        mask_generator
                    );

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
    pub(super) fn generate_with_pre_seeded_generator<Gen>(
        client_key: &StandardAtomicPatternClientKey,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        match client_key.parameters {
            PBSParameters::PBS(classic_pbs_parameters) => {
                let core_ksk =
                    allocate_and_generate_new_seeded_lwe_key_switching_key_with_pre_seeded_generator(
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
                    allocate_and_generate_new_seeded_lwe_key_switching_key_with_pre_seeded_generator(
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

    pub(super) fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        mask_generator: &mut MaskRandomGenerator<Gen>,
    ) -> ExpandedStandardAtomicPatternServerKey
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

        ExpandedStandardAtomicPatternServerKey {
            key_switching_key: core_ksk,
            bootstrapping_key: shortint_bsk,
            pbs_order: self.pbs_order(),
        }
    }
}

impl CompressedNoiseSquashingCompressionKey {
    pub(super) fn generate_with_pre_seeded_generator<Gen>(
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

    pub(super) fn decompress_with_pre_seeded_generator<Gen>(
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
    pub(super) fn decompress_with_pre_seeded_generator<Gen>(
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
    pub(super) fn generate_with_pre_seeded_generator<Gen>(
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
                    allocate_and_generate_new_seeded_lwe_key_switching_key_with_pre_seeded_generator(
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

fn decompress_bootstrap_key_with_pre_seeded_generator<Scalar, Gen>(
    compressed_bsk: &SeededLweBootstrapKeyOwned<Scalar>,
    mask_generator: &mut MaskRandomGenerator<Gen>,
) -> LweBootstrapKey<Vec<Scalar>>
where
    Scalar: UnsignedTorus,
    Gen: ByteRandomGenerator,
{
    let mut core_bsk = LweBootstrapKeyOwned::new(
        Scalar::ZERO,
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

    core_bsk
}

fn par_decompress_seeded_lwe_multi_bit_bootstrap_key_to_new_with_pre_seeded_generator<Scalar, Gen>(
    seeded_bsk: &SeededLweMultiBitBootstrapKeyOwned<Scalar>,
    mask_generator: &mut MaskRandomGenerator<Gen>,
) -> LweMultiBitBootstrapKey<Vec<Scalar>>
where
    Scalar: UnsignedTorus + Send + Sync,
    Gen: ParallelByteRandomGenerator,
{
    let mut core_bsk = LweMultiBitBootstrapKeyOwned::new(
        Scalar::ZERO,
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

    core_bsk
}
