use crate::core_crypto::commons::generators::MaskRandomGenerator;
#[cfg(test)]
use crate::core_crypto::commons::generators::NoiseRandomGenerator;
#[cfg(test)]
use crate::core_crypto::commons::math::random::CompressionSeed;
#[cfg(test)]
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::entities::{LweCompactPublicKey, LweKeyswitchKey};
use crate::core_crypto::prelude::*;
#[cfg(test)]
use crate::high_level_api::keys::CompactPrivateKey;
use crate::integer::ciphertext::{
    CompressedNoiseSquashingCompressionKey, NoiseSquashingCompressionKey,
};
#[cfg(test)]
use crate::integer::compression_keys::CompressionPrivateKeys;
use crate::integer::noise_squashing::CompressedNoiseSquashingKey;
#[cfg(test)]
use crate::integer::noise_squashing::NoiseSquashingPrivateKey;
#[cfg(test)]
use crate::shortint::atomic_pattern::compressed::{
    CompressedAtomicPatternServerKey, CompressedStandardAtomicPatternServerKey,
};
use crate::shortint::atomic_pattern::AtomicPatternServerKey;
#[cfg(test)]
use crate::shortint::ciphertext::MaxDegree;
#[cfg(test)]
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
#[cfg(test)]
use crate::shortint::parameters::{
    ModulusSwitchNoiseReductionParams, ModulusSwitchType, NoiseSquashingParameters,
};
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, CompressedModulusSwitchNoiseReductionKey,
    ModulusSwitchConfiguration, ModulusSwitchNoiseReductionKey, ShortintBootstrappingKey,
    ShortintCompressedBootstrappingKey,
};
#[cfg(test)]
use crate::shortint::{PBSParameters, ShortintParameterSet};
#[cfg(test)]
use crate::ClientKey;
use crate::{
    integer, shortint, CompactPublicKey, CompressedCompactPublicKey, CompressedServerKey,
    ReRandomizationKeySwitchingKey, ServerKey, Tag,
};
use aligned_vec::ABox;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use tfhe_csprng::seeders::Seed;
use tfhe_csprng::seeders::XofSeed;
use tfhe_fft::c64;

use crate::integer::compression_keys::CompressionKey;
use crate::integer::key_switching_key::{
    CompressedKeySwitchingKeyMaterial, KeySwitchingKeyMaterial,
};
use crate::shortint::noise_squashing::{
    CompressedShortint128BootstrappingKey, Shortint128BootstrappingKey,
};

// Generation order:
//
// 1) Public key (enc params)
// 2) Compression key
// 3) Decompression key
// 4) KSK (compute params)
// 5) BSK (compute params)
// 6) BSK (SnS params)
// 7) Mod Switch Key (SnS params)
// 8) KSK (encryption params to compute params)
// 9) Mod Switch Key (compute params)

/// Compressed KeySet which respects the [NIST document]
/// regarding the random generator used, and the order of key generation
///
/// [NIST document]: https://eprint.iacr.org/2025/699
pub struct CompressedXofKeySet {
    seed: XofSeed,
    compressed_public_key: CompressedCompactPublicKey,
    compressed_server_key: CompressedServerKey,
}

impl CompressedXofKeySet {
    #[cfg(test)]
    fn with_seed(pub_seed: XofSeed, priv_seed: XofSeed, ck: &ClientKey) -> crate::Result<Self> {
        use crate::high_level_api::keys::ReRandomizationKeyGenerationInfo;

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
        let (lwe_secret_key, glwe_secret_key) = match &shortint_client_key.atomic_pattern {
            AtomicPatternClientKey::Standard(ap) => (&ap.lwe_secret_key, &ap.glwe_secret_key),
            AtomicPatternClientKey::KeySwitch32(_) => {
                return Err(crate::error!("KeySwitch32 atomic pattern is not supported"));
            }
        };

        // First, the public key used to encrypt
        // It uses separate parameters from the computation ones
        let compressed_public_key = CompressedCompactPublicKey::generate_with_pre_seeded_generator(
            dedicated_pk_key,
            &mut encryption_rand_gen,
        );

        let compression_key = ck
            .key
            .compression_key
            .as_ref()
            .map(|private_compression_key| {
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
        let mut integer_compressed_server_key = {
            let core_ksk = allocate_and_generate_lwe_key_switching_key_with_pre_seeded_generator(
                &glwe_secret_key.as_lwe_secret_key(),
                lwe_secret_key,
                computation_parameters.ks_base_log(),
                computation_parameters.ks_level(),
                computation_parameters.encryption_noise_distribution(),
                computation_parameters.ciphertext_modulus(),
                &mut encryption_rand_gen,
            );

            let shortint_bsk = match computation_parameters.pbs_parameters() {
                Some(PBSParameters::PBS(_)) => {
                    let core_bsk =
                        allocate_and_generate_lwe_bootstrapping_key_with_pre_seeded_generator(
                            lwe_secret_key,
                            glwe_secret_key,
                            computation_parameters.pbs_base_log(),
                            computation_parameters.pbs_level(),
                            computation_parameters.encryption_noise_distribution(),
                            computation_parameters.ciphertext_modulus(),
                            &mut encryption_rand_gen,
                        );

                    ShortintCompressedBootstrappingKey::Classic {
                        bsk: core_bsk,
                        modulus_switch_noise_reduction_key:
                            CompressedModulusSwitchConfiguration::Standard,
                    }
                }
                Some(PBSParameters::MultiBitPBS(multibit_params)) => {
                    let mut core_bsk = SeededLweMultiBitBootstrapKeyOwned::new(
                        0u64,
                        computation_parameters.glwe_dimension().to_glwe_size(),
                        computation_parameters.polynomial_size(),
                        computation_parameters.pbs_base_log(),
                        computation_parameters.pbs_level(),
                        lwe_secret_key.lwe_dimension(),
                        multibit_params.grouping_factor,
                        CompressionSeed::from(Seed(0)),
                        computation_parameters.ciphertext_modulus(),
                    );

                    generate_seeded_lwe_multi_bit_bootstrap_key_with_pre_seeded_generator(
                        lwe_secret_key,
                        glwe_secret_key,
                        &mut core_bsk,
                        computation_parameters.encryption_noise_distribution(),
                        &mut encryption_rand_gen,
                    );
                    ShortintCompressedBootstrappingKey::MultiBit {
                        seeded_bsk: core_bsk,
                        deterministic_execution: multibit_params.deterministic_execution,
                    }
                }
                None => {
                    return Err(crate::Error::new("No PBS parameters found".to_string()));
                }
            };

            let max_degree = MaxDegree::integer_radix_server_key(
                computation_parameters.message_modulus(),
                computation_parameters.carry_modulus(),
            );

            integer::CompressedServerKey::from_raw_parts(
                shortint::CompressedServerKey::from_raw_parts(
                    CompressedAtomicPatternServerKey::Standard(
                        CompressedStandardAtomicPatternServerKey::from_raw_parts(
                            core_ksk,
                            shortint_bsk,
                            computation_parameters.encryption_key_choice().into(),
                        ),
                    ),
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
                        lwe_secret_key,
                        computation_parameters,
                        &mut encryption_rand_gen,
                    )
                });

        // Generate the key switching material that will allow going from
        // the public key's dedicated parameters to the computation parameters
        let pk_to_sk_ksk_params = dedicated_pk_key.1;
        let (target_private_key, noise_distrib) = match pk_to_sk_ksk_params.destination_key {
            EncryptionKeyChoice::Big => (
                glwe_secret_key.as_lwe_secret_key(),
                computation_parameters.glwe_noise_distribution(),
            ),
            EncryptionKeyChoice::Small => (
                lwe_secret_key.as_view(),
                computation_parameters.lwe_noise_distribution(),
            ),
        };

        let integer_ksk_material = {
            let key_switching_key =
                allocate_and_generate_lwe_key_switching_key_with_pre_seeded_generator(
                    &dedicated_pk_key.0.key.key(),
                    &target_private_key,
                    pk_to_sk_ksk_params.ks_base_log,
                    pk_to_sk_ksk_params.ks_level,
                    noise_distrib,
                    computation_parameters.ciphertext_modulus(),
                    &mut encryption_rand_gen,
                );

            CompressedKeySwitchingKeyMaterial {
                material: shortint::key_switching_key::CompressedKeySwitchingKeyMaterial {
                    key_switching_key,
                    cast_rshift: 0,
                    destination_key: dedicated_pk_key.1.destination_key,
                },
            }
        };

        // Generate the key switching material that will allow going from
        // the public key's dedicated parameters to the re-rand

        let cpk_re_randomization_key_switching_key_material = ck
            .key
            .re_randomization_ksk_gen_info()?
            .map(|key_gen_info| match key_gen_info {
                ReRandomizationKeyGenerationInfo::UseCPKEncryptionKSK => {
                    use crate::CompressedReRandomizationKeySwitchingKey;

                    CompressedReRandomizationKeySwitchingKey::UseCPKEncryptionKSK
                }
                ReRandomizationKeyGenerationInfo::DedicatedKSK((
                    input_cpk,
                    cpk_re_randomization_ksk_params,
                )) => {
                    use crate::CompressedReRandomizationKeySwitchingKey;

                    let (target_private_key, noise_distrib) = (
                        glwe_secret_key.as_lwe_secret_key(),
                        computation_parameters.glwe_noise_distribution(),
                    );

                    let key_switching_key =
                        allocate_and_generate_lwe_key_switching_key_with_pre_seeded_generator(
                            &input_cpk.key.key(),
                            &target_private_key,
                            cpk_re_randomization_ksk_params.ks_base_log,
                            cpk_re_randomization_ksk_params.ks_level,
                            noise_distrib,
                            computation_parameters.ciphertext_modulus(),
                            &mut encryption_rand_gen,
                        );

                    let key = CompressedKeySwitchingKeyMaterial {
                        material: shortint::key_switching_key::CompressedKeySwitchingKeyMaterial {
                            key_switching_key,
                            cast_rshift: 0,
                            destination_key: EncryptionKeyChoice::Big,
                        },
                    };

                    CompressedReRandomizationKeySwitchingKey::DedicatedKSK(key)
                }
            });

        if let PBSParameters::PBS(pbs_params) = computation_parameters.pbs_parameters().unwrap() {
            let mod_switch_noise_key =
                CompressedModulusSwitchConfiguration::generate_from_existing_generator(
                    &pbs_params.modulus_switch_noise_reduction_params,
                    lwe_secret_key,
                    computation_parameters.lwe_noise_distribution(),
                    computation_parameters.ciphertext_modulus(),
                    &mut encryption_rand_gen,
                );

            match &mut integer_compressed_server_key.key.compressed_ap_server_key {
                CompressedAtomicPatternServerKey::Standard(ap) => {
                    match ap.bootstrapping_key_mut() {
                        ShortintCompressedBootstrappingKey::Classic {
                            bsk: _,
                            modulus_switch_noise_reduction_key,
                        } => {
                            *modulus_switch_noise_reduction_key = mod_switch_noise_key;
                        }
                        ShortintCompressedBootstrappingKey::MultiBit { .. } => {
                            return Err(crate::error!(
                                "Multi-bit PBS does not support modulus switch noise reduction"
                            ))
                        }
                    }
                }
                CompressedAtomicPatternServerKey::KeySwitch32(_) => {
                    unreachable!("not supported")
                }
            }
        }

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
            Tag::default(),
        );

        Ok(Self {
            seed: pub_seed,
            compressed_public_key,
            compressed_server_key,
        })
    }

    /// Decompress the KeySet
    pub fn decompress(self) -> XofKeySet {
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

        let server_key = {
            let shortint_sk = &self.compressed_server_key.integer_key.key.key;
            let compressed_ksk = &shortint_sk
                .as_compressed_standard_atomic_pattern_server_key()
                .unwrap()
                .key_switching_key();

            let mut core_ksk = LweKeyswitchKey::new(
                0u64,
                compressed_ksk.decomposition_base_log(),
                compressed_ksk.decomposition_level_count(),
                compressed_ksk.input_key_lwe_dimension(),
                compressed_ksk.output_key_lwe_dimension(),
                compressed_ksk.ciphertext_modulus(),
            );
            decompress_seeded_lwe_keyswitch_key_with_pre_seeded_generator(
                &mut core_ksk,
                compressed_ksk,
                &mut mask_generator,
            );

            let shortint_bsk = match &shortint_sk
                .as_compressed_standard_atomic_pattern_server_key()
                .unwrap()
                .bootstrapping_key()
            {
                ShortintCompressedBootstrappingKey::Classic {
                    bsk: compressed_bsk,
                    modulus_switch_noise_reduction_key: _,
                } => {
                    let core_fourier_bsk =
                        par_decompress_bootstrap_key_to_fourier_with_pre_seeded_generator(
                            compressed_bsk,
                            &mut mask_generator,
                        );

                    ShortintBootstrappingKey::Classic {
                        bsk: core_fourier_bsk,
                        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration::Standard,
                    }
                }
                ShortintCompressedBootstrappingKey::MultiBit {
                    seeded_bsk,
                    deterministic_execution,
                } => {
                    let core_fourier_bsk = par_decompress_seeded_lwe_multi_bit_bootstrap_key_to_fourier_with_pre_seeded_generator(
                        seeded_bsk,
                        &mut mask_generator
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
            };

            let pbs_order = shortint_sk
                .as_compressed_standard_atomic_pattern_server_key()
                .unwrap()
                .pbs_order();
            let shortint_sk = shortint::ServerKey::from_raw_parts(
                AtomicPatternServerKey::Standard(
                    shortint::atomic_pattern::StandardAtomicPatternServerKey::from_raw_parts(
                        core_ksk,
                        shortint_bsk,
                        pbs_order,
                    ),
                ),
                shortint_sk.message_modulus,
                shortint_sk.carry_modulus,
                shortint_sk.max_degree,
                shortint_sk.max_noise_level,
            );

            let mut integer_sk = integer::ServerKey::from_raw_parts(shortint_sk);

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

            match &mut integer_sk.key.atomic_pattern {
                AtomicPatternServerKey::Standard(ap) => {
                    match &mut ap.bootstrapping_key {
                        ShortintBootstrappingKey::Classic {
                            bsk: _,
                            modulus_switch_noise_reduction_key: decomp_ms_nrk,
                        } => {
                            *decomp_ms_nrk = match &self
                                .compressed_server_key
                                .integer_key
                                .key
                                .key
                                .as_compressed_standard_atomic_pattern_server_key()
                                .unwrap()
                                .bootstrapping_key()
                            {
                                ShortintCompressedBootstrappingKey::Classic {
                                    bsk: _,
                                    modulus_switch_noise_reduction_key,
                                } => modulus_switch_noise_reduction_key
                                    .decompress_with_pre_seeded_generator(&mut mask_generator),
                                ShortintCompressedBootstrappingKey::MultiBit { .. } => {
                                    // We already created the decompressed bsk matching the
                                    // compressed one
                                    // so this cannot happen
                                    unreachable!("Internal error, somehow got mismatched key type")
                                }
                            }
                        }
                        ShortintBootstrappingKey::MultiBit { .. } => {}
                    }
                }
                AtomicPatternServerKey::KeySwitch32(_) => {
                    // The constructor does not allow this
                    panic!("KeySwitch32 atomic pattern is not supported")
                }
                AtomicPatternServerKey::Dynamic(_) => {
                    // The constructor does not allow this
                    panic!("Dynamic atomic patterns are not supported")
                }
            }

            let noise_squashing_compression_key = self
                .compressed_server_key
                .integer_key
                .noise_squashing_compression_key
                .map(|ns_comp_key| {
                    ns_comp_key.decompress_with_pre_seeded_generator(&mut mask_generator)
                });

            ServerKey::from_raw_parts(
                integer_sk,
                integer_cpk_ksk,
                compression_key,
                decompression_key,
                noise_squashing_key,
                noise_squashing_compression_key,
                integer_cpk_re_rand_ksk,
                Tag::default(),
            )
        };

        XofKeySet {
            public_key,
            server_key,
        }
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
/// of the [NIST document]
///
/// To create such key set, first create a [CompressedXofKeySet] then decompress it
///
/// [NIST document]: https://eprint.iacr.org/2025/699
#[derive(Serialize, Deserialize)]
pub struct XofKeySet {
    public_key: CompactPublicKey,
    server_key: ServerKey,
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
            Tag::default(),
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
        CompactPublicKey::from_raw_parts(integer_pk, Tag::default())
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
            compression_params.packing_ks_base_log,
            compression_params.packing_ks_level,
            glwe_secret_key.as_lwe_secret_key().lwe_dimension(),
            compression_params.packing_ks_glwe_dimension,
            compression_params.packing_ks_polynomial_size,
            CompressionSeed::from(Seed(0)),
            ciphertext_modulus,
        );

        generate_seeded_lwe_packing_keyswitch_key_with_pre_seeded_generator(
            &glwe_secret_key.as_lwe_secret_key(),
            &private_compression_key.key.post_packing_ks_key,
            &mut packing_key_switching_key,
            compression_params.packing_ks_key_noise_distribution,
            generator,
        );

        Self {
            key: shortint::list_compression::CompressedCompressionKey {
                packing_key_switching_key,
                lwe_per_glwe: compression_params.lwe_per_glwe,
                storage_log_modulus: compression_params.storage_log_modulus,
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
            compression_params.br_base_log,
            compression_params.br_level,
            computation_parameters.glwe_noise_distribution(),
            computation_parameters.ciphertext_modulus(),
            generator,
        );

        Self {
            key: shortint::list_compression::CompressedDecompressionKey {
                blind_rotate_key: core_bsk,
                lwe_per_glwe: compression_params.lwe_per_glwe,
            },
        }
    }

    fn decompress_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> integer::compression_keys::DecompressionKey
    where
        Gen: ByteRandomGenerator,
    {
        let compressed_blind_rot_key = &self.key.blind_rotate_key;

        let core_fourier_bsk = par_decompress_bootstrap_key_to_fourier_with_pre_seeded_generator(
            compressed_blind_rot_key,
            generator,
        );

        integer::compression_keys::DecompressionKey {
            key: shortint::list_compression::DecompressionKey {
                blind_rotate_key: core_fourier_bsk,
                lwe_per_glwe: self.key.lwe_per_glwe,
            },
        }
    }
}

impl CompressedNoiseSquashingKey {
    #[cfg(test)]
    fn generate_with_pre_seeded_generator<Gen>(
        private_noise_squashing_key: &integer::noise_squashing::NoiseSquashingPrivateKey,
        lwe_secret_key: &LweSecretKey<Vec<u64>>,
        computation_parameters: ShortintParameterSet,
        generator: &mut EncryptionRandomGenerator<Gen>,
    ) -> Self
    where
        Gen: ByteRandomGenerator,
    {
        let noise_squashing_parameters = private_noise_squashing_key.noise_squashing_parameters();

        let shortint_key = match noise_squashing_parameters {
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
                    CompressedModulusSwitchConfiguration::generate_from_existing_generator(
                        &ns_params.modulus_switch_noise_reduction_params,
                        lwe_secret_key,
                        computation_parameters.lwe_noise_distribution(),
                        computation_parameters.ciphertext_modulus(),
                        generator,
                    );

                CompressedShortint128BootstrappingKey::Classic {
                    bsk: core_bsk,
                    modulus_switch_noise_reduction_key: compressed_mod_switch_config,
                }
            }
            NoiseSquashingParameters::MultiBit(_) => {
                // return Err("Multibit NoiseSquashing is not supported");
                panic!("Multibit NoiseSquashing is not supported");
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
        let CompressedShortint128BootstrappingKey::Classic {
            bsk: compressed_bsk,
            modulus_switch_noise_reduction_key,
        } = self.key.bootstrapping_key()
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

        let decompressed = Shortint128BootstrappingKey::Classic {
            bsk: core_fourier_bsk,
            modulus_switch_noise_reduction_key: ms_nrk,
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
        };
        KeySwitchingKeyMaterial::from_raw_parts(shortint_cpk_ksk)
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
    fn generate_from_existing_generator<NoiseDistribution, Gen>(
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
    use crate::core_crypto::prelude::new_seeder;
    use crate::prelude::*;
    use crate::xof_key_set::CompressedXofKeySet;
    use crate::{XofSeed, *};

    #[test]
    fn test_xof_key_set() {
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

        let cks = ClientKey::generate(config);

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

        let key_set = compressed_key_set.decompress();

        let (pk, sk) = key_set.into_raw_parts();

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
            let compact_public_encryption_domain_separator = *b"TFHE.Enc";
            let rerand_domain_separator = *b"TFHE.Rrd";

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

        let c_dec: u32 = c.decrypt(&cks);
        let d_dec: u32 = d.decrypt(&cks);

        assert_eq!(clear_a.wrapping_mul(clear_b), c_dec);
        assert_eq!(clear_a & clear_b, d_dec);

        let ns_c = c.squash_noise().unwrap();
        let ns_c_dec: u32 = ns_c.decrypt(&cks);
        assert_eq!(clear_a.wrapping_mul(clear_b), ns_c_dec);

        let ns_d = d.squash_noise().unwrap();
        let ns_d_dec: u32 = ns_d.decrypt(&cks);
        assert_eq!(clear_a & clear_b, ns_d_dec);

        let compressed_list = CompressedCiphertextListBuilder::new()
            .push(a)
            .push(b)
            .push(c)
            .push(d)
            .build()
            .unwrap();

        let a: FheUint32 = compressed_list.get(0).unwrap().unwrap();
        let da: u32 = a.decrypt(&cks);
        assert_eq!(da, clear_a);
        let b: FheUint32 = compressed_list.get(1).unwrap().unwrap();
        let db: u32 = b.decrypt(&cks);
        assert_eq!(db, clear_b);
        let c: FheUint32 = compressed_list.get(2).unwrap().unwrap();
        let dc: u32 = c.decrypt(&cks);
        assert_eq!(dc, clear_a.wrapping_mul(clear_b));
        let d: FheUint32 = compressed_list.get(3).unwrap().unwrap();
        let db: u32 = d.decrypt(&cks);
        assert_eq!(db, clear_a & clear_b);
    }
}
