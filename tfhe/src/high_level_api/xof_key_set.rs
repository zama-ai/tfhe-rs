use crate::core_crypto::commons::generators::{MaskRandomGenerator, NoiseRandomGenerator};
use crate::core_crypto::commons::math::random::{CompressionSeed, RandomGenerator};
use crate::core_crypto::entities::{LweCompactPublicKey, LweKeyswitchKey};
use crate::core_crypto::prelude::*;
use crate::integer::noise_squashing::CompressedNoiseSquashingKey;
use crate::shortint::atomic_pattern::compressed::{
    CompressedAtomicPatternServerKey, CompressedStandardAtomicPatternServerKey,
};
use crate::shortint::atomic_pattern::AtomicPatternServerKey;
use crate::shortint::ciphertext::MaxDegree;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::parameters::ModulusSwitchNoiseReductionParams;
use crate::shortint::server_key::{
    CompressedModulusSwitchNoiseReductionKey, ModulusSwitchNoiseReductionKey,
    ShortintBootstrappingKey, ShortintCompressedBootstrappingKey,
};
use crate::shortint::{PBSParameters, ShortintParameterSet};
use crate::{
    integer, shortint, ClientKey, CompactPublicKey, CompressedCompactPublicKey,
    CompressedServerKey, ServerKey, Tag,
};
use aligned_vec::ABox;
use serde::{Deserialize, Serialize};
use tfhe_csprng::seeders::{Seed, XofSeed};
use tfhe_fft::c64;
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

pub struct CompressedXofKeySet {
    seed: XofSeed,
    compressed_public_key: CompressedCompactPublicKey,
    compressed_server_key: CompressedServerKey,
}

impl CompressedXofKeySet {
    pub fn with_seed(pub_seed: XofSeed, priv_seed: XofSeed, ck: &ClientKey) -> crate::Result<Self> {
        let Some(dedicated_pk_key) = ck.key.dedicated_compact_private_key.as_ref() else {
            return Err(crate::error!("Dedicated compact private key is required"));
        };

        let Some(noise_squashing_key) = ck.key.noise_squashing_private_key.as_ref() else {
            return Err(crate::error!("Noise squashing key is required"));
        };

        let mask_random_generator =
            MaskRandomGenerator::<DefaultRandomGenerator>::new(pub_seed.clone());
        let noise_random_generator =
            NoiseRandomGenerator::from_raw_parts(RandomGenerator::new(priv_seed));
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
        let compressed_public_key = {
            let public_key_parameters = dedicated_pk_key.0.key.parameters();

            let mut core_pk = SeededLweCompactPublicKeyOwned::new(
                0u64,
                public_key_parameters.encryption_lwe_dimension,
                CompressionSeed::from(Seed(0)), // This is not the seed that is actually used
                public_key_parameters.ciphertext_modulus,
            );

            generate_seeded_lwe_compact_public_key_with_pre_seeded_generator(
                &dedicated_pk_key.0.key.key(),
                &mut core_pk,
                public_key_parameters.encryption_noise_distribution,
                &mut encryption_rand_gen,
            );

            CompressedCompactPublicKey::from_raw_parts(
                integer::CompressedCompactPublicKey::from_raw_parts(
                    shortint::CompressedCompactPublicKey::from_raw_parts(
                        core_pk,
                        dedicated_pk_key.0.key.parameters(),
                    ),
                ),
                Tag::default(),
            )
        };

        // Compression Key
        let compression_key = ck
            .key
            .compression_key
            .as_ref()
            .map(|private_compression_key| {
                let compression_params = private_compression_key.key.params;
                let mut packing_key_switching_key = SeededLwePackingKeyswitchKey::new(
                    0u64,
                    compression_params.packing_ks_base_log,
                    compression_params.packing_ks_level,
                    glwe_secret_key.as_lwe_secret_key().lwe_dimension(),
                    compression_params.packing_ks_glwe_dimension,
                    compression_params.packing_ks_polynomial_size,
                    CompressionSeed::from(Seed(0)),
                    computation_parameters.ciphertext_modulus(),
                );

                generate_seeded_lwe_packing_keyswitch_key_with_pre_seeded_generator(
                    &glwe_secret_key.as_lwe_secret_key(),
                    &private_compression_key.key.post_packing_ks_key,
                    &mut packing_key_switching_key,
                    compression_params.packing_ks_key_noise_distribution,
                    &mut encryption_rand_gen,
                );

                integer::compression_keys::CompressedCompressionKey {
                    key: shortint::list_compression::CompressedCompressionKey {
                        packing_key_switching_key,
                        lwe_per_glwe: compression_params.lwe_per_glwe,
                        storage_log_modulus: compression_params.storage_log_modulus,
                    },
                }
            });

        let decompression_key = ck
            .key
            .compression_key
            .as_ref()
            .map(|private_compression_key| {
                let compression_params = private_compression_key.key.params;

                let core_bsk =
                    allocate_and_generate_lwe_bootstrapping_key_with_pre_seeded_generator(
                        &private_compression_key
                            .key
                            .post_packing_ks_key
                            .as_lwe_secret_key(),
                        glwe_secret_key,
                        compression_params.br_base_log,
                        compression_params.br_level,
                        computation_parameters.glwe_noise_distribution(),
                        computation_parameters.ciphertext_modulus(),
                        &mut encryption_rand_gen,
                    );

                integer::compression_keys::CompressedDecompressionKey {
                    key: shortint::list_compression::CompressedDecompressionKey {
                        blind_rotate_key: core_bsk,
                        lwe_per_glwe: compression_params.lwe_per_glwe,
                    },
                }
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
                        modulus_switch_noise_reduction_key: None,
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

                    generate_seeded_lwe_multi_bit_bootstrap_key_with_existing_generator(
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

        let noise_squashing_bs_key = {
            let noise_squashing_parameters = noise_squashing_key.noise_squashing_parameters();

            let core_bsk = allocate_and_generate_lwe_bootstrapping_key_with_pre_seeded_generator(
                lwe_secret_key,
                noise_squashing_key.key.post_noise_squashing_secret_key(),
                noise_squashing_parameters.decomp_base_log,
                noise_squashing_parameters.decomp_level_count,
                noise_squashing_parameters.glwe_noise_distribution,
                noise_squashing_parameters.ciphertext_modulus,
                &mut encryption_rand_gen,
            );

            let modulus_switch_noise_reduction_key = noise_squashing_parameters
                .modulus_switch_noise_reduction_params
                .as_ref()
                .map(|p| {
                    allocate_and_generate_compressed_modulus_switch_noise_reduction_key_with_pre_seeded_generator(
                        lwe_secret_key,
                        p,
                        computation_parameters.lwe_noise_distribution(),
                        computation_parameters.ciphertext_modulus(),
                        &mut encryption_rand_gen,
                    )
                });

            CompressedNoiseSquashingKey::from_raw_parts(
                shortint::noise_squashing::CompressedNoiseSquashingKey::from_raw_parts(
                    core_bsk,
                    modulus_switch_noise_reduction_key,
                    noise_squashing_parameters.message_modulus,
                    noise_squashing_parameters.carry_modulus,
                    noise_squashing_parameters.ciphertext_modulus,
                ),
            )
        };

        // Lastly, generate the key switching material that will allow going from
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

            integer::key_switching_key::CompressedKeySwitchingKeyMaterial {
                material: shortint::key_switching_key::CompressedKeySwitchingKeyMaterial {
                    key_switching_key,
                    cast_rshift: 0,
                    destination_key: dedicated_pk_key.1.destination_key,
                },
            }
        };

        if let PBSParameters::PBS(pbs_params) = computation_parameters.pbs_parameters().unwrap() {
            let mod_switch_noise_key =
                pbs_params.modulus_switch_noise_reduction_params.as_ref().map(
                    |p| {
                        allocate_and_generate_compressed_modulus_switch_noise_reduction_key_with_pre_seeded_generator(
                            lwe_secret_key,
                            p,
                            computation_parameters.lwe_noise_distribution(),
                            computation_parameters.ciphertext_modulus(),
                            &mut encryption_rand_gen,
                        )
                    }
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

        let compressed_server_key = CompressedServerKey::from_raw_parts(
            integer_compressed_server_key,
            Some(integer_ksk_material),
            compression_key,
            decompression_key,
            Some(noise_squashing_bs_key),
            Tag::default(),
        );

        Ok(Self {
            seed: pub_seed,
            compressed_public_key,
            compressed_server_key,
        })
    }

    pub fn decompress(self) -> XofKeySet {
        let mut mask_generator = MaskRandomGenerator::<DefaultRandomGenerator>::new(self.seed);

        let public_key = {
            let shortint_cpk = self.compressed_public_key.into_raw_parts().0.key;
            let compressed_pk = &shortint_cpk.key;
            let mut pk = LweCompactPublicKey::new(
                0u64,
                compressed_pk.lwe_dimension(),
                compressed_pk.ciphertext_modulus(),
            );
            decompress_seeded_lwe_compact_public_key_with_pre_seeded_generator(
                &mut pk,
                compressed_pk,
                &mut mask_generator,
            );

            let shortint_pk =
                shortint::CompactPublicKey::from_raw_parts(pk, shortint_cpk.parameters);
            let integer_pk = integer::CompactPublicKey::from_raw_parts(shortint_pk);
            CompactPublicKey::from_raw_parts(integer_pk, Tag::default())
        };

        let (compression_key, decompression_key) =
            match self.compressed_server_key.integer_key.compression_key {
                Some(compressed_compression_key) => {
                    let packing_key_switching_key = compressed_compression_key
                        .key
                        .packing_key_switching_key
                        .decompress_to_lwe_packing_keyswitch_key_with_pre_seeded_generator(
                            &mut mask_generator,
                        );

                    let compression_key = integer::compression_keys::CompressionKey {
                        key: shortint::list_compression::CompressionKey {
                            packing_key_switching_key,
                            lwe_per_glwe: compressed_compression_key.key.lwe_per_glwe,
                            storage_log_modulus: compressed_compression_key.key.storage_log_modulus,
                        },
                    };

                    let compressed_decompression_key = self
                        .compressed_server_key
                        .integer_key
                        .decompression_key
                        .unwrap();

                    let compressed_blind_rot_key =
                        &compressed_decompression_key.key.blind_rotate_key;

                    let core_fourier_bsk =
                        par_decompress_bootstrap_key_to_fourier_with_pre_seeded_generator(
                            compressed_blind_rot_key,
                            &mut mask_generator,
                        );

                    let decompression_key = integer::compression_keys::DecompressionKey {
                        key: shortint::list_compression::DecompressionKey {
                            blind_rotate_key: ShortintBootstrappingKey::Classic {
                                bsk: core_fourier_bsk,
                                modulus_switch_noise_reduction_key: None,
                            },
                            lwe_per_glwe: compressed_decompression_key.key.lwe_per_glwe,
                        },
                    };

                    (Some(compression_key), Some(decompression_key))
                }
                None => (None, None),
            };

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
                        modulus_switch_noise_reduction_key: None,
                    }
                }
                ShortintCompressedBootstrappingKey::MultiBit {
                    seeded_bsk,
                    deterministic_execution,
                } => {
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
                        &mut mask_generator,
                    );

                    let core_fourier_bsk = FourierLweMultiBitBootstrapKeyOwned::new(
                        core_bsk.input_lwe_dimension(),
                        core_bsk.glwe_size(),
                        core_bsk.polynomial_size(),
                        core_bsk.decomposition_base_log(),
                        core_bsk.decomposition_level_count(),
                        core_bsk.grouping_factor(),
                    );

                    let thread_count = match core_fourier_bsk.grouping_factor().0 {
                        2 => ThreadCount(5),
                        3 => ThreadCount(7),
                        _ => {
                            todo!("Currently shortint only supports grouping factor 2 and 3 for multi bit PBS")
                        }
                    };

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

            let noise_squashing_key = {
                let compressed_nsk = self
                    .compressed_server_key
                    .integer_key
                    .noise_squashing_key
                    .as_ref()
                    .unwrap();

                let mut core_bsk = LweBootstrapKeyOwned::new(
                    0u128,
                    compressed_nsk.key.bootstrapping_key().glwe_size(),
                    compressed_nsk.key.bootstrapping_key().polynomial_size(),
                    compressed_nsk
                        .key
                        .bootstrapping_key()
                        .decomposition_base_log(),
                    compressed_nsk
                        .key
                        .bootstrapping_key()
                        .decomposition_level_count(),
                    compressed_nsk.key.bootstrapping_key().input_lwe_dimension(),
                    compressed_nsk.key.bootstrapping_key().ciphertext_modulus(),
                );

                decompress_seeded_lwe_bootstrap_key_with_pre_seeded_generator(
                    &mut core_bsk,
                    compressed_nsk.key.bootstrapping_key(),
                    &mut mask_generator,
                );

                let mut core_fourier_bsk = Fourier128LweBootstrapKeyOwned::new(
                    core_bsk.input_lwe_dimension(),
                    core_bsk.glwe_size(),
                    core_bsk.polynomial_size(),
                    core_bsk.decomposition_base_log(),
                    core_bsk.decomposition_level_count(),
                );

                par_convert_standard_lwe_bootstrap_key_to_fourier_128(
                    &core_bsk,
                    &mut core_fourier_bsk,
                );

                let ms_nrk = compressed_nsk
                    .key
                    .modulus_switch_noise_reduction_key()
                    .as_ref()
                    .map(|compressed_ms_nrk| {
                        decompress_compressed_modulus_switch_noise_reduction_key_with_pre_seeded_generator(compressed_ms_nrk, &mut mask_generator)
                    });
                integer::noise_squashing::NoiseSquashingKey::from_raw_parts(
                    shortint::noise_squashing::NoiseSquashingKey::from_raw_parts(
                        core_fourier_bsk,
                        ms_nrk,
                        compressed_nsk.key.message_modulus(),
                        compressed_nsk.key.carry_modulus(),
                        compressed_nsk.key.output_ciphertext_modulus(),
                    ),
                )
            };

            let compressed_cpk_ksk = &self
                .compressed_server_key
                .integer_key
                .cpk_key_switching_key_material
                .as_ref()
                .unwrap()
                .material;

            let mut key_switching_key = LweKeyswitchKey::new(
                0u64,
                compressed_cpk_ksk
                    .key_switching_key
                    .decomposition_base_log(),
                compressed_cpk_ksk
                    .key_switching_key
                    .decomposition_level_count(),
                compressed_cpk_ksk
                    .key_switching_key
                    .input_key_lwe_dimension(),
                compressed_cpk_ksk
                    .key_switching_key
                    .output_key_lwe_dimension(),
                compressed_cpk_ksk.key_switching_key.ciphertext_modulus(),
            );
            decompress_seeded_lwe_keyswitch_key_with_pre_seeded_generator(
                &mut key_switching_key,
                &compressed_cpk_ksk.key_switching_key,
                &mut mask_generator,
            );
            let shortint_cpk_ksk = shortint::key_switching_key::KeySwitchingKeyMaterial {
                key_switching_key,
                cast_rshift: compressed_cpk_ksk.cast_rshift,
                destination_key: compressed_cpk_ksk.destination_key,
            };
            let integer_cpk_ksk =
                integer::key_switching_key::KeySwitchingKeyMaterial::from_raw_parts(
                    shortint_cpk_ksk,
                );

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
                                } => {
                                    modulus_switch_noise_reduction_key
                                        .as_ref()
                                        .map(|compressed_ms_nrk| {
                                            decompress_compressed_modulus_switch_noise_reduction_key_with_pre_seeded_generator(compressed_ms_nrk, &mut mask_generator)
                                        })
                                }
                                ShortintCompressedBootstrappingKey::MultiBit { .. } => {
                                    // We already created the decompressed bsk matching the compressed one
                                    // so this cannot happen
                                    unreachable!(
                                        "Internal error, somehow got mismatched key type"
                                    )
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

            ServerKey::from_raw_parts(
                integer_sk,
                Some(integer_cpk_ksk),
                compression_key,
                decompression_key,
                Some(noise_squashing_key),
                Tag::default(),
            )
        };

        XofKeySet {
            public_key,
            server_key,
        }
    }
}

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

fn allocate_and_generate_compressed_modulus_switch_noise_reduction_key_with_pre_seeded_generator<
    LweCont,
>(
    lwe_secret_key: &LweSecretKey<LweCont>,
    params: &ModulusSwitchNoiseReductionParams,
    lwe_noise_distribution: DynamicDistribution<u64>,
    ciphertext_modulus: CiphertextModulus<u64>,
    noise_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> CompressedModulusSwitchNoiseReductionKey<u64>
where
    LweCont: Container<Element = u64>,
{
    let mut modulus_switch_zeros = SeededLweCiphertextList::new(
        0,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        params.modulus_switch_zeros_count,
        // That's weird that we have this type
        CompressionSeed { seed: Seed(0) },
        ciphertext_modulus,
    );

    let plaintext_list = PlaintextList::new(0, PlaintextCount(params.modulus_switch_zeros_count.0));
    encrypt_seeded_lwe_ciphertext_list_with_pre_seeded_generator(
        lwe_secret_key,
        &mut modulus_switch_zeros,
        &plaintext_list,
        lwe_noise_distribution,
        noise_generator,
    );
    CompressedModulusSwitchNoiseReductionKey {
        modulus_switch_zeros,
        ms_bound: params.ms_bound,
        ms_r_sigma_factor: params.ms_r_sigma_factor,
        ms_input_variance: params.ms_input_variance,
    }
}

fn decompress_compressed_modulus_switch_noise_reduction_key_with_pre_seeded_generator<Gen>(
    compressed: &CompressedModulusSwitchNoiseReductionKey<u64>,
    mask_generator: &mut MaskRandomGenerator<Gen>,
) -> ModulusSwitchNoiseReductionKey<u64>
where
    Gen: ByteRandomGenerator,
{
    let mut decompressed_list = LweCiphertextList::new(
        0u64,
        compressed.modulus_switch_zeros.lwe_size(),
        compressed.modulus_switch_zeros.lwe_ciphertext_count(),
        compressed.modulus_switch_zeros.ciphertext_modulus(),
    );

    decompress_seeded_lwe_ciphertext_list_with_pre_seeded_generator(
        &mut decompressed_list,
        &compressed.modulus_switch_zeros,
        mask_generator,
    );

    ModulusSwitchNoiseReductionKey {
        modulus_switch_zeros: decompressed_list,
        ms_bound: compressed.ms_bound,
        ms_r_sigma_factor: compressed.ms_r_sigma_factor,
        ms_input_variance: compressed.ms_input_variance,
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

#[cfg(test)]
mod test {
    use crate::core_crypto::prelude::new_seeder;
    use crate::prelude::*;
    use crate::XofSeed;

    use crate::shortint::parameters::v1_1::V1_1_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use crate::xof_key_set::CompressedXofKeySet;
    use crate::*;

    #[test]
    fn test_xof_key_set() {
        let params = shortint::parameters::v1_1::V1_1_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let cpk_params = shortint::parameters::v1_1::compact_public_key_only::p_fail_2_minus_128::ks_pbs::V1_1_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let casting_params = V1_1_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_params = shortint::parameters::v1_1::noise_squashing::p_fail_2_minus_128::V1_1_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let compression_params = shortint::parameters::v1_1::list_compression::p_fail_2_minus_128::V1_1_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let config = ConfigBuilder::with_custom_parameters(params)
            .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
            .enable_noise_squashing(noise_squashing_params)
            .enable_compression(compression_params)
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

        set_server_key(sk);

        let clear_a = rand::random::<u32>();
        let clear_b = rand::random::<u32>();

        let list = CompactCiphertextList::builder(&pk)
            .push(clear_a)
            .push(clear_b)
            .build();
        let expander = list.expand().unwrap();
        let a = expander.get::<FheUint32>(0).unwrap().unwrap();
        let b = expander.get::<FheUint32>(1).unwrap().unwrap();

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
