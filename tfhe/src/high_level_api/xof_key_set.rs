use crate::core_crypto::commons::generators::{MaskRandomGenerator, NoiseRandomGenerator};
use crate::core_crypto::commons::math::random::{CompressionSeed, RandomGenerator};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::{LweCompactPublicKey, LweKeyswitchKey};
use crate::core_crypto::fft_impl::fft64::math::fft::FftView;
use crate::core_crypto::prelude::*;
use crate::integer::noise_squashing::CompressedNoiseSquashingKey;
use crate::shortint::atomic_pattern::compressed::{
    CompressedAtomicPatternServerKey, CompressedStandardAtomicPatternServerKey,
};
use crate::shortint::atomic_pattern::AtomicPatternServerKey;
use crate::shortint::ciphertext::MaxDegree;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::parameters::{
    ModulusSwitchNoiseReductionParams, ModulusSwitchType, NoiseSquashingParameters,
};
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, CompressedModulusSwitchNoiseReductionKey,
    ModulusSwitchConfiguration, ModulusSwitchNoiseReductionKey, ShortintBootstrappingKey,
    ShortintCompressedBootstrappingKey,
};
use crate::shortint::{PBSParameters, ShortintParameterSet};
use crate::{
    integer, shortint, ClientKey, CompactPublicKey, CompressedCompactPublicKey,
    CompressedServerKey, ServerKey, Tag,
};
use aligned_vec::ABox;
use dyn_stack::PodStack;
use serde::{Deserialize, Serialize};
use tfhe_csprng::seeders::{Seed, XofSeed};
use tfhe_fft::c64;

use crate::integer::key_switching_key::{
    CompressedKeySwitchingKeyMaterial, KeySwitchingKeyMaterial,
};
use crate::shortint::noise_squashing::{
    CompressedShortint128BootstrappingKey, Shortint128BootstrappingKey,
};
use rayon::prelude::*;
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

        let noise_squashing_bs_key =
            ck.key
                .noise_squashing_private_key
                .as_ref()
                .map(|noise_squashing_key| {
                    let noise_squashing_parameters =
                        noise_squashing_key.noise_squashing_parameters();

                    let shortint_key = match noise_squashing_parameters {
                        NoiseSquashingParameters::Classic(ns_params) => {
                            let core_bsk =
                            allocate_and_generate_lwe_bootstrapping_key_with_pre_seeded_generator(
                                lwe_secret_key,
                                noise_squashing_key.key.post_noise_squashing_secret_key(),
                                ns_params.decomp_base_log,
                                ns_params.decomp_level_count,
                                ns_params.glwe_noise_distribution,
                                ns_params.ciphertext_modulus,
                                &mut encryption_rand_gen,
                            );

                            let compressed_mod_switch_config =
                                generate_compressed_mod_switch_config(
                                    &ns_params.modulus_switch_noise_reduction_params,
                                    computation_parameters,
                                    lwe_secret_key,
                                    &mut encryption_rand_gen,
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

                    CompressedNoiseSquashingKey::from_raw_parts(
                        shortint::noise_squashing::CompressedNoiseSquashingKey::from_raw_parts(
                            shortint_key,
                            noise_squashing_parameters.message_modulus(),
                            noise_squashing_parameters.carry_modulus(),
                            noise_squashing_parameters.ciphertext_modulus(),
                        ),
                    )
                });

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
            let mod_switch_noise_key = generate_compressed_mod_switch_config(
                &pbs_params.modulus_switch_noise_reduction_params,
                computation_parameters,
                lwe_secret_key,
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

        let noise_squashing_compression_key = None;
        let compressed_server_key = CompressedServerKey::from_raw_parts(
            integer_compressed_server_key,
            Some(integer_ksk_material),
            compression_key,
            decompression_key,
            noise_squashing_bs_key,
            noise_squashing_compression_key,
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
                            blind_rotate_key: core_fourier_bsk,
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
                        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration::Standard,
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

            let noise_squashing_key = self
                .compressed_server_key
                .integer_key
                .noise_squashing_key
                .as_ref()
                .map(|compressed_nsk| {
                    let CompressedShortint128BootstrappingKey::Classic {
                        bsk: compressed_bsk,
                        modulus_switch_noise_reduction_key,
                    } = compressed_nsk.key.bootstrapping_key()
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

                    let ms_nrk = decompress_compressed_mod_switch_config(
                        modulus_switch_noise_reduction_key,
                        &mut mask_generator,
                    );

                    let decompressed = Shortint128BootstrappingKey::Classic {
                        bsk: core_fourier_bsk,
                        modulus_switch_noise_reduction_key: ms_nrk,
                    };

                    integer::noise_squashing::NoiseSquashingKey::from_raw_parts(
                        shortint::noise_squashing::NoiseSquashingKey::from_raw_parts(
                            decompressed,
                            compressed_nsk.key.message_modulus(),
                            compressed_nsk.key.carry_modulus(),
                            compressed_nsk.key.output_ciphertext_modulus(),
                        ),
                    )
                });

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
                                } => decompress_compressed_mod_switch_config(
                                    modulus_switch_noise_reduction_key,
                                    &mut mask_generator,
                                ),
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

            let noise_squashing_compression_key = None;
            ServerKey::from_raw_parts(
                integer_sk,
                Some(integer_cpk_ksk),
                compression_key,
                decompression_key,
                noise_squashing_key,
                noise_squashing_compression_key,
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

fn decompress_compressed_mod_switch_config<Gen>(
    config: &CompressedModulusSwitchConfiguration<u64>,
    mask_generator: &mut MaskRandomGenerator<Gen>,
) -> ModulusSwitchConfiguration<u64>
where
    Gen: ByteRandomGenerator,
{
    match config {
        CompressedModulusSwitchConfiguration::Standard => ModulusSwitchConfiguration::Standard,
        CompressedModulusSwitchConfiguration::CenteredMeanNoiseReduction => {
            ModulusSwitchConfiguration::CenteredMeanNoiseReduction
        }
        CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(key) => {
            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                decompress_compressed_modulus_switch_noise_reduction_key_with_pre_seeded_generator(
                    key,
                    mask_generator,
                ),
            )
        }
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

fn generate_compressed_mod_switch_config(
    modulus_switch_noise_reduction_params: &ModulusSwitchType,
    computation_parameters: ShortintParameterSet,
    lwe_secret_key: &LweSecretKeyOwned<u64>,
    encryption_rand_gen: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> CompressedModulusSwitchConfiguration<u64> {
    match modulus_switch_noise_reduction_params {
        ModulusSwitchType::Standard => {
            CompressedModulusSwitchConfiguration::Standard
        }
        ModulusSwitchType::DriftTechniqueNoiseReduction(params) => {
            CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(allocate_and_generate_compressed_modulus_switch_noise_reduction_key_with_pre_seeded_generator(
                lwe_secret_key,
                params,
                computation_parameters.lwe_noise_distribution(),
                computation_parameters.ciphertext_modulus(),
                encryption_rand_gen,
            ))
        }
        ModulusSwitchType::CenteredMeanNoiseReduction => {
            CompressedModulusSwitchConfiguration::CenteredMeanNoiseReduction
        }
    }
}

#[cfg(test)]
mod test {
    use crate::core_crypto::prelude::new_seeder;
    use crate::prelude::*;
    use crate::XofSeed;
    use pulp::c64;

    use crate::shortint::parameters::v1_1::V1_1_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use crate::xof_key_set::{
        par_convert_fourier_lwe_bootstrap_key_to_standard, CompressedXofKeySet,
    };
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

    #[test]
    fn test_core() {
        use crate::core_crypto::prelude::*;

        // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
        // computations
        // Define the parameters for a 4 bits message able to hold the doubled 2 bits message
        let small_lwe_dimension = LweDimension(742);
        let glwe_dimension = GlweDimension(1);
        let polynomial_size = PolynomialSize(2048);
        let lwe_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
        let glwe_noise_distribution = Gaussian::from_dispersion_parameter(
            StandardDev(0.00000000000000029403601535432533),
            0.0,
        );
        let pbs_base_log = DecompositionBaseLog(23);
        let pbs_level = DecompositionLevelCount(1);
        let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

        // Request the best seeder possible, starting with hardware entropy sources and falling back
        // to /dev/random on Unix systems if enabled via cargo features
        let mut boxed_seeder = new_seeder();
        // Get a mutable reference to the seeder as a trait object from the Box returned by
        // new_seeder
        let seeder = boxed_seeder.as_mut();

        // Create a generator which uses a CSPRNG to generate secret keys
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
        // noise
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        println!("Generating keys...");

        // Generate an LweSecretKey with binary coefficients
        let small_lwe_sk = LweSecretKey::<Vec<u64>>::generate_new_binary(
            small_lwe_dimension,
            &mut secret_generator,
        );

        // Generate a GlweSecretKey with binary coefficients
        let glwe_sk = GlweSecretKey::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );

        // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        // Generate the bootstrapping key, we use the parallel variant for performance reason
        let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            pbs_base_log,
            pbs_level,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        // Create the empty bootstrapping key in the Fourier domain
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            std_bootstrapping_key.input_lwe_dimension(),
            std_bootstrapping_key.glwe_size(),
            std_bootstrapping_key.polynomial_size(),
            std_bootstrapping_key.decomposition_base_log(),
            std_bootstrapping_key.decomposition_level_count(),
        );

        // Use the conversion function (a memory optimized version also exists but is more
        // complicated to use) to convert the standard bootstrapping key to the Fourier
        // domain
        par_convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
        // We don't need the standard bootstrapping key anymore

        let mut std_bootstrapping_key2 = std_bootstrapping_key.clone();
        std_bootstrapping_key2.as_mut().fill(0);
        par_convert_fourier_lwe_bootstrap_key_to_standard(
            &fourier_bsk,
            &mut std_bootstrapping_key2,
        );
        // assert_eq!(std_bootstrapping_key, std_bootstrapping_key2);

        let mut fourier_bsk2 = fourier_bsk.clone();
        fourier_bsk2.as_mut_view().data().fill(c64::ZERO);
        par_convert_standard_lwe_bootstrap_key_to_fourier(
            &std_bootstrapping_key2,
            &mut fourier_bsk2,
        );
        let fourier_bsk = fourier_bsk2;

        // Our 4 bits message space
        let message_modulus = 1u64 << 4;

        // Our input message
        let input_message = 3u64;

        // Delta used to encode 4 bits of message + a bit of padding on u64
        let delta = (1_u64 << 63) / message_modulus;

        // Apply our encoding
        let plaintext = Plaintext(input_message * delta);

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_sk,
            plaintext,
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        // Compute a cleartext multiplication by 2
        let mut cleartext_multiplication_ct = lwe_ciphertext_in.clone();
        println!("Performing cleartext multiplication...");
        lwe_ciphertext_cleartext_mul(
            &mut cleartext_multiplication_ct,
            &lwe_ciphertext_in,
            Cleartext(2),
        );

        // Decrypt the cleartext multiplication result
        let cleartext_multiplication_plaintext: Plaintext<u64> =
            decrypt_lwe_ciphertext(&small_lwe_sk, &cleartext_multiplication_ct);

        // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
        // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want
        // to round the 5 MSB, 1 bit of padding plus our 4 bits of message
        let signed_decomposer =
            SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

        // Round and remove our encoding
        let cleartext_multiplication_result: u64 =
            signed_decomposer.closest_representable(cleartext_multiplication_plaintext.0) / delta;

        println!("Checking result...");
        assert_eq!(6, cleartext_multiplication_result);
        println!(
            "Cleartext multiplication result is correct! \
        Expected 6, got {cleartext_multiplication_result}"
        );

        // Now we will use a PBS to compute the same multiplication, it is NOT the recommended way
        // of doing this operation in terms of performance as it's much more costly than a
        // multiplication with a cleartext, however it resets the noise in a ciphertext to a
        // nominal level and allows to evaluate arbitrary functions so depending on your use
        // case it can be a better fit.

        // Generate the accumulator for our multiplication by 2 using a simple closure
        let accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            message_modulus as usize,
            ciphertext_modulus,
            delta,
            |x: u64| 2 * x,
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut pbs_multiplication_ct = LweCiphertext::new(
            0u64,
            big_lwe_sk.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );
        println!("Computing PBS...");
        programmable_bootstrap_lwe_ciphertext(
            &lwe_ciphertext_in,
            &mut pbs_multiplication_ct,
            &accumulator,
            &fourier_bsk,
        );

        // Decrypt the PBS multiplication result
        let pbs_multiplication_plaintext: Plaintext<u64> =
            decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);

        // Round and remove our encoding
        let pbs_multiplication_result: u64 =
            signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

        println!("Checking result...");
        assert_eq!(6, pbs_multiplication_result);
        println!(
            "Multiplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
        );
    }

    #[test]
    fn compress_decompress() {
        let params = shortint::parameters::v1_1::V1_1_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let cpk_params = shortint::parameters::v1_1::compact_public_key_only::p_fail_2_minus_128::ks_pbs::V1_1_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let casting_params = V1_1_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_params =
        shortint::parameters::v1_1::noise_squashing::p_fail_2_minus_128::V1_1_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let compression_params =
        shortint::parameters::v1_1::list_compression::p_fail_2_minus_128::V1_1_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

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

        let compressed_key_set =
            CompressedXofKeySet::with_seed(pub_seed.clone(), priv_seed, &cks).unwrap();

        let key_set = compressed_key_set.decompress();

        let (pk, sk) = key_set.into_raw_parts();

        set_server_key(sk.clone());

        let clear_a = rand::random::<u32>();
        let clear_b = rand::random::<u32>();

        let a = FheUint32::encrypt(clear_a, &cks);
        let b = FheUint32::encrypt(clear_b, &cks);

        let list = CompactCiphertextList::builder(&pk)
            .push(clear_a)
            .push(clear_b)
            .build();

        let c = &a * &b;
        let d = &a & &b;

        let c_dec: u32 = c.decrypt(&cks);
        let d_dec: u32 = d.decrypt(&cks);

        assert_eq!(clear_a.wrapping_mul(clear_b), c_dec);
        assert_eq!(clear_a & clear_b, d_dec);

        let csk = sk.compress();
        let cpk = pk.compress();

        let compressed_xof_key_set = CompressedXofKeySet::from_raw_parts(pub_seed, cpk, csk);
        let (pk, sk) = compressed_xof_key_set.decompress().into_raw_parts();

        set_server_key(sk.clone());
        {
            let c = &a * &b;
            let d = &a & &b;

            let c_dec: u32 = c.decrypt(&cks);
            let d_dec: u32 = d.decrypt(&cks);

            assert_eq!(clear_a.wrapping_mul(clear_b), c_dec);
            assert_eq!(clear_a & clear_b, d_dec);
        }
        {
            // First test we can decompress list from before the compress->decompress
            let expander = list.expand().unwrap();
            let a = expander.get::<FheUint32>(0).unwrap().unwrap();
            let b = expander.get::<FheUint32>(1).unwrap().unwrap();

            let c = &a * &b;
            let d = &a & &b;

            let c_dec: u32 = c.decrypt(&cks);
            let d_dec: u32 = d.decrypt(&cks);

            assert_eq!(clear_a.wrapping_mul(clear_b), c_dec);
            assert_eq!(clear_a & clear_b, d_dec);

            // Then test we can compress our own stuff
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
        }
        {
            let compressed_list = CompressedCiphertextListBuilder::new()
                .push(a)
                .push(b)
                .build()
                .unwrap();

            let a: FheUint32 = compressed_list.get(0).unwrap().unwrap();
            let da: u32 = a.decrypt(&cks);
            assert_eq!(da, clear_a);
            let b: FheUint32 = compressed_list.get(1).unwrap().unwrap();
            let db: u32 = b.decrypt(&cks);
            assert_eq!(db, clear_b);
        }
    }
}

fn compress_lwe_key_switching_key<Scalar>(
    ksk: &LweKeyswitchKeyOwned<Scalar>,
) -> SeededLweKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedInteger,
{
    let mut output = SeededLweKeyswitchKeyOwned::new(
        Scalar::ZERO,
        ksk.decomposition_base_log(),
        ksk.decomposition_level_count(),
        ksk.input_key_lwe_dimension(),
        ksk.output_key_lwe_dimension(),
        Seed(0).into(),
        ksk.ciphertext_modulus(),
    );

    let mut out_iter = output.as_mut().iter_mut();
    for lev in ksk.iter() {
        for lwe in lev.iter() {
            *out_iter.next().unwrap() = *lwe.get_body().data;
        }
    }

    assert!(out_iter.next().is_none());

    output
}

fn compress_lwe_bootstrap_key<Scalar>(
    bsk: &LweBootstrapKeyOwned<Scalar>,
) -> SeededLweBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedInteger,
{
    let mut output = SeededLweBootstrapKeyOwned::new(
        Scalar::ZERO,
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
        bsk.input_lwe_dimension(),
        Seed(0).into(),
        bsk.ciphertext_modulus(),
    );

    let mut out_iter = output.as_mut().chunks_exact_mut(bsk.polynomial_size().0);
    for ggsw in bsk.iter() {
        for glev in ggsw.iter() {
            for glwe in glev.as_glwe_list().iter() {
                out_iter
                    .next()
                    .unwrap()
                    .copy_from_slice(glwe.get_body().as_ref());
            }
        }
    }
    assert!(out_iter.next().is_none());

    output
}

fn par_convert_fourier_polynomials_list_to_standard<Scalar: UnsignedTorus>(
    dest: &mut [Scalar],
    origin: &[c64],
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) {
    assert_eq!(dest.len() % polynomial_size.0, 0);
    let nb_polynomial = dest.len() / polynomial_size.0;

    let f_polynomial_size = polynomial_size.to_fourier_polynomial_size().0;

    assert_eq!(nb_polynomial * f_polynomial_size, origin.len());

    let nb_threads = rayon::current_num_threads();

    let chunk_size = nb_polynomial.div_ceil(nb_threads);

    dest.par_chunks_mut(chunk_size * polynomial_size.0)
        .zip_eq(origin.par_chunks(chunk_size * f_polynomial_size))
        .for_each(|(standard_poly_chunk, fourier_poly_chunk)| {
            let stack_len = fft
                .backward_scratch()
                .unwrap()
                .try_unaligned_bytes_required()
                .unwrap();
            let mut mem = vec![0; stack_len];

            let stack = PodStack::new(&mut mem);

            for (standard_poly, fourier_poly) in izip!(
                standard_poly_chunk.chunks_exact_mut(polynomial_size.0),
                fourier_poly_chunk.chunks_exact(f_polynomial_size)
            ) {
                fft.backward_as_torus(
                    PolynomialMutView::from_container(standard_poly),
                    crate::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomialView {
                        data: fourier_poly,
                    },
                    stack,
                )
            }
        });
}

fn par_convert_fourier_lwe_bootstrap_key_to_standard<Scalar, InputCont, OutputCont>(
    input_bsk: &FourierLweBootstrapKey<InputCont>,
    output_bsk: &mut LweBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = c64>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        input_bsk.polynomial_size(),
        output_bsk.polynomial_size(),
        "Mismatched PolynomialSize between input_bsk {:?} and output_bsk {:?}",
        input_bsk.polynomial_size(),
        output_bsk.polynomial_size(),
    );

    assert_eq!(
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
        "Mismatched GlweSize"
    );

    assert_eq!(
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
    );

    assert_eq!(
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
        "Mismatched DecompositionLevelCount between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
    );

    assert_eq!(
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension between input_bsk {:?} and output_bsk {:?}",
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
    );

    let fft = Fft::new(input_bsk.polynomial_size());
    let fft = fft.as_view();
    let fbsk_view = input_bsk.as_view();
    par_convert_fourier_polynomials_list_to_standard(
        output_bsk.as_mut(),
        fbsk_view.data(),
        input_bsk.polynomial_size(),
        fft,
    );
}

fn compress_fourier_lwe_bootstrap_key(
    bsk: &FourierLweBootstrapKeyOwned,
) -> SeededLweBootstrapKeyOwned<u64> {
    let mut tmp_standard_bsk = LweBootstrapKeyOwned::new(
        0u64,
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
        bsk.input_lwe_dimension(),
        CiphertextModulus::new_native(),
    );

    par_convert_fourier_lwe_bootstrap_key_to_standard(bsk, &mut tmp_standard_bsk);
    compress_lwe_bootstrap_key(&tmp_standard_bsk)
}

pub fn par_convert_fourier_128_lwe_bootstrap_key_to_standard<Scalar, InputCont, OutputCont>(
    input_bsk: &Fourier128LweBootstrapKey<InputCont>,
    output_bsk: &mut LweBootstrapKey<OutputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = f64>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        input_bsk.polynomial_size(),
        output_bsk.polynomial_size(),
        "Mismatched PolynomialSize between input_bsk {:?} and output_bsk {:?}",
        input_bsk.polynomial_size(),
        output_bsk.polynomial_size(),
    );

    assert_eq!(
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
        "Mismatched GlweSize"
    );

    assert_eq!(
        input_bsk.decomposition_base_log(),
        output_bsk.decomposition_base_log(),
        "Mismatched DecompositionBaseLog between input_bsk {:?} and output_bsk {:?}",
        input_bsk.glwe_size(),
        output_bsk.glwe_size(),
    );

    assert_eq!(
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
        "Mismatched DecompositionLevelCount between input_bsk {:?} and output_bsk {:?}",
        input_bsk.decomposition_level_count(),
        output_bsk.decomposition_level_count(),
    );

    assert_eq!(
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension between input_bsk {:?} and output_bsk {:?}",
        input_bsk.input_lwe_dimension(),
        output_bsk.input_lwe_dimension(),
    );

    let fft = Fft128::new(input_bsk.polynomial_size());
    let fft = fft.as_view();

    let fourier_poly_size = input_bsk.polynomial_size().to_fourier_polynomial_size();

    let (data_re0, data_re1, data_im0, data_im1) = input_bsk.as_view().data();

    data_re0
        .par_chunks_exact(fourier_poly_size.0)
        .zip(
            data_re1.par_chunks_exact(fourier_poly_size.0).zip(
                data_im0
                    .par_chunks_exact(fourier_poly_size.0)
                    .zip(data_im1.par_chunks_exact(fourier_poly_size.0)),
            ),
        )
        .zip(output_bsk.as_mut_polynomial_list().par_iter_mut())
        .for_each(
            |((fourier_re0, (fourier_re1, (fourier_im0, fourier_im1))), mut coef_poly)| {
                let size = fft
                    .backward_scratch()
                    .unwrap()
                    .try_unaligned_bytes_required()
                    .unwrap();
                let mut data = vec![0u8; size];
                let stack = PodStack::new(&mut data);
                fft.backward_as_torus(
                    coef_poly.as_mut(),
                    fourier_re0,
                    fourier_re1,
                    fourier_im0,
                    fourier_im1,
                    stack,
                );
            },
        );
}

fn compress_fourier_128_lwe_bootstrap_key(
    bsk: &Fourier128LweBootstrapKeyOwned,
) -> SeededLweBootstrapKeyOwned<u128> {
    let mut tmp_standard_bsk = LweBootstrapKeyOwned::new(
        0u128,
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
        bsk.input_lwe_dimension(),
        CiphertextModulus::new_native(),
    );

    par_convert_fourier_128_lwe_bootstrap_key_to_standard(bsk, &mut tmp_standard_bsk);
    compress_lwe_bootstrap_key(&tmp_standard_bsk)
}

fn compress_mod_switch_config(
    input: &ModulusSwitchConfiguration<u64>,
) -> CompressedModulusSwitchConfiguration<u64> {
    match input {
        ModulusSwitchConfiguration::Standard => CompressedModulusSwitchConfiguration::Standard,
        ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(key) => {
            let mut bodies = vec![0u64; key.modulus_switch_zeros.lwe_ciphertext_count().0];
            for (lwe, output) in key.modulus_switch_zeros.iter().zip(bodies.iter_mut()) {
                *output = *lwe.get_body().data;
            }

            let compressed_key = CompressedModulusSwitchNoiseReductionKey {
                modulus_switch_zeros: SeededLweCiphertextList::from_container(
                    bodies,
                    key.modulus_switch_zeros.lwe_size(),
                    Seed(0).into(),
                    key.modulus_switch_zeros.ciphertext_modulus(),
                ),
                ms_bound: key.ms_bound,
                ms_r_sigma_factor: key.ms_r_sigma_factor,
                ms_input_variance: key.ms_input_variance,
            };
            CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(compressed_key)
        }
        ModulusSwitchConfiguration::CenteredMeanNoiseReduction => {
            CompressedModulusSwitchConfiguration::CenteredMeanNoiseReduction
        }
    }
}

fn compress_lwe_packing_key_switching_key<Scalar>(
    input: &LwePackingKeyswitchKeyOwned<Scalar>,
) -> SeededLwePackingKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedInteger,
{
    let mut output = SeededLwePackingKeyswitchKeyOwned::new(
        Scalar::ZERO,
        input.decomposition_base_log(),
        input.decomposition_level_count(),
        input.input_key_lwe_dimension(),
        input.output_key_glwe_dimension(),
        input.output_key_polynomial_size(),
        Seed(0).into(),
        input.ciphertext_modulus(),
    );

    let mut out_iter = output
        .as_mut()
        .chunks_exact_mut(input.output_polynomial_size().0);
    for glev in input.iter() {
        for glwe in glev.iter() {
            out_iter
                .next()
                .unwrap()
                .copy_from_slice(glwe.get_body().as_ref());
        }
    }
    assert!(out_iter.next().is_none());

    output
}

impl ShortintBootstrappingKey<u64> {
    fn compress(&self) -> ShortintCompressedBootstrappingKey<u64> {
        match self {
            ShortintBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => ShortintCompressedBootstrappingKey::Classic {
                bsk: compress_fourier_lwe_bootstrap_key(bsk),
                modulus_switch_noise_reduction_key: compress_mod_switch_config(
                    modulus_switch_noise_reduction_key,
                ),
            },
            ShortintBootstrappingKey::MultiBit { .. } => {
                panic!("Multi-bit not supported")
            }
        }
    }
}

impl crate::shortint::ServerKey {
    fn compress(&self) -> crate::shortint::CompressedServerKey {
        match &self.atomic_pattern {
            AtomicPatternServerKey::Standard(ap) => {
                let compressed_ksk = compress_lwe_key_switching_key(&ap.key_switching_key);
                let compressed_bsk = ap.bootstrapping_key.compress();
                let compressed_ap = CompressedAtomicPatternServerKey::Standard(
                    CompressedStandardAtomicPatternServerKey::from_raw_parts(
                        compressed_ksk,
                        compressed_bsk,
                        ap.pbs_order,
                    ),
                );
                crate::shortint::CompressedServerKey::from_raw_parts(
                    compressed_ap,
                    self.message_modulus,
                    self.carry_modulus,
                    self.max_degree,
                    self.max_noise_level,
                )
            }
            AtomicPatternServerKey::KeySwitch32(_) => {
                panic!("Unsupported")
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported")
            }
        }
    }
}

impl crate::integer::ServerKey {
    fn compress(&self) -> crate::integer::CompressedServerKey {
        crate::integer::CompressedServerKey::from_raw_parts(self.key.compress())
    }
}

impl KeySwitchingKeyMaterial {
    fn compress(&self) -> CompressedKeySwitchingKeyMaterial {
        CompressedKeySwitchingKeyMaterial {
            material: shortint::key_switching_key::CompressedKeySwitchingKeyMaterial {
                key_switching_key: compress_lwe_key_switching_key(&self.material.key_switching_key),
                cast_rshift: self.material.cast_rshift,
                destination_key: self.material.destination_key,
            },
        }
    }
}

impl integer::noise_squashing::NoiseSquashingKey {
    fn compress(&self) -> CompressedNoiseSquashingKey {
        let Shortint128BootstrappingKey::Classic {
            bsk,
            modulus_switch_noise_reduction_key,
        } = self.key.bootstrapping_key()
        else {
            panic!("Compression for multibit key not supported")
        };

        let compressed_bsk = compress_fourier_128_lwe_bootstrap_key(bsk);
        let compressed_mod_switch = compress_mod_switch_config(modulus_switch_noise_reduction_key);

        CompressedNoiseSquashingKey::from_raw_parts(
            shortint::noise_squashing::CompressedNoiseSquashingKey::from_raw_parts(
                CompressedShortint128BootstrappingKey::Classic {
                    bsk: compressed_bsk,
                    modulus_switch_noise_reduction_key: compressed_mod_switch,
                },
                self.key.message_modulus(),
                self.key.carry_modulus(),
                self.key.output_ciphertext_modulus(),
            ),
        )
    }
}

impl integer::ciphertext::NoiseSquashingCompressionKey {
    fn compress(&self) -> integer::ciphertext::CompressedNoiseSquashingCompressionKey {
        let (pksk, lwe_count) = self.key.clone().into_raw_parts();
        let compressed_pksk = compress_lwe_packing_key_switching_key(&pksk);

        integer::ciphertext::CompressedNoiseSquashingCompressionKey::from_raw_parts(
            shortint::list_compression::CompressedNoiseSquashingCompressionKey::from_raw_parts(
                compressed_pksk,
                lwe_count,
            ),
        )
    }
}

impl ServerKey {
    pub fn compress(&self) -> CompressedServerKey {
        let crate::high_level_api::keys::IntegerServerKey {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
        } = &*self.key;

        CompressedServerKey {
            integer_key: crate::high_level_api::keys::IntegerCompressedServerKey {
                key: key.compress(),
                cpk_key_switching_key_material: cpk_key_switching_key_material
                    .as_ref()
                    .map(|k| k.compress()),
                compression_key: compression_key.as_ref().map(|key| {
                    let shortint_key = &key.key;

                    integer::compression_keys::CompressedCompressionKey::from_raw_parts(
                        shortint::list_compression::CompressedCompressionKey {
                            packing_key_switching_key: compress_lwe_packing_key_switching_key(
                                &shortint_key.packing_key_switching_key,
                            ),
                            lwe_per_glwe: shortint_key.lwe_per_glwe,
                            storage_log_modulus: shortint_key.storage_log_modulus,
                        },
                    )
                }),
                decompression_key: decompression_key.as_ref().map(|key| {
                    let shortint_key = &key.key;
                    crate::integer::compression_keys::CompressedDecompressionKey::from_raw_parts(
                        crate::shortint::list_compression::CompressedDecompressionKey {
                            blind_rotate_key: compress_fourier_lwe_bootstrap_key(
                                &shortint_key.blind_rotate_key,
                            ),
                            lwe_per_glwe: shortint_key.lwe_per_glwe,
                        },
                    )
                }),
                noise_squashing_key: noise_squashing_key.as_ref().map(|key| key.compress()),
                noise_squashing_compression_key: noise_squashing_compression_key
                    .as_ref()
                    .map(|key| key.compress()),
            },
            tag: self.tag.clone(),
        }
    }
}

impl CompactPublicKey {
    pub fn compress(&self) -> CompressedCompactPublicKey {
        let core_pk = &self.key.key.key.key;

        let mut seeded_key = SeededLweCompactPublicKey::new(
            0u64,
            core_pk.lwe_dimension(),
            Seed(0).into(),
            core_pk.ciphertext_modulus(),
        );

        seeded_key
            .get_mut_body()
            .as_mut()
            .copy_from_slice(core_pk.get_body().as_ref());

        CompressedCompactPublicKey {
            key: crate::high_level_api::keys::IntegerCompressedCompactPublicKey {
                key: crate::integer::CompressedCompactPublicKey {
                    key: crate::shortint::CompressedCompactPublicKey {
                        key: seeded_key,
                        parameters: self.parameters(),
                    },
                },
            },
            tag: self.tag.clone(),
        }
    }
}
