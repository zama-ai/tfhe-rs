use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{
    allocate_and_generate_new_binary_glwe_secret_key,
    allocate_and_generate_new_lwe_packing_keyswitch_key,
    allocate_and_generate_new_seeded_lwe_packing_keyswitch_key,
    par_allocate_and_generate_new_seeded_lwe_bootstrap_key,
    par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key, GlweSecretKey,
    GlweSecretKeyOwned,
};
use crate::shortint::backward_compatibility::list_compression::{
    CompressionPrivateKeysVersions, NoiseSquashingCompressionPrivateKeyVersions,
};
use crate::shortint::ciphertext::CompressedSquashedNoiseCiphertextList;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::noise_squashing::NoiseSquashingPrivateKeyView;
use crate::shortint::parameters::{CompressionParameters, NoiseSquashingCompressionParameters};
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, ModulusSwitchConfiguration, ShortintBootstrappingKey,
    ShortintCompressedBootstrappingKey,
};
use crate::shortint::{EncryptionKeyChoice, ShortintParameterSet};
use std::fmt::Debug;

use super::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, DecompressionKey,
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressionPrivateKeysVersions)]
pub struct CompressionPrivateKeys {
    pub post_packing_ks_key: GlweSecretKeyOwned<u64>,
    pub params: CompressionParameters,
}

impl CompressionPrivateKeys {
    pub(crate) fn new_compression_key(
        &self,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        pbs_params: ShortintParameterSet,
    ) -> CompressionKey {
        assert_eq!(
            pbs_params.encryption_key_choice(),
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        let compression_params = &self.params;

        assert!(
            compression_params.storage_log_modulus().0
                <= pbs_params
                    .polynomial_size()
                    .to_blind_rotation_input_modulus_log()
                    .0,
            "Compression parameters say to store more bits than useful"
        );

        let packing_key_switching_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_lwe_packing_keyswitch_key(
                &glwe_secret_key.as_lwe_secret_key(),
                &self.post_packing_ks_key,
                compression_params.packing_ks_base_log(),
                compression_params.packing_ks_level(),
                compression_params.packing_ks_key_noise_distribution(),
                pbs_params.ciphertext_modulus(),
                &mut engine.encryption_generator,
            )
        });

        CompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: compression_params.lwe_per_glwe(),
            storage_log_modulus: compression_params.storage_log_modulus(),
        }
    }
    pub(crate) fn new_compressed_compression_key(
        &self,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        pbs_params: ShortintParameterSet,
    ) -> CompressedCompressionKey {
        assert_eq!(
            pbs_params.encryption_key_choice(),
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        let compression_params = &self.params;

        let packing_key_switching_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_seeded_lwe_packing_keyswitch_key(
                &glwe_secret_key.as_lwe_secret_key(),
                &self.post_packing_ks_key,
                compression_params.packing_ks_base_log(),
                compression_params.packing_ks_level(),
                compression_params.packing_ks_key_noise_distribution(),
                pbs_params.ciphertext_modulus(),
                &mut engine.seeder,
            )
        });

        CompressedCompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: compression_params.lwe_per_glwe(),
            storage_log_modulus: compression_params.storage_log_modulus(),
        }
    }

    pub(crate) fn new_decompression_key(
        &self,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        pbs_params: ShortintParameterSet,
    ) -> DecompressionKey {
        self.new_decompression_key_with_params(glwe_secret_key, pbs_params, self.params)
    }

    /// Create a decompression key with different parameters than the one in the secret key.
    ///
    /// This allows for example to compress using cpu parameters and decompress with gpu parameters
    pub(crate) fn new_decompression_key_with_params(
        &self,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        pbs_params: ShortintParameterSet,
        compression_params: CompressionParameters,
    ) -> DecompressionKey {
        ShortintEngine::with_thread_local_mut(|engine| {
            self.new_decompression_key_with_params_and_engine(
                glwe_secret_key,
                pbs_params,
                compression_params,
                engine,
            )
        })
    }

    pub(crate) fn new_decompression_key_with_params_and_engine(
        &self,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        pbs_params: ShortintParameterSet,
        compression_params: CompressionParameters,
        engine: &mut ShortintEngine,
    ) -> DecompressionKey {
        assert_eq!(
            pbs_params.encryption_key_choice(),
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        match compression_params {
            CompressionParameters::Classic(classic_compression_parameters) => {
                let blind_rotate_key = engine.new_classic_bootstrapping_key(
                    &self.post_packing_ks_key.as_lwe_secret_key(),
                    glwe_secret_key,
                    pbs_params.glwe_noise_distribution(),
                    classic_compression_parameters.br_base_log,
                    classic_compression_parameters.br_level,
                    pbs_params.ciphertext_modulus(),
                );

                DecompressionKey {
                    bsk: ShortintBootstrappingKey::Classic {
                        bsk: blind_rotate_key,
                        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration::Standard,
                    },
                    lwe_per_glwe: classic_compression_parameters.lwe_per_glwe,
                }
            }
            CompressionParameters::MultiBit(multi_bit_compression_parameters) => {
                let multi_bit_blind_rotate_key = engine.new_multibit_bootstrapping_key(
                    &self.post_packing_ks_key.as_lwe_secret_key(),
                    glwe_secret_key,
                    pbs_params.glwe_noise_distribution(),
                    multi_bit_compression_parameters.br_base_log,
                    multi_bit_compression_parameters.br_level,
                    multi_bit_compression_parameters.decompression_grouping_factor,
                    pbs_params.ciphertext_modulus(),
                );

                let thread_count = ShortintEngine::get_thread_count_for_multi_bit_pbs(
                    pbs_params.lwe_dimension(),
                    pbs_params.glwe_dimension(),
                    pbs_params.polynomial_size(),
                    pbs_params.pbs_base_log(),
                    pbs_params.pbs_level(),
                    multi_bit_compression_parameters.decompression_grouping_factor,
                );

                DecompressionKey {
                    bsk: ShortintBootstrappingKey::MultiBit {
                        fourier_bsk: multi_bit_blind_rotate_key,
                        thread_count,
                        deterministic_execution: true,
                    },
                    lwe_per_glwe: multi_bit_compression_parameters.lwe_per_glwe,
                }
            }
        }
    }

    pub(crate) fn new_compressed_decompression_key(
        &self,
        glwe_secret_key: &GlweSecretKey<Vec<u64>>,
        pbs_params: ShortintParameterSet,
    ) -> CompressedDecompressionKey {
        assert_eq!(
            pbs_params.encryption_key_choice(),
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        let compression_params = &self.params;

        match compression_params {
            CompressionParameters::Classic(classic_compression_parameters) => {
                let blind_rotate_key = ShortintEngine::with_thread_local_mut(|engine| {
                    par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
                        &self.post_packing_ks_key.as_lwe_secret_key(),
                        glwe_secret_key,
                        classic_compression_parameters.br_base_log,
                        classic_compression_parameters.br_level,
                        pbs_params.glwe_noise_distribution(),
                        pbs_params.ciphertext_modulus(),
                        &mut engine.seeder,
                    )
                });

                CompressedDecompressionKey {
                    bsk: ShortintCompressedBootstrappingKey::Classic {
                        bsk: blind_rotate_key,
                        modulus_switch_noise_reduction_key:
                            CompressedModulusSwitchConfiguration::Standard,
                    },
                    lwe_per_glwe: classic_compression_parameters.lwe_per_glwe,
                }
            }
            CompressionParameters::MultiBit(multi_bit_compression_parameters) => {
                let multi_bit_blind_rotate_key = ShortintEngine::with_thread_local_mut(|engine| {
                    par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key(
                        &self.post_packing_ks_key.as_lwe_secret_key(),
                        glwe_secret_key,
                        multi_bit_compression_parameters.br_base_log,
                        multi_bit_compression_parameters.br_level,
                        pbs_params.glwe_noise_distribution(),
                        multi_bit_compression_parameters.decompression_grouping_factor,
                        pbs_params.ciphertext_modulus(),
                        &mut engine.seeder,
                    )
                });

                CompressedDecompressionKey {
                    bsk: ShortintCompressedBootstrappingKey::MultiBit {
                        seeded_bsk: multi_bit_blind_rotate_key,
                        deterministic_execution: true,
                    },
                    lwe_per_glwe: multi_bit_compression_parameters.lwe_per_glwe,
                }
            }
        }
    }
}

impl ClientKey {
    pub fn new_compression_private_key(
        &self,
        params: CompressionParameters,
    ) -> CompressionPrivateKeys {
        ShortintEngine::with_thread_local_mut(|engine| {
            self.new_compression_private_key_with_engine(params, engine)
        })
    }

    pub(crate) fn new_compression_private_key_with_engine(
        &self,
        params: CompressionParameters,
        engine: &mut ShortintEngine,
    ) -> CompressionPrivateKeys {
        assert_eq!(
            self.parameters().encryption_key_choice(),
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        let post_packing_ks_key = allocate_and_generate_new_binary_glwe_secret_key(
            params.packing_ks_glwe_dimension(),
            params.packing_ks_polynomial_size(),
            &mut engine.secret_generator,
        );

        CompressionPrivateKeys {
            post_packing_ks_key,
            params,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(NoiseSquashingCompressionPrivateKeyVersions)]
pub struct NoiseSquashingCompressionPrivateKey {
    pub(crate) post_packing_ks_key: GlweSecretKeyOwned<u128>,
    pub(crate) params: NoiseSquashingCompressionParameters,
}

impl NoiseSquashingCompressionPrivateKey {
    pub fn new(params: NoiseSquashingCompressionParameters) -> Self {
        let post_packing_ks_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_binary_glwe_secret_key(
                params.packing_ks_glwe_dimension,
                params.packing_ks_polynomial_size,
                &mut engine.secret_generator,
            )
        });

        Self {
            post_packing_ks_key,
            params,
        }
    }

    /// Construct from raw parts
    ///
    /// # Panics
    ///
    /// Panics if params does not match the `post_packing_ks_key`
    pub fn from_raw_parts(
        post_packing_ks_key: GlweSecretKeyOwned<u128>,
        params: NoiseSquashingCompressionParameters,
    ) -> Self {
        assert_eq!(
            post_packing_ks_key.polynomial_size(),
            params.packing_ks_polynomial_size,
            "Invalid polynomial size for NoiseSquashingCompressionPrivateKey, expected {}, got {}",
            params.packing_ks_polynomial_size.0,
            post_packing_ks_key.polynomial_size().0,
        );

        assert_eq!(
            post_packing_ks_key.glwe_dimension(),
            params.packing_ks_glwe_dimension,
            "Invalid GLWE dimension for NoiseSquashingCompressionPrivateKey, expected {}, got {}",
            params.packing_ks_glwe_dimension.0,
            post_packing_ks_key.glwe_dimension().0,
        );

        Self {
            post_packing_ks_key,
            params,
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        GlweSecretKeyOwned<u128>,
        NoiseSquashingCompressionParameters,
    ) {
        let Self {
            post_packing_ks_key,
            params,
        } = self;
        (post_packing_ks_key, params)
    }

    /// Extract and decrypt all the ciphertexts in the list
    pub fn unpack_and_decrypt_squashed_noise_ciphertexts(
        &self,
        compressed_list: &CompressedSquashedNoiseCiphertextList,
    ) -> Vec<u128> {
        let decryption_key = NoiseSquashingPrivateKeyView::from(self);
        (0..compressed_list.len())
            .map(|i| {
                let ciphertext = compressed_list.unpack(i).unwrap(); // i is smaller than list size

                decryption_key.decrypt_squashed_noise_ciphertext(&ciphertext)
            })
            .collect()
    }

    pub fn post_packing_ks_key(&self) -> &GlweSecretKeyOwned<u128> {
        &self.post_packing_ks_key
    }

    pub fn params(&self) -> NoiseSquashingCompressionParameters {
        self.params
    }
}
