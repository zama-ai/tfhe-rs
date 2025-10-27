use crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{
    allocate_and_generate_new_lwe_packing_keyswitch_key, par_generate_lwe_bootstrap_key,
    par_generate_lwe_multi_bit_bootstrap_key, LweBootstrapKey, LweMultiBitBootstrapKey,
};
use crate::integer::compression_keys::{CompressionKey, CompressionPrivateKeys};
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::RadixClientKey;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::PBSParameters;
use crate::shortint::EncryptionKeyChoice;

impl RadixClientKey {
    pub fn new_cuda_compression_decompression_keys(
        &self,
        private_compression_key: &CompressionPrivateKeys,
        streams: &CudaStreams,
    ) -> (CudaCompressionKey, CudaDecompressionKey) {
        let private_compression_key = &private_compression_key.key;

        let compression_params = &private_compression_key.params;

        let AtomicPatternClientKey::Standard(std_cks) = &self.as_ref().key.atomic_pattern else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        assert_eq!(
            self.parameters().encryption_key_choice(),
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        // Compression key
        let packing_key_switching_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_lwe_packing_keyswitch_key(
                &std_cks.large_lwe_secret_key(),
                &private_compression_key.post_packing_ks_key,
                compression_params.packing_ks_base_log(),
                compression_params.packing_ks_level(),
                compression_params.packing_ks_key_noise_distribution(),
                self.parameters().ciphertext_modulus(),
                &mut engine.encryption_generator,
            )
        });

        let glwe_compression_key = CompressionKey {
            key: crate::shortint::list_compression::CompressionKey {
                packing_key_switching_key,
                lwe_per_glwe: compression_params.lwe_per_glwe(),
                storage_log_modulus: private_compression_key.params.storage_log_modulus(),
            },
        };

        let cuda_compression_key =
            CudaCompressionKey::from_compression_key(&glwe_compression_key, streams);

        let blind_rotate_key = match std_cks.parameters {
            PBSParameters::PBS(_) => {
                let mut bsk = LweBootstrapKey::new(
                    0u64,
                    self.parameters().glwe_dimension().to_glwe_size(),
                    self.parameters().polynomial_size(),
                    private_compression_key.params.br_base_log(),
                    private_compression_key.params.br_level(),
                    compression_params
                        .packing_ks_glwe_dimension()
                        .to_equivalent_lwe_dimension(
                            compression_params.packing_ks_polynomial_size(),
                        ),
                    self.parameters().ciphertext_modulus(),
                );

                ShortintEngine::with_thread_local_mut(|engine| {
                    par_generate_lwe_bootstrap_key(
                        &private_compression_key
                            .post_packing_ks_key
                            .as_lwe_secret_key(),
                        &std_cks.glwe_secret_key,
                        &mut bsk,
                        self.parameters().glwe_noise_distribution(),
                        &mut engine.encryption_generator,
                    );
                });

                CudaBootstrappingKey::Classic(CudaLweBootstrapKey::from_lwe_bootstrap_key(
                    &bsk, None, streams,
                ))
            }
            PBSParameters::MultiBitPBS(pbs_params) => {
                let mut bsk = LweMultiBitBootstrapKey::new(
                    0u64,
                    self.parameters().glwe_dimension().to_glwe_size(),
                    self.parameters().polynomial_size(),
                    private_compression_key.params.br_base_log(),
                    private_compression_key.params.br_level(),
                    compression_params
                        .packing_ks_glwe_dimension()
                        .to_equivalent_lwe_dimension(
                            compression_params.packing_ks_polynomial_size(),
                        ),
                    pbs_params.grouping_factor,
                    self.parameters().ciphertext_modulus(),
                );

                ShortintEngine::with_thread_local_mut(|engine| {
                    par_generate_lwe_multi_bit_bootstrap_key(
                        &private_compression_key
                            .post_packing_ks_key
                            .as_lwe_secret_key(),
                        &std_cks.glwe_secret_key,
                        &mut bsk,
                        self.parameters().glwe_noise_distribution(),
                        &mut engine.encryption_generator,
                    );
                });

                CudaBootstrappingKey::MultiBit(
                    CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(&bsk, streams),
                )
            }
        };

        let cuda_decompression_key = CudaDecompressionKey {
            blind_rotate_key,
            lwe_per_glwe: compression_params.lwe_per_glwe(),
            glwe_dimension: self.parameters().glwe_dimension(),
            polynomial_size: self.parameters().polynomial_size(),
            message_modulus: self.parameters().message_modulus(),
            carry_modulus: self.parameters().carry_modulus(),
            ciphertext_modulus: self.parameters().ciphertext_modulus(),
        };

        (cuda_compression_key, cuda_decompression_key)
    }
}
