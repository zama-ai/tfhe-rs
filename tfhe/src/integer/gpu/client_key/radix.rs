use crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{
    allocate_and_generate_new_lwe_packing_keyswitch_key, par_generate_lwe_bootstrap_key,
    LweBootstrapKey,
};
use crate::integer::compression_keys::{CompressionKey, CompressionPrivateKeys};
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::RadixClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::{ClassicPBSParameters, EncryptionKeyChoice, PBSParameters};

impl RadixClientKey {
    pub fn new_cuda_compression_decompression_keys(
        &self,
        private_compression_key: &CompressionPrivateKeys,
        streams: &CudaStreams,
    ) -> (CudaCompressionKey, CudaDecompressionKey) {
        let private_compression_key = &private_compression_key.key;

        let cks_params: ClassicPBSParameters = match self.parameters() {
            PBSParameters::PBS(a) => a,
            PBSParameters::MultiBitPBS(_) => {
                panic!("Compression is currently not compatible with Multi Bit PBS")
            }
        };
        let params = &private_compression_key.params;

        assert_eq!(
            cks_params.encryption_key_choice,
            EncryptionKeyChoice::Big,
            "Compression is only compatible with ciphertext in post PBS dimension"
        );

        // Compression key
        let packing_key_switching_key = ShortintEngine::with_thread_local_mut(|engine| {
            allocate_and_generate_new_lwe_packing_keyswitch_key(
                &self.as_ref().key.large_lwe_secret_key(),
                &private_compression_key.post_packing_ks_key,
                params.packing_ks_base_log,
                params.packing_ks_level,
                params.packing_ks_key_noise_distribution,
                self.parameters().ciphertext_modulus(),
                &mut engine.encryption_generator,
            )
        });

        let glwe_compression_key = CompressionKey {
            key: crate::shortint::list_compression::CompressionKey {
                packing_key_switching_key,
                lwe_per_glwe: params.lwe_per_glwe,
                storage_log_modulus: private_compression_key.params.storage_log_modulus,
            },
        };

        let cuda_compression_key =
            CudaCompressionKey::from_compression_key(&glwe_compression_key, streams);

        // Decompression key
        let mut bsk = LweBootstrapKey::new(
            0u64,
            self.parameters().glwe_dimension().to_glwe_size(),
            self.parameters().polynomial_size(),
            private_compression_key.params.br_base_log,
            private_compression_key.params.br_level,
            params
                .packing_ks_glwe_dimension
                .to_equivalent_lwe_dimension(params.packing_ks_polynomial_size),
            self.parameters().ciphertext_modulus(),
        );

        ShortintEngine::with_thread_local_mut(|engine| {
            par_generate_lwe_bootstrap_key(
                &private_compression_key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                &self.as_ref().key.glwe_secret_key,
                &mut bsk,
                self.parameters().glwe_noise_distribution(),
                &mut engine.encryption_generator,
            );
        });

        let blind_rotate_key = CudaBootstrappingKey::Classic(
            CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, streams),
        );

        let cuda_decompression_key = CudaDecompressionKey {
            blind_rotate_key,
            lwe_per_glwe: params.lwe_per_glwe,
            glwe_dimension: self.parameters().glwe_dimension(),
            polynomial_size: self.parameters().polynomial_size(),
            message_modulus: self.parameters().message_modulus(),
            carry_modulus: self.parameters().carry_modulus(),
            ciphertext_modulus: self.parameters().ciphertext_modulus(),
        };

        (cuda_compression_key, cuda_decompression_key)
    }
}
