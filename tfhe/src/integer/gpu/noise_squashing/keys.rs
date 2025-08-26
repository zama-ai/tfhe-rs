use crate::core_crypto::gpu::CudaStreams;

use crate::core_crypto::prelude::LweCiphertextCount;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::squashed_noise::{
    CudaSquashedNoiseBooleanBlock, CudaSquashedNoiseRadixCiphertext,
    CudaSquashedNoiseSignedRadixCiphertext,
};
use crate::integer::gpu::ciphertext::{CudaRadixCiphertext, CudaSignedRadixCiphertext};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::CudaServerKey;
use crate::shortint::parameters::CoreCiphertextModulus;

use crate::shortint::{CarryModulus, MessageModulus};

pub struct CudaNoiseSquashingKey {
    pub bootstrapping_key: CudaBootstrappingKey<u128>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl CudaNoiseSquashingKey {
    pub fn checked_squash_ciphertext_noise(
        &self,
        ciphertext: &CudaRadixCiphertext,
        src_server_key: &CudaServerKey,
        streams: &CudaStreams,
    ) -> crate::Result<CudaSquashedNoiseRadixCiphertext> {
        for block in ciphertext.info.blocks.iter() {
            if src_server_key
                .max_noise_level
                .validate(block.noise_level)
                .is_err()
            {
                return Err(crate::error!(
                        "squash_ciphertext_noise requires the input Ciphertext to have at most {:?} noise \
                        got {:?}.",
                        src_server_key.max_noise_level,
                        block.noise_level
                    ));
            }
            if block.message_modulus != self.message_modulus {
                return Err(crate::error!(
                    "Mismatched MessageModulus between Ciphertext {:?} and NoiseSquashingKey {:?}.",
                    block.message_modulus,
                    self.message_modulus,
                ));
            }
            if block.carry_modulus != self.carry_modulus {
                return Err(crate::error!(
                    "Mismatched CarryModulus between Ciphertext {:?} and NoiseSquashingKey {:?}.",
                    block.carry_modulus,
                    self.carry_modulus,
                ));
            }
        }

        Ok(self.unchecked_squash_ciphertext_noise(ciphertext, src_server_key, streams))
    }

    pub fn unchecked_squash_ciphertext_noise(
        &self,
        ciphertext: &CudaRadixCiphertext,
        src_server_key: &CudaServerKey,
        streams: &CudaStreams,
    ) -> CudaSquashedNoiseRadixCiphertext {
        let original_block_count = ciphertext.d_blocks.lwe_ciphertext_count().0;
        let packed_size = ciphertext.d_blocks.lwe_ciphertext_count().0.div_ceil(2);
        let mut squashed_output = CudaSquashedNoiseRadixCiphertext::new_zero(
            self.bootstrapping_key.output_lwe_dimension().to_lwe_size(),
            LweCiphertextCount(packed_size),
            self.output_ciphertext_modulus,
            self.message_modulus,
            self.carry_modulus,
            original_block_count,
            streams,
        );

        src_server_key.apply_noise_squashing(&mut squashed_output, ciphertext, self, streams);

        let mut new_block_info = Vec::<CudaBlockInfo>::with_capacity(packed_size);
        for (i, block) in squashed_output.info.blocks.iter().enumerate() {
            let block_info = squashed_output.info.blocks[i];
            new_block_info.push(CudaBlockInfo {
                degree: block.degree,
                message_modulus: block_info.message_modulus,
                carry_modulus: block_info.carry_modulus,
                atomic_pattern: block_info.atomic_pattern,
                noise_level: block_info.noise_level,
            });
        }
        CudaSquashedNoiseRadixCiphertext {
            packed_d_blocks: squashed_output.packed_d_blocks,
            info: CudaRadixCiphertextInfo {
                blocks: new_block_info,
            },
            original_block_count,
        }
    }

    pub fn squash_radix_ciphertext_noise(
        &self,
        src_server_key: &CudaServerKey,
        ciphertext: &CudaRadixCiphertext,
        streams: &CudaStreams,
    ) -> crate::Result<CudaSquashedNoiseRadixCiphertext> {
        self.checked_squash_ciphertext_noise(ciphertext, src_server_key, streams)
    }

    pub fn squash_signed_radix_ciphertext_noise(
        &self,
        src_server_key: &CudaServerKey,
        ciphertext: &CudaSignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> crate::Result<CudaSquashedNoiseSignedRadixCiphertext> {
        let squashed_output =
            self.checked_squash_ciphertext_noise(&ciphertext.ciphertext, src_server_key, streams)?;
        Ok(CudaSquashedNoiseSignedRadixCiphertext {
            ciphertext: squashed_output,
        })
    }

    pub fn squash_boolean_block_noise(
        &self,
        src_server_key: &CudaServerKey,
        ciphertext: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) -> crate::Result<CudaSquashedNoiseBooleanBlock> {
        let squashed_output = self.checked_squash_ciphertext_noise(
            &ciphertext.as_ref().ciphertext,
            src_server_key,
            streams,
        )?;
        Ok(CudaSquashedNoiseBooleanBlock {
            ciphertext: squashed_output,
        })
    }
}
