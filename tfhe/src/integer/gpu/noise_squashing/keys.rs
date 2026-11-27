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
use crate::integer::noise_squashing::check_blocks_can_be_packed_and_squashed;
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
        self.check_squash_input(ciphertext)?;

        // The CUDA backend packs blocks by pairs before the noise squashing PBS, the checks on
        // carries and noise must be done on the packed chunks, same as on the CPU
        check_blocks_can_be_packed_and_squashed(
            ciphertext
                .info
                .blocks
                .iter()
                .map(|block| (block.degree, block.noise_level)),
            self.message_modulus,
            self.carry_modulus,
            src_server_key.max_noise_level,
        )?;

        Ok(self.unchecked_squash_ciphertext_noise(ciphertext, src_server_key, streams))
    }

    /// Squashes each block alone, with the checks of checked_squash_ciphertext_noise. Packing
    /// blocks by pairs needs clean carries, a one time pad mask may use its carry space. As on
    /// CPU, each output block keeps the degree of its input block.
    pub(crate) fn checked_squash_blocks_noise(
        &self,
        ciphertext: &CudaRadixCiphertext,
        src_server_key: &CudaServerKey,
        streams: &CudaStreams,
    ) -> crate::Result<CudaSquashedNoiseRadixCiphertext> {
        self.check_squash_input(ciphertext)?;

        // No packing here, so the noise is checked block by block
        for block in ciphertext.info.blocks.iter() {
            if src_server_key
                .max_noise_level
                .validate(block.noise_level)
                .is_err()
            {
                return Err(crate::error!(
                    "squash_blocks_noise requires the input Ciphertext to have at most {:?} noise \
                    got {:?}.",
                    src_server_key.max_noise_level,
                    block.noise_level
                ));
            }
        }

        let block_count = ciphertext.d_blocks.lwe_ciphertext_count().0;
        let mut squashed_output = CudaSquashedNoiseRadixCiphertext::new_zero(
            self.bootstrapping_key.output_lwe_dimension().to_lwe_size(),
            LweCiphertextCount(block_count),
            self.output_ciphertext_modulus,
            self.message_modulus,
            self.carry_modulus,
            block_count,
            streams,
        );
        if block_count == 0 {
            return Ok(squashed_output);
        }

        // As many output blocks as input blocks, so the backend does not pack
        src_server_key.apply_noise_squashing(&mut squashed_output, ciphertext, self, streams);

        // The backend sets the degree of its identity LUT, the largest value of the block
        for (output, input) in squashed_output
            .info
            .blocks
            .iter_mut()
            .zip(&ciphertext.info.blocks)
        {
            output.degree = input.degree;
        }

        Ok(squashed_output)
    }

    /// Checks shared by the packed and the block by block squash, the noise is checked by each
    /// of them as it depends on the packing
    fn check_squash_input(&self, ciphertext: &CudaRadixCiphertext) -> crate::Result<()> {
        for block in ciphertext.info.blocks.iter() {
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

        Ok(())
    }

    pub(crate) fn unchecked_squash_ciphertext_noise(
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
        let blocks = &ciphertext.as_ref().ciphertext.info.blocks;
        if blocks.len() != 1 {
            return Err(crate::error!(
                "A CudaBooleanBlock must contain exactly 1 block, got {}",
                blocks.len()
            ));
        }
        // The boolean block is checked as a single, unpacked block by the radix checks: its carry
        // must be empty as the squashed boolean is decrypted as `value != 0` over the whole
        // message and carry space
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

#[cfg(test)]
mod tests {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    use crate::integer::gpu::CudaServerKey;
    use crate::integer::noise_squashing::NoiseSquashingPrivateKey;
    use crate::integer::{ClientKey, CompressedServerKey, IntegerCiphertext, ServerKey};
    use crate::shortint::ciphertext::NoiseLevel;
    use crate::shortint::parameters::test_params::{
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };

    /// The checked GPU noise squashing must reject the same inputs as the CPU one
    #[test]
    fn test_cuda_noise_squashing_rejects_unpackable_inputs() {
        let param = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_parameters =
            TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let streams = CudaStreams::new_multi_gpu();

        let cks = ClientKey::new(param);
        let compressed_sks = CompressedServerKey::new_radix_compressed_server_key(&cks);
        let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_sks, &streams);
        let shortint_sks = ServerKey::new_radix_server_key(&cks).into_raw_parts();
        let max_noise_level = shortint_sks.max_noise_level;

        let nspk = NoiseSquashingPrivateKey::new(noise_squashing_parameters);
        let cuda_nsk = cks
            .new_compressed_noise_squashing_key(&nspk)
            .decompress_to_cuda(&streams);

        // Unclean pair, previously packed to 1 + 4 * 4 = 17 >= 16 (padding bit)
        {
            let mut ct = cks.encrypt_signed_radix(1i8, 4);
            shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[1], 4);
            let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
            assert!(cuda_nsk
                .squash_signed_radix_ciphertext_noise(&cuda_sks, &d_ct, &streams)
                .is_err());
        }
        // Unclean last block of an odd block count radix
        {
            let mut ct = cks.encrypt_signed_radix(17i8, 3);
            shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[2], 16);
            let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
            assert!(cuda_nsk
                .squash_signed_radix_ciphertext_noise(&cuda_sks, &d_ct, &streams)
                .is_err());
        }
        // Clean carries but packed noise above the max noise level, including blocks individually
        // at the max noise level (previously packed to 5 + 4 * 5 = 25)
        for (low_noise, high_noise) in [
            (NoiseLevel(5), NoiseLevel(5)),
            (NoiseLevel(1), NoiseLevel(2)),
            (NoiseLevel(5), NoiseLevel(1)),
        ] {
            let mut ct = cks.encrypt_radix(5u8, 2);
            ct.blocks_mut()[0].set_noise_level(low_noise, max_noise_level);
            ct.blocks_mut()[1].set_noise_level(high_noise, max_noise_level);
            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
            assert!(cuda_nsk
                .squash_radix_ciphertext_noise(&cuda_sks, &d_ct.ciphertext, &streams)
                .is_err());
        }
        // BooleanBlock with a non empty carry
        {
            let mut b = cks.encrypt_bool(false);
            shortint_sks.unchecked_scalar_add_assign(&mut b.0, 4);
            let d_b = CudaBooleanBlock::from_boolean_block(&b, &streams);
            assert!(cuda_nsk
                .squash_boolean_block_noise(&cuda_sks, &d_b, &streams)
                .is_err());
        }
        // BooleanBlock with degree 2 but an empty carry: accepted, both decryptions agree
        {
            let mut b = cks.encrypt_bool(true);
            shortint_sks.unchecked_scalar_add_assign(&mut b.0, 1);
            assert!(b.0.degree.get() > 1 && b.0.carry_is_empty());
            assert!(cks.decrypt_bool(&b));
            let d_b = CudaBooleanBlock::from_boolean_block(&b, &streams);
            let squashed = cuda_nsk
                .squash_boolean_block_noise(&cuda_sks, &d_b, &streams)
                .unwrap()
                .to_squashed_noise_boolean_block(&streams);
            assert!(nspk.decrypt_bool(&squashed).unwrap());
        }

        // Sanity check: clean inputs are accepted and decrypt correctly
        // -1 is representable with a single 2 bits block
        for num_blocks in [1, 3, 4] {
            let ct = cks.encrypt_signed_radix(-1i8, num_blocks);
            let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
            let squashed = cuda_nsk
                .squash_signed_radix_ciphertext_noise(&cuda_sks, &d_ct, &streams)
                .unwrap()
                .to_squashed_noise_signed_radix_ciphertext(&streams);
            let d: i8 = nspk.decrypt_signed_radix(&squashed).unwrap();
            assert_eq!(d, -1);
        }
        for val in [false, true] {
            let b = cks.encrypt_bool(val);
            let d_b = CudaBooleanBlock::from_boolean_block(&b, &streams);
            let squashed = cuda_nsk
                .squash_boolean_block_noise(&cuda_sks, &d_b, &streams)
                .unwrap()
                .to_squashed_noise_boolean_block(&streams);
            assert_eq!(nspk.decrypt_bool(&squashed).unwrap(), val);
        }
    }
}
