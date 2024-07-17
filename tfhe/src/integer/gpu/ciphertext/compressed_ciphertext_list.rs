use crate::core_crypto::gpu::CudaStreams;
use crate::integer::ciphertext::DataKind;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey, CudaPackedGlweCiphertext,
};

pub struct CudaCompressedCiphertextList {
    pub(crate) packed_list: CudaPackedGlweCiphertext,
    info: Vec<DataKind>,
}
impl CudaCompressedCiphertextList {
    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.info.len() == 0
    }

    pub fn get(
        &self,
        index: usize,
        decomp_key: &CudaDecompressionKey,
        streams: &CudaStreams,
    ) -> CudaRadixCiphertext {
        let preceding_infos = self.info.get(..index).unwrap();
        let current_info = self.info.get(index).copied().unwrap();

        let start_block_index: usize = preceding_infos
            .iter()
            .copied()
            .map(DataKind::num_blocks)
            .sum();

        let end_block_index = start_block_index + current_info.num_blocks() - 1;

        decomp_key.unpack(
            &self.packed_list,
            start_block_index,
            end_block_index,
            streams,
        )
    }
}

pub trait CudaCompressible {
    fn compress_into(
        self,
        messages: &mut Vec<CudaRadixCiphertext>,
        streams: &CudaStreams,
    ) -> DataKind;
}

impl CudaCompressible for CudaSignedRadixCiphertext {
    fn compress_into(
        self,
        messages: &mut Vec<CudaRadixCiphertext>,
        streams: &CudaStreams,
    ) -> DataKind {
        let x = self.ciphertext.duplicate(streams);
        let num_blocks = x.d_blocks.lwe_ciphertext_count().0;

        messages.push(x);
        DataKind::Signed(num_blocks)
    }
}

impl CudaCompressible for CudaBooleanBlock {
    fn compress_into(
        self,
        messages: &mut Vec<CudaRadixCiphertext>,
        streams: &CudaStreams,
    ) -> DataKind {
        let x = self.0.ciphertext.duplicate(streams);

        messages.push(x);
        DataKind::Boolean
    }
}
impl CudaCompressible for CudaUnsignedRadixCiphertext {
    fn compress_into(
        self,
        messages: &mut Vec<CudaRadixCiphertext>,
        streams: &CudaStreams,
    ) -> DataKind {
        let x = self.ciphertext.duplicate(streams);
        let num_blocks = x.d_blocks.lwe_ciphertext_count().0;

        messages.push(x);
        DataKind::Unsigned(num_blocks)
    }
}

pub struct CudaCompressedCiphertextListBuilder {
    pub(crate) ciphertexts: Vec<CudaRadixCiphertext>,
    pub(crate) info: Vec<DataKind>,
}

impl CudaCompressedCiphertextListBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ciphertexts: vec![],
            info: vec![],
        }
    }

    pub fn push<T: CudaCompressible>(&mut self, data: T, streams: &CudaStreams) -> &mut Self {
        let kind = data.compress_into(&mut self.ciphertexts, streams);

        if kind.num_blocks() != 0 {
            self.info.push(kind);
        }

        self
    }

    pub fn build(
        &self,
        comp_key: &CudaCompressionKey,
        streams: &CudaStreams,
    ) -> CudaCompressedCiphertextList {
        let packed_list = comp_key.compress_ciphertexts_into_list(&self.ciphertexts, streams);

        CudaCompressedCiphertextList {
            packed_list,
            info: self.info.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::gpu::gen_keys_radix_gpu;
    use crate::integer::ClientKey;
    use crate::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    #[test]
    fn test_gpu_ciphertext_compression() {
        let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

        let private_compression_key =
            cks.new_compression_private_key(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

        let streams = CudaStreams::new_multi_gpu();

        let num_blocks = 4;
        let (radix_cks, _) = gen_keys_radix_gpu(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            num_blocks,
            &streams,
        );

        let (cuda_compression_key, cuda_decompression_key) =
            radix_cks.new_cuda_compression_decompression_keys(&private_compression_key, &streams);

        let ct1 = radix_cks.encrypt(3_u32);
        let ct2 = radix_cks.encrypt(2_u32);
        let ct3 = radix_cks.encrypt_signed(-2);
        let ct4 = cks.encrypt_bool(true);

        // Copy to GPU
        let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
        let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
        let d_ct3 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct3, &streams);
        let d_ct4 = CudaBooleanBlock::from_boolean_block(&ct4, &streams);

        let cuda_compressed = CudaCompressedCiphertextListBuilder::new()
            .push(d_ct1, &streams)
            .push(d_ct2, &streams)
            .push(d_ct3, &streams)
            .push(d_ct4, &streams)
            .build(&cuda_compression_key, &streams);

        let d_decompressed1 = CudaUnsignedRadixCiphertext {
            ciphertext: cuda_compressed.get(0, &cuda_decompression_key, &streams),
        };

        let decompressed1 = d_decompressed1.to_radix_ciphertext(&streams);
        let decrypted: u32 = radix_cks.decrypt(&decompressed1);

        assert_eq!(decrypted, 3_u32);
        let d_decompressed2 = CudaUnsignedRadixCiphertext {
            ciphertext: cuda_compressed.get(1, &cuda_decompression_key, &streams),
        };

        let decompressed2 = d_decompressed2.to_radix_ciphertext(&streams);
        let decrypted: u32 = radix_cks.decrypt(&decompressed2);

        assert_eq!(decrypted, 2_u32);
        let d_decompressed3 = CudaSignedRadixCiphertext {
            ciphertext: cuda_compressed.get(2, &cuda_decompression_key, &streams),
        };

        let decompressed3 = d_decompressed3.to_signed_radix_ciphertext(&streams);
        let decrypted: i32 = radix_cks.decrypt_signed(&decompressed3);

        assert_eq!(decrypted, -2);
        let d_decompressed4 = CudaBooleanBlock::from_cuda_radix_ciphertext(cuda_compressed.get(
            3,
            &cuda_decompression_key,
            &streams,
        ));

        let decompressed4 = d_decompressed4.to_boolean_block(&streams);
        let decrypted = radix_cks.decrypt_bool(&decompressed4);

        assert!(decrypted);
    }
}
