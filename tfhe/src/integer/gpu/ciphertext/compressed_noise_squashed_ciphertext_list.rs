use crate::core_crypto::gpu::CudaStreams;
use crate::integer::ciphertext::DataKind;
use crate::integer::gpu::ciphertext::squashed_noise::{CudaSquashedNoiseBooleanBlock, CudaSquashedNoiseRadixCiphertext, CudaSquashedNoiseSignedRadixCiphertext};
use crate::integer::gpu::list_compression::server_keys::{CudaNoiseSquashingCompressionKey, CudaPackedGlweCiphertextList};
use crate::named::Named;

pub struct CudaCompressedSquashedNoiseCiphertextListBuilder {
    pub(crate) ciphertexts: Vec<CudaSquashedNoiseRadixCiphertext>,
    pub(crate) info: Vec<DataKind>,
}

pub struct CudaCompressedSquashedNoiseCiphertextList {
    pub(crate) packed_list: CudaPackedGlweCiphertextList<u128>,
    pub(crate) info: Vec<DataKind>,
}

impl Named for CudaCompressedSquashedNoiseCiphertextList {
    const NAME: &'static str = "integer::gpu::CudaCompressedSquashedNoiseCiphertextList";
}

pub trait SquashedCudaCompressible {
    fn compress_into(
        self,
        messages: &mut Vec<CudaSquashedNoiseRadixCiphertext>,
        streams: &CudaStreams,
    ) -> DataKind;
}

impl SquashedCudaCompressible for CudaSquashedNoiseRadixCiphertext {
    fn compress_into(
        self,
        messages: &mut Vec<CudaSquashedNoiseRadixCiphertext>,
        streams: &CudaStreams,
    ) -> DataKind {
        let x = self.duplicate(streams);
        let num_blocks = x.original_block_count;

        messages.push(x);
        DataKind::Unsigned(num_blocks)
    }
}

impl SquashedCudaCompressible for CudaSquashedNoiseSignedRadixCiphertext {
    fn compress_into(
        self,
        messages: &mut Vec<CudaSquashedNoiseRadixCiphertext>,
        streams: &CudaStreams,
    ) -> DataKind {
        let x = self.duplicate(streams);
        let num_blocks = x.ciphertext.original_block_count;

        messages.push(x.ciphertext);
        DataKind::Unsigned(num_blocks)
    }
}

impl SquashedCudaCompressible for CudaSquashedNoiseBooleanBlock {
    fn compress_into(
        self,
        messages: &mut Vec<CudaSquashedNoiseRadixCiphertext>,
        streams: &CudaStreams,
    ) -> DataKind {
        let x = self.duplicate(streams);
        let num_blocks = x.ciphertext.original_block_count;

        messages.push(x.ciphertext);
        DataKind::Unsigned(num_blocks)
    }
}

impl CudaCompressedSquashedNoiseCiphertextListBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ciphertexts: vec![],
            info: vec![],
        }
    }

    pub fn push<T: SquashedCudaCompressible>(
        &mut self,
        data: T,
        streams: &CudaStreams,
    ) -> &mut Self {
        let kind = data.compress_into(&mut self.ciphertexts, streams);
        let message_modulus = self.ciphertexts.last().unwrap().info.blocks[0].message_modulus;

        if kind.num_blocks(message_modulus) != 0 {
            self.info.push(kind);
        }

        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>, streams: &CudaStreams) -> &mut Self
    where
        T: SquashedCudaCompressible,
    {
        for value in values {
            self.push(value, streams);
        }
        self
    }


    pub fn build(
        &self,
        comp_key: &CudaNoiseSquashingCompressionKey,
        streams: &CudaStreams,
    ) -> CudaCompressedSquashedNoiseCiphertextList {
        let packed_list = comp_key.compress_ciphertexts_into_list(&self.ciphertexts, streams);
        CudaCompressedSquashedNoiseCiphertextList {
            packed_list,
            info: self.info.clone(),
        }
    }

}

impl CudaCompressedSquashedNoiseCiphertextList {
    pub fn builder() -> CudaCompressedSquashedNoiseCiphertextListBuilder{
        CudaCompressedSquashedNoiseCiphertextListBuilder::new()
    }
}