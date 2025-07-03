use crate::core_crypto::gpu::CudaStreams;
use crate::integer::ciphertext::DataKind;
use crate::integer::gpu::ciphertext::squashed_noise::{
    CudaSquashedNoiseBooleanBlock, CudaSquashedNoiseRadixCiphertext,
    CudaSquashedNoiseSignedRadixCiphertext,
};
use crate::integer::gpu::list_compression::server_keys::{
    CudaNoiseSquashingCompressionKey, CudaPackedGlweCiphertextList,
};
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

pub trait CudaSquashedNoiseExpandable{
    fn from_expanded_blocks(
        blocks: CudaSquashedNoiseRadixCiphertext,
        kind: DataKind,
    ) -> crate::Result<Self>;
}

impl CudaCompressedSquashedNoiseCiphertextList {
    pub fn builder() -> CudaCompressedSquashedNoiseCiphertextListBuilder {
        CudaCompressedSquashedNoiseCiphertextListBuilder::new()
    }

    #[allow(clippy::unnecessary_wraps)]
    fn blocks_of(
        &self,
        index: usize,
        decomp_key: &CudaNoiseSquashingDecompressionKey,
        streams: &CudaStreams,
    ) -> Option<(CudaSquashedNoiseRadixCiphertext, DataKind)> {
        let preceding_infos = self.info.get(..index)?;
        let current_info = self.info.get(index).copied()?;
        let message_modulus = self.packed_list.message_modulus()?;

        let start_block_index: usize = preceding_infos
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(message_modulus))
            .sum();

        let end_block_index = start_block_index + current_info.num_blocks(message_modulus) - 1;

        Some((
            decomp_key
                .unpack(
                    &self.packed_list,
                    current_info,
                    start_block_index,
                    end_block_index,
                    streams,
                )
                .unwrap(),
            current_info,
        ))
    }

        pub fn get<T>(
        &self,
        index: usize,
        decomp_key: &CudaNoiseSquashingDecompressionKey,
        streams: &CudaStreams,
    ) -> crate::Result<Option<T>>
    where
        T: CudaSquashedNoiseExpandable,
    {
        self.blocks_of(index, decomp_key, streams)
            .map(|(blocks, kind)| T::from_expanded_blocks(blocks, kind))
            .transpose()
    }
}

#[cfg(test)]
mod test {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::ciphertext::NoiseSquashingCompressionPrivateKey;
    use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    use crate::integer::gpu::ciphertext::squashed_noise::{CudaSquashedNoiseBooleanBlock, CudaSquashedNoiseRadixCiphertext, CudaSquashedNoiseSignedRadixCiphertext};
    use crate::integer::gpu::ciphertext::{
        CudaCompressedSquashedNoiseCiphertextList, CudaSignedRadixCiphertext,
        CudaUnsignedRadixCiphertext,
    };
    use crate::integer::gpu::gen_keys_radix_gpu;
    use crate::integer::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
    use crate::shortint::parameters::test_params::{
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use rand::Rng;
    use crate::integer::gpu::list_compression::server_keys::CudaNoiseSquashingCompressionKey;

    #[test]
    fn test_cuda_compressed_noise_squashed_ciphertext_list() {
        let param = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_parameters =
            TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        const NUM_BLOCKS: usize = 16;
        let streams = CudaStreams::new_multi_gpu();

        let (radix_cks, sks) = gen_keys_radix_gpu(param, NUM_BLOCKS, &streams);
        let cks = radix_cks.as_ref();

        let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_parameters);
        let noise_squashing_key = NoiseSquashingKey::new(&cks, &noise_squashing_private_key);

        let compressed_noise_squashing_compression_key =
            cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);

        let cuda_noise_squashing_key =
            compressed_noise_squashing_compression_key.decompress_to_cuda(&streams);

        let noise_squashing_compression_private_key = NoiseSquashingCompressionPrivateKey::new(
            TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );
        let noise_squashing_compression_key = noise_squashing_private_key
            .new_noise_squashing_compression_key(&noise_squashing_compression_private_key);
        let cuda_noise_squashing_compression_key = CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(&noise_squashing_compression_key, &streams);
        let mut rng = rand::thread_rng();

        let clear_a = rng.gen_range(0..=i32::MAX);
        let clear_b = rng.gen_range(i32::MIN..=-1);
        let clear_c = rng.gen::<u32>();
        let clear_d = rng.gen::<bool>();

        let ct_a = cks.encrypt_signed_radix(clear_a, NUM_BLOCKS);
        let ct_b = cks.encrypt_signed_radix(clear_b, NUM_BLOCKS);
        let ct_c = cks.encrypt_radix(clear_c, NUM_BLOCKS);
        let ct_d = cks.encrypt_bool(clear_d);

        let d_ct_a = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct_a, &streams);
        let d_ct_b = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct_b, &streams);
        let d_ct_c = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_c, &streams);
        let d_ct_d = CudaBooleanBlock::from_boolean_block(&ct_d, &streams);

        let ns_ct_a = cuda_noise_squashing_key
            .squash_signed_radix_ciphertext_noise(&sks, &d_ct_a, &streams)
            .unwrap();
        let ns_ct_b = cuda_noise_squashing_key
            .squash_signed_radix_ciphertext_noise(&sks, &d_ct_b, &streams)
            .unwrap();
        let ns_ct_c = cuda_noise_squashing_key
            .squash_radix_ciphertext_noise(&sks, &d_ct_c.ciphertext, &streams)
            .unwrap();
        let ns_ct_d = cuda_noise_squashing_key
            .squash_boolean_block_noise(&sks, &d_ct_d, &streams)
            .unwrap();

        let list = CudaCompressedSquashedNoiseCiphertextList::builder()
            .push(ns_ct_a, &streams)
            .push(ns_ct_b, &streams)
            .push(ns_ct_c, &streams)
            .push(ns_ct_d, &streams)
            .build(&cuda_noise_squashing_compression_key, &streams);

        let d_ns_ct_a: CudaSquashedNoiseSignedRadixCiphertext = list.get(0).unwrap().unwrap();
        let d_ns_ct_b: CudaSquashedNoiseSignedRadixCiphertext = list.get(1).unwrap().unwrap();
        let d_ns_ct_c: CudaSquashedNoiseRadixCiphertext = list.get(2).unwrap().unwrap();
        let d_ns_ct_d: CudaSquashedNoiseBooleanBlock = list.get(3).unwrap().unwrap();

        let ns_ct_a = d_ns_ct_a.to_squashed_noise_signed_radix_ciphertext(&streams);
        let ns_ct_b = d_ns_ct_b.to_squashed_noise_signed_radix_ciphertext(&streams);
        let ns_ct_c = d_ns_ct_c.to_squashed_noise_radix_ciphertext(&streams);
        let ns_ct_d = d_ns_ct_d.to_squashed_noise_boolean_block(&streams);

        let decryption_key = noise_squashing_compression_private_key.private_key_view();

        let d_clear_a: i32 = decryption_key.decrypt_signed_radix(&ns_ct_a).unwrap();
        let d_clear_b: i32 = decryption_key.decrypt_signed_radix(&ns_ct_b).unwrap();
        let d_clear_c: u32 = decryption_key.decrypt_radix(&ns_ct_c).unwrap();
        let d_clear_d = decryption_key.decrypt_bool(&ns_ct_d).unwrap();

        assert_eq!(clear_a, d_clear_a);
        assert_eq!(clear_b, d_clear_b);
        assert_eq!(clear_c, d_clear_c);
        assert_eq!(clear_d, d_clear_d);
    }
}
