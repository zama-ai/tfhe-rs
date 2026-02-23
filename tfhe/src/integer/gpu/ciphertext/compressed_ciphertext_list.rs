use crate::core_crypto::entities::packed_integers::PackedIntegers;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::core_crypto::prelude::LweCiphertextCount;
use crate::integer::ciphertext::{CompressedCiphertextList, DataKind};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaSignedRadixCiphertext,
    CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey, CudaPackedGlweCiphertextList,
    CudaPackedGlweCiphertextListMeta,
};
use crate::shortint::ciphertext::{
    CompressedCiphertextList as ShortintCompressedCiphertextList, CompressedCiphertextListMeta,
};
use crate::shortint::parameters::AtomicPatternKind;
use crate::shortint::PBSOrder;
use itertools::Itertools;
use serde::{Deserializer, Serializer};
use std::num::NonZeroUsize;

pub trait CudaExpandable: Sized {
    fn from_expanded_blocks(blocks: CudaRadixCiphertext, kind: DataKind) -> crate::Result<Self>;
}

impl<T> CudaExpandable for T
where
    T: CudaIntegerRadixCiphertext,
{
    fn from_expanded_blocks(blocks: CudaRadixCiphertext, kind: DataKind) -> crate::Result<Self> {
        match (kind, T::IS_SIGNED) {
            (DataKind::Unsigned(_), false) | (DataKind::Signed(_), true) => Ok(T::from(blocks)),
            (DataKind::Boolean, _) => {
                let signed_or_unsigned_str = if T::IS_SIGNED { "signed" } else { "unsigned" };
                Err(crate::Error::new(format!(
                    "Tried to expand a {signed_or_unsigned_str} radix while boolean is stored"
                )))
            }
            (DataKind::Unsigned(_), true) => Err(crate::Error::new(
                "Tried to expand a signed radix while an unsigned radix is stored".to_string(),
            )),
            (DataKind::Signed(_), false) => Err(crate::Error::new(
                "Tried to expand an unsigned radix while a signed radix is stored".to_string(),
            )),
            (DataKind::String { .. }, signed) => {
                let signedness = if signed { "signed" } else { "unsigned" };
                Err(crate::error!(
                    "Tried to expand a {signedness} radix while a string is stored"
                ))
            }
        }
    }
}

impl CudaExpandable for CudaBooleanBlock {
    fn from_expanded_blocks(blocks: CudaRadixCiphertext, kind: DataKind) -> crate::Result<Self> {
        match kind {
            DataKind::Unsigned(_) => Err(crate::Error::new(
                "Tried to expand a boolean block while an unsigned radix was stored".to_string(),
            )),
            DataKind::Signed(_) => Err(crate::Error::new(
                "Tried to expand a boolean block while a signed radix was stored".to_string(),
            )),
            DataKind::Boolean => Ok(Self::from_cuda_radix_ciphertext(blocks)),
            DataKind::String { .. } => Err(crate::Error::new(
                "Tried to expand a boolean block while a string  radix was stored".to_string(),
            )),
        }
    }
}
pub struct CudaCompressedCiphertextList {
    pub(crate) packed_list: CudaPackedGlweCiphertextList<u64>,
    pub(crate) info: Vec<DataKind>,
}

impl CudaCompressedCiphertextList {
    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        &self.packed_list.data.gpu_indexes
    }
    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.info.len() == 0
    }

    pub fn get_kind_of(&self, index: usize) -> Option<DataKind> {
        self.info.get(index).copied()
    }

    #[allow(clippy::unnecessary_wraps)]
    fn blocks_of(
        &self,
        index: usize,
        decomp_key: &CudaDecompressionKey,
        streams: &CudaStreams,
    ) -> Option<(CudaRadixCiphertext, DataKind)> {
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

    fn get_blocks_of_size_on_gpu(
        &self,
        index: usize,
        decomp_key: &CudaDecompressionKey,
        streams: &CudaStreams,
    ) -> Option<u64> {
        let preceding_infos = self.info.get(..index)?;
        let current_info = self.info.get(index).copied()?;
        let message_modulus = self.packed_list.message_modulus()?;

        let start_block_index: usize = preceding_infos
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(message_modulus))
            .sum();

        let end_block_index = start_block_index + current_info.num_blocks(message_modulus) - 1;

        Some(decomp_key.get_gpu_list_unpack_size_on_gpu(
            &self.packed_list,
            start_block_index,
            end_block_index,
            streams,
        ))
    }

    pub fn get<T>(
        &self,
        index: usize,
        decomp_key: &CudaDecompressionKey,
        streams: &CudaStreams,
    ) -> crate::Result<Option<T>>
    where
        T: CudaExpandable,
    {
        self.blocks_of(index, decomp_key, streams)
            .map(|(blocks, kind)| T::from_expanded_blocks(blocks, kind))
            .transpose()
    }

    pub fn get_decompression_size_on_gpu(
        &self,
        index: usize,
        decomp_key: &CudaDecompressionKey,
        streams: &CudaStreams,
    ) -> Option<u64> {
        self.get_blocks_of_size_on_gpu(index, decomp_key, streams)
    }

    /// ```rust
    ///  use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
    /// use tfhe::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    /// };
    ///
    /// let block_params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// let compression_params = COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// let num_blocks = 32;
    /// let streams = CudaStreams::new_multi_gpu();
    ///
    /// let (radix_cks, _) = gen_keys_radix_gpu(block_params,
    ///     num_blocks,
    ///     &streams,
    /// );
    /// let cks = radix_cks.as_ref();
    ///
    /// let private_compression_key =
    /// cks.new_compression_private_key(compression_params);
    ///
    /// let (cuda_compression_key, cuda_decompression_key) =
    /// radix_cks.new_cuda_compression_decompression_keys(&private_compression_key, &streams);
    ///
    /// let private_compression_key =
    ///     cks.new_compression_private_key(compression_params);
    ///
    /// let (compressed_compression_key, compressed_decompression_key) =
    ///     radix_cks.new_compressed_compression_decompression_keys(&private_compression_key);
    ///
    /// let cuda_compression_key = compressed_compression_key.decompress_to_cuda(&streams);
    ///
    /// let compression_key = compressed_compression_key.decompress();
    /// let decompression_key = compressed_decompression_key.decompress();
    ///
    /// let ct1 = radix_cks.encrypt(3_u32);
    /// let ct2 = radix_cks.encrypt_signed(-2);
    /// let ct3 = radix_cks.encrypt_bool(true);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct2, &streams);
    /// let d_ct3 = CudaBooleanBlock::from_boolean_block(&ct3, &streams);
    ///
    /// let cuda_compressed = CudaCompressedCiphertextListBuilder::new()
    ///     .push(d_ct1, &streams)
    ///     .push(d_ct2, &streams)
    ///     .push(d_ct3, &streams)
    ///     .build(&cuda_compression_key, &streams);
    ///
    /// let converted_compressed = cuda_compressed.to_compressed_ciphertext_list(&streams);
    /// ```
    pub fn to_compressed_ciphertext_list(&self, streams: &CudaStreams) -> CompressedCiphertextList {
        let Some(gpu_meta) = self.packed_list.meta.as_ref() else {
            // If there is no metadata, the list is empty
            let packed_list = ShortintCompressedCiphertextList {
                modulus_switched_glwe_ciphertext_list: Vec::new(),
                meta: None,
            };

            return CompressedCiphertextList {
                packed_list,
                info: Vec::new(),
            };
        };

        let ciphertext_modulus = gpu_meta.ciphertext_modulus;
        let message_modulus = gpu_meta.message_modulus;
        let carry_modulus = gpu_meta.carry_modulus;
        let lwe_per_glwe = gpu_meta.lwe_per_glwe;
        let storage_log_modulus = gpu_meta.storage_log_modulus;
        let glwe_dimension = gpu_meta.glwe_dimension;
        let polynomial_size = gpu_meta.polynomial_size;
        let mut modulus_switched_glwe_ciphertext_list =
            Vec::with_capacity(self.packed_list.glwe_ciphertext_count().0);

        let flat_cpu_data = unsafe {
            let mut v = vec![0u64; self.packed_list.data.len()];
            self.packed_list.data.copy_to_cpu_async(&mut v, streams, 0);
            streams.synchronize();
            v
        };

        let mut num_bodies_left = gpu_meta.total_lwe_bodies_count;
        let mut chunk_start = 0;
        while num_bodies_left != 0 {
            let bodies_count = LweCiphertextCount(num_bodies_left.min(lwe_per_glwe.0));
            let initial_len = (glwe_dimension.0 * polynomial_size.0) + bodies_count.0;
            let number_bits_to_pack = initial_len * storage_log_modulus.0;
            let len = number_bits_to_pack.div_ceil(u64::BITS as usize);
            let chunk_end = chunk_start + len;
            modulus_switched_glwe_ciphertext_list.push(
                CompressedModulusSwitchedGlweCiphertext::from_raw_parts(
                    PackedIntegers::from_raw_parts(
                        flat_cpu_data[chunk_start..chunk_end].to_vec(),
                        storage_log_modulus,
                        initial_len,
                    ),
                    glwe_dimension,
                    polynomial_size,
                    bodies_count,
                    ciphertext_modulus,
                ),
            );
            num_bodies_left = num_bodies_left.saturating_sub(lwe_per_glwe.0);
            chunk_start = chunk_end;
        }

        let atomic_pattern = AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap);
        let meta = Some(CompressedCiphertextListMeta {
            ciphertext_modulus,
            message_modulus,
            carry_modulus,
            atomic_pattern,
            lwe_per_glwe,
        });
        let packed_list = ShortintCompressedCiphertextList {
            modulus_switched_glwe_ciphertext_list,
            meta,
        };

        CompressedCiphertextList {
            packed_list,
            info: self.info.clone(),
        }
    }

    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            packed_list: self.packed_list.duplicate(streams),
            info: self.info.clone(),
        }
    }
}

impl CompressedCiphertextList {
    ///```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::{
    ///     COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    /// };
    ///
    /// let block_params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// let compression_params =
    ///     COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// let num_blocks = 32;
    /// let streams = CudaStreams::new_multi_gpu();
    ///
    /// let (radix_cks, _) = gen_keys_radix_gpu(block_params, num_blocks, &streams);
    /// let cks = radix_cks.as_ref();
    ///
    /// let private_compression_key = cks.new_compression_private_key(compression_params);
    ///
    /// let (compressed_compression_key, compressed_decompression_key) =
    ///     radix_cks.new_compressed_compression_decompression_keys(&private_compression_key);
    ///
    /// let cuda_decompression_key = compressed_decompression_key.decompress_to_cuda(
    ///     radix_cks.parameters().glwe_dimension(),
    ///     radix_cks.parameters().polynomial_size(),
    ///     radix_cks.parameters().message_modulus(),
    ///     radix_cks.parameters().carry_modulus(),
    ///     radix_cks.parameters().ciphertext_modulus(),
    ///     &streams,
    /// );
    ///
    /// let compression_key = compressed_compression_key.decompress();
    ///
    /// let ct1 = radix_cks.encrypt(3_u32);
    /// let ct2 = radix_cks.encrypt_signed(-2);
    /// let ct3 = radix_cks.encrypt_bool(true);
    ///
    /// let compressed = CompressedCiphertextListBuilder::new()
    ///     .push(ct1)
    ///     .push(ct2)
    ///     .push(ct3)
    ///     .build(&compression_key);
    ///
    /// let cuda_compressed = compressed.to_cuda_compressed_ciphertext_list(&streams);
    /// let recovered_cuda_compressed = cuda_compressed.to_compressed_ciphertext_list(&streams);
    ///
    /// assert_eq!(recovered_cuda_compressed, compressed);
    ///
    /// let d_decompressed1: CudaUnsignedRadixCiphertext = cuda_compressed
    ///     .get(0, &cuda_decompression_key, &streams)
    ///     .unwrap()
    ///     .unwrap();
    /// let decompressed1 = d_decompressed1.to_radix_ciphertext(&streams);
    /// let decrypted: u32 = radix_cks.decrypt(&decompressed1);
    /// assert_eq!(decrypted, 3_u32);
    ///
    /// let d_decompressed2: CudaSignedRadixCiphertext = cuda_compressed
    ///     .get(1, &cuda_decompression_key, &streams)
    ///     .unwrap()
    ///     .unwrap();
    /// let decompressed2 = d_decompressed2.to_signed_radix_ciphertext(&streams);
    /// let decrypted: i32 = radix_cks.decrypt_signed(&decompressed2);
    /// assert_eq!(decrypted, -2);
    ///
    /// let d_decompressed3: CudaBooleanBlock = cuda_compressed
    ///     .get(2, &cuda_decompression_key, &streams)
    ///     .unwrap()
    ///     .unwrap();
    /// let decompressed3 = d_decompressed3.to_boolean_block(&streams);
    /// let decrypted = radix_cks.decrypt_bool(&decompressed3);
    /// assert!(decrypted);
    /// ```
    pub fn to_cuda_compressed_ciphertext_list(
        &self,
        streams: &CudaStreams,
    ) -> CudaCompressedCiphertextList {
        let modulus_switched_glwe_ciphertext_list =
            &self.packed_list.modulus_switched_glwe_ciphertext_list;

        let flat_cpu_data = modulus_switched_glwe_ciphertext_list
            .iter()
            .flat_map(|ct| ct.packed_integers().packed_coeffs().to_vec())
            .collect_vec();

        let flat_gpu_data = unsafe {
            let v = CudaVec::from_cpu_async(flat_cpu_data.as_slice(), streams, 0);
            streams.synchronize();
            v
        };

        let initial_len = modulus_switched_glwe_ciphertext_list
            .iter()
            .map(|glwe| glwe.packed_integers().initial_len())
            .sum();

        let meta = self.packed_list.meta.as_ref().and_then(|cpu_meta| {
            let lwe_per_glwe = cpu_meta.lwe_per_glwe;
            let message_modulus = cpu_meta.message_modulus;
            let carry_modulus = cpu_meta.carry_modulus;

            modulus_switched_glwe_ciphertext_list
                .first()
                .map(|first_ct| CudaPackedGlweCiphertextListMeta {
                    glwe_dimension: first_ct.glwe_dimension(),
                    polynomial_size: first_ct.polynomial_size(),
                    message_modulus,
                    carry_modulus,
                    ciphertext_modulus: cpu_meta.ciphertext_modulus,
                    storage_log_modulus: first_ct.packed_integers().log_modulus(),
                    lwe_per_glwe,
                    total_lwe_bodies_count: self.packed_list.len(),
                    initial_len,
                })
        });

        CudaCompressedCiphertextList {
            packed_list: CudaPackedGlweCiphertextList {
                data: flat_gpu_data,
                meta,
            },
            info: self.info.clone(),
        }
    }
}

pub trait CudaCompressible {
    fn compress_into(
        self,
        messages: &mut Vec<CudaRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Option<DataKind>;
}

impl CudaCompressible for CudaSignedRadixCiphertext {
    fn compress_into(
        self,
        messages: &mut Vec<CudaRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Option<DataKind> {
        let x = self.ciphertext.duplicate(streams);
        let num_blocks = x.d_blocks.lwe_ciphertext_count().0;

        let num_blocks = NonZeroUsize::new(num_blocks);
        if num_blocks.is_some() {
            messages.push(x)
        }
        num_blocks.map(DataKind::Signed)
    }
}

impl CudaCompressible for CudaBooleanBlock {
    fn compress_into(
        self,
        messages: &mut Vec<CudaRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Option<DataKind> {
        let x = self.0.ciphertext.duplicate(streams);

        messages.push(x);
        Some(DataKind::Boolean)
    }
}
impl CudaCompressible for CudaUnsignedRadixCiphertext {
    fn compress_into(
        self,
        messages: &mut Vec<CudaRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Option<DataKind> {
        let x = self.ciphertext.duplicate(streams);
        let num_blocks = x.d_blocks.lwe_ciphertext_count().0;

        let num_blocks = NonZeroUsize::new(num_blocks);
        if num_blocks.is_some() {
            messages.push(x)
        }
        num_blocks.map(DataKind::Unsigned)
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
        if let Some(kind) = data.compress_into(&mut self.ciphertexts, streams) {
            self.info.push(kind);
        }
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>, streams: &CudaStreams) -> &mut Self
    where
        T: CudaCompressible,
    {
        for value in values {
            self.push(value, streams);
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

impl Clone for CudaCompressedCiphertextList {
    fn clone(&self) -> Self {
        Self {
            packed_list: self.packed_list.clone(),
            info: self.info.clone(),
        }
    }
}

impl serde::Serialize for CudaCompressedCiphertextList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let streams = CudaStreams::new_multi_gpu();
        let cpu_res = self.to_compressed_ciphertext_list(&streams);
        cpu_res.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for CudaCompressedCiphertextList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let cpu_compressed = CompressedCiphertextList::deserialize(deserializer)?;
        let streams = CudaStreams::new_multi_gpu();

        Ok(cpu_compressed.to_cuda_compressed_ciphertext_list(&streams))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::ciphertext::CompressedCiphertextListBuilder;
    use crate::integer::gpu::gen_keys_radix_gpu;
    use crate::integer::{ClientKey, RadixCiphertext, RadixClientKey};
    use crate::shortint::parameters::*;
    use crate::shortint::ShortintParameterSet;
    use rand::Rng;

    const NB_TESTS: usize = 10;
    const NB_OPERATOR_TESTS: usize = 10;

    #[test]
    fn test_cpu_to_gpu_compressed_ciphertext_list() {
        const NUM_BLOCKS: usize = 32;
        let streams = CudaStreams::new_multi_gpu();

        let params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let comp_params = COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let cks = ClientKey::new(params);

        let private_compression_key = cks.new_compression_private_key(comp_params);
        let (compressed_compression_key, compressed_decompression_key) =
            cks.new_compressed_compression_decompression_keys(&private_compression_key);
        let cuda_compression_key = compressed_compression_key.decompress_to_cuda(&streams);
        let cuda_decompression_key = compressed_decompression_key.decompress_to_cuda(
            cks.parameters().glwe_dimension(),
            cks.parameters().polynomial_size(),
            cks.parameters().message_modulus(),
            cks.parameters().carry_modulus(),
            cks.parameters().ciphertext_modulus(),
            &streams,
        );
        let cpu_compression_key = compressed_compression_key.decompress();
        let cpu_decompression_key = compressed_decompression_key.decompress();

        let radix_cks = RadixClientKey::from((cks, NUM_BLOCKS));

        // How many uints of NUM_BLOCKS we have to push in the list to ensure it
        // internally has more than one packed GLWE
        let max_nb_messages: usize = 1 + 2 * comp_params.lwe_per_glwe().0 / NUM_BLOCKS;

        let mut rng = rand::rng();
        let message_modulus: u128 = radix_cks.parameters().message_modulus().0 as u128;
        let modulus = message_modulus.pow(NUM_BLOCKS as u32);
        let messages = (0..max_nb_messages)
            .map(|_| rng.gen::<u128>() % modulus)
            .collect::<Vec<_>>();

        let cpu_cts = messages
            .iter()
            .map(|message| radix_cks.encrypt(*message))
            .collect_vec();

        let cuda_cts = cpu_cts
            .iter()
            .map(|ct| CudaUnsignedRadixCiphertext::from_radix_ciphertext(ct, &streams))
            .collect_vec();

        let cpu_compressed_list = {
            let mut builder = CompressedCiphertextListBuilder::new();
            for d_ct in cpu_cts {
                builder.push(d_ct);
            }
            builder.build(&cpu_compression_key)
        };

        let cuda_compressed_list = {
            let mut builder = CudaCompressedCiphertextListBuilder::new();
            for d_ct in cuda_cts {
                builder.push(d_ct, &streams);
            }
            builder.build(&cuda_compression_key, &streams)
        };

        // Test Decompression on Gpu
        {
            // Roundtrip Gpu->Cpu->Gpu
            let cuda_compressed_list = cuda_compressed_list
                .to_compressed_ciphertext_list(&streams)
                .to_cuda_compressed_ciphertext_list(&streams);

            let cuda_compressed_list_2 =
                cpu_compressed_list.to_cuda_compressed_ciphertext_list(&streams);

            for (i, message) in messages.iter().enumerate() {
                let d_decompressed: CudaUnsignedRadixCiphertext = cuda_compressed_list
                    .get(i, &cuda_decompression_key, &streams)
                    .unwrap()
                    .unwrap();
                let decompressed = d_decompressed.to_radix_ciphertext(&streams);
                let decrypted: u128 = radix_cks.decrypt(&decompressed);
                assert_eq!(
                    decrypted, *message,
                    "Invalid decompression for cuda list that roundtripped Cuda->Cpu->Cuda"
                );

                let d_decompressed: CudaUnsignedRadixCiphertext = cuda_compressed_list_2
                    .get(i, &cuda_decompression_key, &streams)
                    .unwrap()
                    .unwrap();
                let decompressed = d_decompressed.to_radix_ciphertext(&streams);
                let decrypted: u128 = radix_cks.decrypt(&decompressed);
                assert_eq!(
                    decrypted, *message,
                    "Invalid decompression for cuda list that originated from Cpu"
                );
            }
        }

        // Test Decompression on CPU (to test conversions)
        {
            let expected_flat_len = cpu_compressed_list.packed_list.flat_len();

            // Roundtrip Cpu->Gpu->Cpu
            let cpu_compressed_list = cpu_compressed_list
                .to_cuda_compressed_ciphertext_list(&streams)
                .to_compressed_ciphertext_list(&streams);
            assert_eq!(
                cpu_compressed_list.packed_list.flat_len(),
                expected_flat_len,
                "Invalid flat len after Cpu->Gpu->Cpu"
            );

            let cpu_compressed_list_2 =
                cuda_compressed_list.to_compressed_ciphertext_list(&streams);
            assert_eq!(
                cpu_compressed_list_2.packed_list.flat_len(),
                expected_flat_len,
                "Invalid flat len after Gpu->Cpu"
            );

            for (i, message) in messages.iter().enumerate() {
                let decompressed: RadixCiphertext = cpu_compressed_list
                    .get(i, &cpu_decompression_key)
                    .unwrap()
                    .unwrap();
                let decrypted: u128 = radix_cks.decrypt(&decompressed);
                assert_eq!(
                    decrypted, *message,
                    "Invalid decompression for cpu list that roundtripped Cpu->Gpu->Cpu"
                );

                let decompressed: RadixCiphertext = cpu_compressed_list_2
                    .get(i, &cpu_decompression_key)
                    .unwrap()
                    .unwrap();
                let decrypted: u128 = radix_cks.decrypt(&decompressed);
                assert_eq!(
                    decrypted, *message,
                    "Invalid decompression for cpu list that originated from Gpu"
                );
            }
        }
    }

    #[test]
    fn test_gpu_ciphertext_compression() {
        const NUM_BLOCKS: usize = 32;
        let streams = CudaStreams::new_multi_gpu();

        for (params, comp_params) in [
            (
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            (
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        ] {
            let (radix_cks, sks) =
                gen_keys_radix_gpu::<ShortintParameterSet>(params, NUM_BLOCKS, &streams);
            let cks = radix_cks.as_ref();

            let private_compression_key = cks.new_compression_private_key(comp_params);

            let (cuda_compression_key, cuda_decompression_key) = radix_cks
                .new_cuda_compression_decompression_keys(&private_compression_key, &streams);

            let max_nb_messages: usize = 2 * comp_params.lwe_per_glwe().0 / NUM_BLOCKS;

            let mut rng = rand::rng();

            let message_modulus: u128 = cks.parameters().message_modulus().0 as u128;

            for _ in 0..NB_TESTS {
                // Unsigned
                let modulus = message_modulus.pow(NUM_BLOCKS as u32);
                for _ in 0..NB_OPERATOR_TESTS {
                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.gen::<u128>() % modulus)
                        .collect::<Vec<_>>();

                    let d_cts = messages
                        .iter()
                        .map(|message| {
                            let ct = radix_cks.encrypt(*message);
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams)
                        })
                        .collect_vec();

                    let mut builder = CudaCompressedCiphertextListBuilder::new();

                    for d_ct in d_cts {
                        let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                        builder.push(d_and_ct, &streams);
                    }

                    let cuda_compressed = builder.build(&cuda_compression_key, &streams);

                    for (i, message) in messages.iter().enumerate() {
                        let d_decompressed: CudaUnsignedRadixCiphertext = cuda_compressed
                            .get(i, &cuda_decompression_key, &streams)
                            .unwrap()
                            .unwrap();
                        assert!(
                            d_decompressed.block_carries_are_empty(),
                            "Expected carries to be empty"
                        );
                        let decompressed = d_decompressed.to_radix_ciphertext(&streams);
                        let decrypted: u128 = radix_cks.decrypt(&decompressed);
                        assert_eq!(decrypted, *message);
                    }
                }

                // Signed
                let modulus = message_modulus.pow((NUM_BLOCKS - 1) as u32) as i128;
                for _ in 0..NB_OPERATOR_TESTS {
                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.gen::<i128>() % modulus)
                        .collect::<Vec<_>>();

                    let d_cts = messages
                        .iter()
                        .map(|message| {
                            let ct = radix_cks.encrypt_signed(*message);
                            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams)
                        })
                        .collect_vec();

                    let mut builder = CudaCompressedCiphertextListBuilder::new();

                    for d_ct in d_cts {
                        let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                        builder.push(d_and_ct, &streams);
                    }

                    let cuda_compressed = builder.build(&cuda_compression_key, &streams);

                    for (i, message) in messages.iter().enumerate() {
                        let d_decompressed: CudaSignedRadixCiphertext = cuda_compressed
                            .get(i, &cuda_decompression_key, &streams)
                            .unwrap()
                            .unwrap();
                        assert!(
                            d_decompressed.block_carries_are_empty(),
                            "Expected carries to be empty"
                        );
                        let decompressed = d_decompressed.to_signed_radix_ciphertext(&streams);
                        let decrypted: i128 = radix_cks.decrypt_signed(&decompressed);
                        assert_eq!(decrypted, *message);
                    }
                }

                // Boolean
                for _ in 0..NB_OPERATOR_TESTS {
                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.gen::<i64>() % 2 != 0)
                        .collect::<Vec<_>>();

                    let d_cts = messages
                        .iter()
                        .map(|message| {
                            let ct = radix_cks.encrypt_bool(*message);
                            CudaBooleanBlock::from_boolean_block(&ct, &streams)
                        })
                        .collect_vec();

                    let mut builder = CudaCompressedCiphertextListBuilder::new();

                    for d_boolean_ct in d_cts {
                        let d_ct = d_boolean_ct.0;
                        let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                        let d_and_boolean_ct =
                            CudaBooleanBlock::from_cuda_radix_ciphertext(d_and_ct.ciphertext);
                        builder.push(d_and_boolean_ct, &streams);
                    }

                    let cuda_compressed = builder.build(&cuda_compression_key, &streams);

                    for (i, message) in messages.iter().enumerate() {
                        let d_decompressed: CudaBooleanBlock = cuda_compressed
                            .get(i, &cuda_decompression_key, &streams)
                            .unwrap()
                            .unwrap();
                        assert!(
                            d_decompressed.0.holds_boolean_value(),
                            "Expected boolean block to have the degree of a boolean value"
                        );
                        let decompressed = d_decompressed.to_boolean_block(&streams);
                        let decrypted = radix_cks.decrypt_bool(&decompressed);
                        assert_eq!(decrypted, *message);
                    }
                }

                // Hybrid
                enum MessageType {
                    Unsigned(u128),
                    Signed(i128),
                    Boolean(bool),
                }
                for _ in 0..NB_OPERATOR_TESTS {
                    let mut builder = CudaCompressedCiphertextListBuilder::new();

                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let mut messages = vec![];
                    for _ in 0..nb_messages {
                        let case_selector = rng.gen_range(0..3);
                        match case_selector {
                            0 => {
                                // Unsigned
                                let modulus = message_modulus.pow(NUM_BLOCKS as u32);
                                let message = rng.gen::<u128>() % modulus;
                                let ct = radix_cks.encrypt(message);
                                let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                    &ct, &streams,
                                );
                                let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                                builder.push(d_and_ct, &streams);
                                messages.push(MessageType::Unsigned(message));
                            }
                            1 => {
                                // Signed
                                let modulus = message_modulus.pow((NUM_BLOCKS - 1) as u32) as i128;
                                let message = rng.gen::<i128>() % modulus;
                                let ct = radix_cks.encrypt_signed(message);
                                let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(
                                    &ct, &streams,
                                );
                                let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                                builder.push(d_and_ct, &streams);
                                messages.push(MessageType::Signed(message));
                            }
                            _ => {
                                // Boolean
                                let message = rng.gen::<i64>() % 2 != 0;
                                let ct = radix_cks.encrypt_bool(message);
                                let d_boolean_ct =
                                    CudaBooleanBlock::from_boolean_block(&ct, &streams);
                                let d_ct = d_boolean_ct.0;
                                let d_and_ct = sks.bitand(&d_ct, &d_ct, &streams);
                                let d_and_boolean_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(
                                    d_and_ct.ciphertext,
                                );
                                builder.push(d_and_boolean_ct, &streams);
                                messages.push(MessageType::Boolean(message));
                            }
                        }
                    }

                    let cuda_compressed = builder.build(&cuda_compression_key, &streams);

                    for (i, val) in messages.iter().enumerate() {
                        match val {
                            MessageType::Unsigned(message) => {
                                let d_decompressed: CudaUnsignedRadixCiphertext = cuda_compressed
                                    .get(i, &cuda_decompression_key, &streams)
                                    .unwrap()
                                    .unwrap();
                                let decompressed = d_decompressed.to_radix_ciphertext(&streams);
                                let decrypted: u128 = radix_cks.decrypt(&decompressed);
                                assert_eq!(decrypted, *message);
                            }
                            MessageType::Signed(message) => {
                                let d_decompressed: CudaSignedRadixCiphertext = cuda_compressed
                                    .get(i, &cuda_decompression_key, &streams)
                                    .unwrap()
                                    .unwrap();
                                let decompressed =
                                    d_decompressed.to_signed_radix_ciphertext(&streams);
                                let decrypted: i128 = radix_cks.decrypt_signed(&decompressed);
                                assert_eq!(decrypted, *message);
                            }
                            MessageType::Boolean(message) => {
                                let d_decompressed: CudaBooleanBlock = cuda_compressed
                                    .get(i, &cuda_decompression_key, &streams)
                                    .unwrap()
                                    .unwrap();
                                let decompressed = d_decompressed.to_boolean_block(&streams);
                                let decrypted = radix_cks.decrypt_bool(&decompressed);
                                assert_eq!(decrypted, *message);
                            }
                        }
                    }
                }
            }
        }
    }
}
