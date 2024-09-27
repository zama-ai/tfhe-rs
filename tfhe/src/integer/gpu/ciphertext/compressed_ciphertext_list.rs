use crate::core_crypto::entities::packed_integers::PackedIntegers;
use crate::core_crypto::entities::GlweCiphertextList;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::core_crypto::prelude::{
    glwe_ciphertext_size, CiphertextCount, ContiguousEntityContainer, LweCiphertextCount,
};
use crate::integer::ciphertext::{CompressedCiphertextList, DataKind};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaSignedRadixCiphertext,
    CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey, CudaPackedGlweCiphertext,
};
use crate::shortint::ciphertext::CompressedCiphertextList as ShortintCompressedCiphertextList;
use crate::shortint::PBSOrder;
use itertools::Itertools;
use serde::{Deserializer, Serializer};

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
        }
    }
}
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
        let preceding_infos = self.info.get(..index).unwrap();
        let current_info = self.info.get(index).copied().unwrap();

        let start_block_index: usize = preceding_infos
            .iter()
            .copied()
            .map(DataKind::num_blocks)
            .sum();

        let end_block_index = start_block_index + current_info.num_blocks() - 1;

        Some((
            decomp_key.unpack(
                &self.packed_list,
                current_info,
                start_block_index,
                end_block_index,
                streams,
            ),
            current_info,
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
    /// ```rust
    ///  use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::{BooleanBlock, ClientKey, RadixCiphertext, SignedRadixCiphertext};
    /// use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
    /// use tfhe::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    ///
    ///     let private_compression_key =
    ///         cks.new_compression_private_key(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    ///
    ///     let streams = CudaStreams::new_multi_gpu();
    ///
    ///     let num_blocks = 32;
    ///     let (radix_cks, _) = gen_keys_radix_gpu(
    ///         PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    ///         num_blocks,
    ///         &streams,
    ///     );
    ///     let (compressed_compression_key, compressed_decompression_key) =
    ///         radix_cks.new_compressed_compression_decompression_keys(&private_compression_key);
    ///
    ///     let cuda_compression_key = compressed_compression_key.decompress_to_cuda(&streams);
    ///
    ///     let compression_key = compressed_compression_key.decompress();
    ///     let decompression_key = compressed_decompression_key.decompress();
    ///
    ///         let ct1 = radix_cks.encrypt(3_u32);
    ///         let ct2 = radix_cks.encrypt_signed(-2);
    ///         let ct3 = radix_cks.encrypt_bool(true);
    ///
    ///         /// Copy to GPU
    ///         let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    ///         let d_ct2 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct2, &streams);
    ///         let d_ct3 = CudaBooleanBlock::from_boolean_block(&ct3, &streams);
    ///
    ///         let cuda_compressed = CudaCompressedCiphertextListBuilder::new()
    ///             .push(d_ct1, &streams)
    ///             .push(d_ct2, &streams)
    ///             .push(d_ct3, &streams)
    ///             .build(&cuda_compression_key, &streams);
    ///
    ///         let reference_compressed = CompressedCiphertextListBuilder::new()
    ///             .push(ct1)
    ///             .push(ct2)
    ///             .push(ct3)
    ///             .build(&compression_key);
    ///
    ///         let converted_compressed = cuda_compressed.to_compressed_ciphertext_list(&streams);
    ///
    ///         let decompressed1: RadixCiphertext = converted_compressed
    ///             .get(0, &decompression_key)
    ///             .unwrap()
    ///             .unwrap();
    ///         let reference_decompressed1 = reference_compressed
    ///             .get(0, &decompression_key)
    ///             .unwrap()
    ///             .unwrap();
    ///         assert_eq!(decompressed1, reference_decompressed1);
    ///
    ///         let decompressed2: SignedRadixCiphertext = converted_compressed
    ///             .get(1, &decompression_key)
    ///             .unwrap()
    ///             .unwrap();
    ///         let reference_decompressed2 = reference_compressed
    ///             .get(1, &decompression_key)
    ///             .unwrap()
    ///             .unwrap();
    ///         assert_eq!(decompressed2, reference_decompressed2);
    ///
    ///         let decompressed3: BooleanBlock = converted_compressed
    ///             .get(2, &decompression_key)
    ///             .unwrap()
    ///             .unwrap();
    ///         let reference_decompressed3 = reference_compressed
    ///             .get(2, &decompression_key)
    ///             .unwrap()
    ///             .unwrap();
    ///         assert_eq!(decompressed3, reference_decompressed3);
    /// ```
    pub fn to_compressed_ciphertext_list(&self, streams: &CudaStreams) -> CompressedCiphertextList {
        let glwe_list = self
            .packed_list
            .glwe_ciphertext_list
            .to_glwe_ciphertext_list(streams);
        let ciphertext_modulus = self.packed_list.glwe_ciphertext_list.ciphertext_modulus();

        let message_modulus = self.packed_list.message_modulus;
        let carry_modulus = self.packed_list.carry_modulus;
        let lwe_per_glwe = self.packed_list.lwe_per_glwe;
        let storage_log_modulus = self.packed_list.storage_log_modulus;

        let initial_len = self.packed_list.initial_len;
        let number_bits_to_pack = initial_len * storage_log_modulus.0;
        let len = number_bits_to_pack.div_ceil(u64::BITS as usize);

        let modulus_switched_glwe_ciphertext_list = glwe_list
            .iter()
            .map(|x| {
                let glwe_dimension = x.glwe_size().to_glwe_dimension();
                let polynomial_size = x.polynomial_size();
                CompressedModulusSwitchedGlweCiphertext {
                    packed_integers: PackedIntegers {
                        packed_coeffs: x.into_container()[0..len].to_vec(),
                        log_modulus: storage_log_modulus,
                        initial_len,
                    },
                    glwe_dimension,
                    polynomial_size,
                    bodies_count: LweCiphertextCount(self.packed_list.bodies_count),
                    uncompressed_ciphertext_modulus: ciphertext_modulus,
                }
            })
            .collect_vec();

        let count = CiphertextCount(self.packed_list.bodies_count);
        let pbs_order = PBSOrder::KeyswitchBootstrap;
        let packed_list = ShortintCompressedCiphertextList {
            modulus_switched_glwe_ciphertext_list,
            ciphertext_modulus,
            message_modulus,
            carry_modulus,
            pbs_order,
            lwe_per_glwe,
            count,
        };

        CompressedCiphertextList {
            packed_list,
            info: self.info.clone(),
        }
    }
}

impl CompressedCiphertextList {
    /// ```rust
    ///    use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
    /// use tfhe::integer::ClientKey;
    /// use tfhe::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    ///
    ///     let private_compression_key =
    ///         cks.new_compression_private_key(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    ///
    ///     let streams = CudaStreams::new_multi_gpu();
    ///
    ///     let num_blocks = 32;
    ///     let (radix_cks, _) = gen_keys_radix_gpu(
    ///         PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    ///         num_blocks,
    ///         &streams,
    ///     );
    ///     let (compressed_compression_key, compressed_decompression_key) =
    ///         radix_cks.new_compressed_compression_decompression_keys(&private_compression_key);
    ///
    ///     let cuda_decompression_key =
    ///         compressed_decompression_key.decompress_to_cuda(
    ///                 radix_cks.parameters().glwe_dimension(),
    ///                 radix_cks.parameters().polynomial_size(),
    ///                 radix_cks.parameters().message_modulus(),
    ///                 radix_cks.parameters().carry_modulus(),
    ///                 radix_cks.parameters().ciphertext_modulus(),
    ///                 &streams);
    ///
    ///     let compression_key = compressed_compression_key.decompress();
    ///
    ///         let ct1 = radix_cks.encrypt(3_u32);
    ///         let ct2 = radix_cks.encrypt_signed(-2);
    ///         let ct3 = radix_cks.encrypt_bool(true);
    ///
    ///         let compressed = CompressedCiphertextListBuilder::new()
    ///             .push(ct1)
    ///             .push(ct2)
    ///             .push(ct3)
    ///             .build(&compression_key);
    ///
    ///         let cuda_compressed = compressed.to_cuda_compressed_ciphertext_list(&streams);
    ///
    ///         let d_decompressed1: CudaUnsignedRadixCiphertext =
    ///             cuda_compressed.get(0, &cuda_decompression_key, &streams).unwrap().unwrap();
    ///         let decompressed1 = d_decompressed1.to_radix_ciphertext(&streams);
    ///         let decrypted: u32 = radix_cks.decrypt(&decompressed1);
    ///         assert_eq!(decrypted, 3_u32);
    ///
    ///         let d_decompressed2: CudaSignedRadixCiphertext =
    ///             cuda_compressed.get(1, &cuda_decompression_key, &streams).unwrap().unwrap();
    ///         let decompressed2 = d_decompressed2.to_signed_radix_ciphertext(&streams);
    ///         let decrypted: i32 = radix_cks.decrypt_signed(&decompressed2);
    ///         assert_eq!(decrypted, -2);
    ///
    ///         let d_decompressed3: CudaBooleanBlock =
    ///             cuda_compressed.get(2, &cuda_decompression_key, &streams).unwrap().unwrap();
    ///         let decompressed3 = d_decompressed3.to_boolean_block(&streams);
    ///         let decrypted = radix_cks.decrypt_bool(&decompressed3);
    ///         assert!(decrypted);
    /// ```
    pub fn to_cuda_compressed_ciphertext_list(
        &self,
        streams: &CudaStreams,
    ) -> CudaCompressedCiphertextList {
        let lwe_per_glwe = self.packed_list.lwe_per_glwe;

        let modulus_switched_glwe_ciphertext_list =
            &self.packed_list.modulus_switched_glwe_ciphertext_list;

        let first_ct = modulus_switched_glwe_ciphertext_list.first().unwrap();
        let storage_log_modulus = first_ct.packed_integers.log_modulus;
        let initial_len = first_ct.packed_integers.initial_len;
        let bodies_count = first_ct.bodies_count.0;

        let message_modulus = self.packed_list.message_modulus;
        let carry_modulus = self.packed_list.carry_modulus;

        let mut data = modulus_switched_glwe_ciphertext_list
            .iter()
            .flat_map(|ct| ct.packed_integers.packed_coeffs.clone())
            .collect_vec();
        let glwe_ciphertext_size = glwe_ciphertext_size(
            first_ct.glwe_dimension.to_glwe_size(),
            first_ct.polynomial_size,
        );
        data.resize(
            self.packed_list.modulus_switched_glwe_ciphertext_list.len() * glwe_ciphertext_size,
            0,
        );
        let glwe_ciphertext_list = GlweCiphertextList::from_container(
            data.as_slice(),
            first_ct.glwe_dimension.to_glwe_size(),
            first_ct.polynomial_size,
            self.packed_list.ciphertext_modulus,
        );
        CudaCompressedCiphertextList {
            packed_list: CudaPackedGlweCiphertext {
                glwe_ciphertext_list: CudaGlweCiphertextList::from_glwe_ciphertext_list(
                    &glwe_ciphertext_list,
                    streams,
                ),
                message_modulus,
                carry_modulus,
                bodies_count,
                storage_log_modulus,
                lwe_per_glwe,
                initial_len,
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
    use crate::integer::gpu::gen_keys_radix_gpu;
    use crate::integer::ClientKey;
    use crate::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use rand::Rng;

    const NB_TESTS: usize = 10;
    const NB_OPERATOR_TESTS: usize = 10;

    #[test]
    fn test_gpu_ciphertext_compression() {
        let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

        let private_compression_key =
            cks.new_compression_private_key(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);

        let streams = CudaStreams::new_multi_gpu();

        let num_blocks = 32;
        let (radix_cks, _) = gen_keys_radix_gpu(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            num_blocks,
            &streams,
        );
        let (cuda_compression_key, cuda_decompression_key) =
            radix_cks.new_cuda_compression_decompression_keys(&private_compression_key, &streams);

        let mut rng = rand::thread_rng();

        let message_modulus: u128 = cks.parameters().message_modulus().0 as u128;

        for _ in 0..NB_TESTS {
            // Unsigned
            let modulus = message_modulus.pow(num_blocks as u32);
            for _ in 0..NB_OPERATOR_TESTS {
                let nb_messages = 1 + (rng.gen::<u64>() % 6);
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
                    builder.push(d_ct, &streams);
                }

                let cuda_compressed = builder.build(&cuda_compression_key, &streams);

                for (i, message) in messages.iter().enumerate() {
                    let d_decompressed: CudaUnsignedRadixCiphertext = cuda_compressed
                        .get(i, &cuda_decompression_key, &streams)
                        .unwrap()
                        .unwrap();
                    let decompressed = d_decompressed.to_radix_ciphertext(&streams);
                    let decrypted: u128 = radix_cks.decrypt(&decompressed);
                    assert_eq!(decrypted, *message);
                }
            }

            // Signed
            let modulus = message_modulus.pow((num_blocks - 1) as u32) as i128;
            for _ in 0..NB_OPERATOR_TESTS {
                let nb_messages = 1 + (rng.gen::<u64>() % 6);
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
                    builder.push(d_ct, &streams);
                }

                let cuda_compressed = builder.build(&cuda_compression_key, &streams);

                for (i, message) in messages.iter().enumerate() {
                    let d_decompressed: CudaSignedRadixCiphertext = cuda_compressed
                        .get(i, &cuda_decompression_key, &streams)
                        .unwrap()
                        .unwrap();
                    let decompressed = d_decompressed.to_signed_radix_ciphertext(&streams);
                    let decrypted: i128 = radix_cks.decrypt_signed(&decompressed);
                    assert_eq!(decrypted, *message);
                }
            }

            // Boolean
            for _ in 0..NB_OPERATOR_TESTS {
                let nb_messages = 1 + (rng.gen::<u64>() % 6);
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

                for d_ct in d_cts {
                    builder.push(d_ct, &streams);
                }

                let cuda_compressed = builder.build(&cuda_compression_key, &streams);

                for (i, message) in messages.iter().enumerate() {
                    let d_decompressed: CudaBooleanBlock = cuda_compressed
                        .get(i, &cuda_decompression_key, &streams)
                        .unwrap()
                        .unwrap();
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

                let nb_messages = 1 + (rng.gen::<u64>() % 6);
                let mut messages = vec![];
                for _ in 0..nb_messages {
                    let case_selector = rng.gen_range(0..3);
                    match case_selector {
                        0 => {
                            // Unsigned
                            let modulus = message_modulus.pow(num_blocks as u32);
                            let message = rng.gen::<u128>() % modulus;
                            let ct = radix_cks.encrypt(message);
                            let d_ct =
                                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
                            builder.push(d_ct, &streams);
                            messages.push(MessageType::Unsigned(message));
                        }
                        1 => {
                            // Signed
                            let modulus = message_modulus.pow((num_blocks - 1) as u32) as i128;
                            let message = rng.gen::<i128>() % modulus;
                            let ct = radix_cks.encrypt_signed(message);
                            let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(
                                &ct, &streams,
                            );
                            builder.push(d_ct, &streams);
                            messages.push(MessageType::Signed(message));
                        }
                        _ => {
                            // Boolean
                            let message = rng.gen::<i64>() % 2 != 0;
                            let ct = radix_cks.encrypt_bool(message);
                            let d_ct = CudaBooleanBlock::from_boolean_block(&ct, &streams);
                            builder.push(d_ct, &streams);
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
                            let decompressed = d_decompressed.to_signed_radix_ciphertext(&streams);
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
