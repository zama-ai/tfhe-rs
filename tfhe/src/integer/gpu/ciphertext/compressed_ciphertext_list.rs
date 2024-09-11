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
    CudaRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey, CudaPackedGlweCiphertext,
};
use crate::shortint::ciphertext::CompressedCiphertextList as ShortintCompressedCiphertextList;
use crate::shortint::PBSOrder;
use itertools::Itertools;

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
            current_info,
            start_block_index,
            end_block_index,
            streams,
        )
    }

    /// ```rust
    ///  use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::{BooleanBlock, ClientKey, RadixCiphertext, SignedRadixCiphertext};
    /// use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
    /// use tfhe::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);
    ///
    ///     let private_compression_key =
    ///         cks.new_compression_private_key(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);
    ///
    ///     let streams = CudaStreams::new_multi_gpu();
    ///
    ///     let num_blocks = 32;
    ///     let (radix_cks, _) = gen_keys_radix_gpu(
    ///         PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
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
    /// use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);
    ///
    ///     let private_compression_key =
    ///         cks.new_compression_private_key(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);
    ///
    ///     let streams = CudaStreams::new_multi_gpu();
    ///
    ///     let num_blocks = 32;
    ///     let (radix_cks, _) = gen_keys_radix_gpu(
    ///         PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    ///         num_blocks,
    ///         &streams,
    ///     );
    ///     let (compressed_compression_key, compressed_decompression_key) =
    ///         radix_cks.new_compressed_compression_decompression_keys(&private_compression_key);
    ///
    ///     let cuda_decompression_key =
    ///         compressed_decompression_key.decompress_to_cuda(radix_cks.parameters(), &streams);
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
    ///         let d_decompressed1 = CudaUnsignedRadixCiphertext {
    ///             ciphertext: cuda_compressed.get(0, &cuda_decompression_key, &streams),
    ///         };
    ///         let decompressed1 = d_decompressed1.to_radix_ciphertext(&streams);
    ///         let decrypted: u32 = radix_cks.decrypt(&decompressed1);
    ///         assert_eq!(decrypted, 3_u32);
    ///
    ///         let d_decompressed2 = CudaSignedRadixCiphertext {
    ///             ciphertext: cuda_compressed.get(1, &cuda_decompression_key, &streams),
    ///         };
    ///         let decompressed2 = d_decompressed2.to_signed_radix_ciphertext(&streams);
    ///         let decrypted: i32 = radix_cks.decrypt_signed(&decompressed2);
    ///         assert_eq!(decrypted, -2);
    ///
    ///         let d_decompressed3 = CudaBooleanBlock::from_cuda_radix_ciphertext(
    ///             cuda_compressed.get(2, &cuda_decompression_key, &streams),
    ///         );
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
    use crate::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

    const NB_TESTS: usize = 10;
    #[test]
    fn test_gpu_ciphertext_compression() {
        let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);

        let private_compression_key =
            cks.new_compression_private_key(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64);

        let streams = CudaStreams::new_multi_gpu();

        let num_blocks = 32;
        let (radix_cks, _) = gen_keys_radix_gpu(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            num_blocks,
            &streams,
        );
        let (cuda_compression_key, cuda_decompression_key) =
            radix_cks.new_cuda_compression_decompression_keys(&private_compression_key, &streams);

        for _ in 0..NB_TESTS {
            let ct1 = radix_cks.encrypt(3_u32);
            let ct2 = radix_cks.encrypt_signed(-2);
            let ct3 = radix_cks.encrypt_bool(true);

            // Copy to GPU
            let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
            let d_ct2 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct2, &streams);
            let d_ct3 = CudaBooleanBlock::from_boolean_block(&ct3, &streams);

            let cuda_compressed = CudaCompressedCiphertextListBuilder::new()
                .push(d_ct1, &streams)
                .push(d_ct2, &streams)
                .push(d_ct3, &streams)
                .build(&cuda_compression_key, &streams);

            let d_decompressed1 = CudaUnsignedRadixCiphertext {
                ciphertext: cuda_compressed.get(0, &cuda_decompression_key, &streams),
            };
            let decompressed1 = d_decompressed1.to_radix_ciphertext(&streams);
            let decrypted: u32 = radix_cks.decrypt(&decompressed1);
            assert_eq!(decrypted, 3_u32);

            let d_decompressed2 = CudaSignedRadixCiphertext {
                ciphertext: cuda_compressed.get(1, &cuda_decompression_key, &streams),
            };
            let decompressed2 = d_decompressed2.to_signed_radix_ciphertext(&streams);
            let decrypted: i32 = radix_cks.decrypt_signed(&decompressed2);
            assert_eq!(decrypted, -2);

            let d_decompressed3 = CudaBooleanBlock::from_cuda_radix_ciphertext(
                cuda_compressed.get(2, &cuda_decompression_key, &streams),
            );
            let decompressed3 = d_decompressed3.to_boolean_block(&streams);
            let decrypted = radix_cks.decrypt_bool(&decompressed3);
            assert!(decrypted);
        }
    }
}
