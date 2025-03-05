use crate::core_crypto::gpu::entities::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{
    glwe_ciphertext_size, glwe_mask_size, CiphertextModulus, CiphertextModulusLog,
    GlweCiphertextCount, LweCiphertextCount, PolynomialSize,
};
use crate::integer::ciphertext::DataKind;
use crate::integer::compression_keys::CompressionKey;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    compress_integer_radix_async, cuda_memcpy_async_gpu_to_gpu, decompress_integer_radix_async,
};
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::prelude::GlweDimension;
use crate::shortint::{CarryModulus, MessageModulus, PBSOrder};
use itertools::Itertools;

#[derive(Debug)]
pub struct CudaCompressionKey {
    pub packing_key_switching_key: CudaLwePackingKeyswitchKey<u64>,
    pub lwe_per_glwe: LweCiphertextCount,
    pub storage_log_modulus: CiphertextModulusLog,
}

pub struct CudaDecompressionKey {
    pub blind_rotate_key: CudaBootstrappingKey,
    pub lwe_per_glwe: LweCiphertextCount,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

pub struct CudaPackedGlweCiphertextList {
    // The compressed GLWE list's elements
    pub data: CudaVec<u64>,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus<u64>,
    pub storage_log_modulus: CiphertextModulusLog,
    pub lwe_per_glwe: LweCiphertextCount,
    // Number of lwe bodies that are compressed in this list
    pub bodies_count: usize,
    // Number of elements (u64) the uncompressed GLWE list had
    // keep in mind the last GLWE may not be full
    pub initial_len: usize,
}

impl CudaPackedGlweCiphertextList {
    pub fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        let uncompressed_glwe_size =
            glwe_ciphertext_size(self.glwe_dimension.to_glwe_size(), self.polynomial_size);

        GlweCiphertextCount(self.initial_len.div_ceil(uncompressed_glwe_size))
    }

    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            data: self.data.duplicate(streams),
            glwe_dimension: self.glwe_dimension,
            polynomial_size: self.polynomial_size,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            ciphertext_modulus: self.ciphertext_modulus,
            bodies_count: self.bodies_count,
            storage_log_modulus: self.storage_log_modulus,
            lwe_per_glwe: self.lwe_per_glwe,
            initial_len: self.initial_len,
        }
    }
}

impl Clone for CudaPackedGlweCiphertextList {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            glwe_dimension: self.glwe_dimension,
            polynomial_size: self.polynomial_size,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            ciphertext_modulus: self.ciphertext_modulus,
            bodies_count: self.bodies_count,
            storage_log_modulus: self.storage_log_modulus,
            lwe_per_glwe: self.lwe_per_glwe,
            initial_len: self.initial_len,
        }
    }
}

impl CudaCompressionKey {
    pub fn from_compression_key(compression_key: &CompressionKey, streams: &CudaStreams) -> Self {
        Self {
            packing_key_switching_key: CudaLwePackingKeyswitchKey::from_lwe_packing_keyswitch_key(
                &compression_key.key.packing_key_switching_key,
                streams,
            ),
            lwe_per_glwe: compression_key.key.lwe_per_glwe,
            storage_log_modulus: compression_key.key.storage_log_modulus,
        }
    }

    unsafe fn flatten_async(
        vec_ciphertexts: &[CudaRadixCiphertext],
        streams: &CudaStreams,
    ) -> CudaLweCiphertextList<u64> {
        let first_ct = &vec_ciphertexts.first().unwrap().d_blocks;

        // We assume all ciphertexts will have the same lwe dimension
        let lwe_dimension = first_ct.lwe_dimension();
        let ciphertext_modulus = first_ct.ciphertext_modulus();

        // Compute total number of lwe ciphertexts we will be handling
        let total_num_blocks: usize = vec_ciphertexts
            .iter()
            .map(|x| x.d_blocks.lwe_ciphertext_count().0)
            .sum();

        let lwe_ciphertext_count = LweCiphertextCount(total_num_blocks);

        let mut d_vec = CudaVec::new_async(
            lwe_dimension.to_lwe_size().0 * lwe_ciphertext_count.0,
            streams,
            0,
        );
        let mut offset: usize = 0;
        for ciphertext in vec_ciphertexts {
            let dest_ptr = d_vec
                .as_mut_c_ptr(0)
                .add(offset * std::mem::size_of::<u64>());
            let size = ciphertext.d_blocks.0.d_vec.len * std::mem::size_of::<u64>();
            cuda_memcpy_async_gpu_to_gpu(
                dest_ptr,
                ciphertext.d_blocks.0.d_vec.as_c_ptr(0),
                size as u64,
                streams.ptr[0],
                streams.gpu_indexes[0].get(),
            );

            offset += ciphertext.d_blocks.0.d_vec.len;
        }

        CudaLweCiphertextList::from_cuda_vec(d_vec, lwe_ciphertext_count, ciphertext_modulus)
    }

    pub fn compress_ciphertexts_into_list(
        &self,
        ciphertexts: &[CudaRadixCiphertext],
        streams: &CudaStreams,
    ) -> CudaPackedGlweCiphertextList {
        let lwe_pksk = &self.packing_key_switching_key;

        let ciphertext_modulus = lwe_pksk.ciphertext_modulus();
        let compressed_polynomial_size = lwe_pksk.output_polynomial_size();
        let compressed_glwe_size = lwe_pksk.output_glwe_size();

        let first_ct = ciphertexts.first().unwrap();
        let first_ct_info = first_ct.info.blocks.first().unwrap();
        let message_modulus = first_ct_info.message_modulus;
        let carry_modulus = first_ct_info.carry_modulus;

        let lwe_dimension = first_ct.d_blocks.lwe_dimension();

        let num_lwes: usize = ciphertexts
            .iter()
            .map(|x| x.d_blocks.lwe_ciphertext_count().0)
            .sum();

        let num_glwes = num_lwes.div_ceil(self.lwe_per_glwe.0);
        let glwe_mask_size = glwe_mask_size(
            compressed_glwe_size.to_glwe_dimension(),
            compressed_polynomial_size,
        );
        // The number of u64 (both mask and bodies)
        let uncompressed_len = num_glwes * glwe_mask_size + num_lwes;
        let number_bits_to_pack = uncompressed_len * self.storage_log_modulus.0;
        let compressed_len = number_bits_to_pack.div_ceil(u64::BITS as usize);
        let mut packed_glwe_list = CudaVec::new(compressed_len, streams, 0);

        unsafe {
            let input_lwes = Self::flatten_async(ciphertexts, streams);

            compress_integer_radix_async(
                streams,
                &mut packed_glwe_list,
                &input_lwes.0.d_vec,
                &self.packing_key_switching_key.d_vec,
                message_modulus,
                carry_modulus,
                compressed_glwe_size.to_glwe_dimension(),
                compressed_polynomial_size,
                lwe_dimension,
                lwe_pksk.decomposition_base_log(),
                lwe_pksk.decomposition_level_count(),
                self.lwe_per_glwe.0 as u32,
                self.storage_log_modulus.0 as u32,
                num_lwes as u32,
            );

            streams.synchronize();
        };

        CudaPackedGlweCiphertextList {
            data: packed_glwe_list,
            glwe_dimension: compressed_glwe_size.to_glwe_dimension(),
            polynomial_size: compressed_polynomial_size,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
            bodies_count: num_lwes,
            storage_log_modulus: self.storage_log_modulus,
            lwe_per_glwe: LweCiphertextCount(compressed_polynomial_size.0),
            initial_len: uncompressed_len,
        }
    }
}

impl CudaDecompressionKey {
    pub fn unpack(
        &self,
        packed_list: &CudaPackedGlweCiphertextList,
        kind: DataKind,
        start_block_index: usize,
        end_block_index: usize,
        streams: &CudaStreams,
    ) -> Result<CudaRadixCiphertext, crate::Error> {
        if self.message_modulus.0 != self.carry_modulus.0 {
            return Err(crate::Error::new(format!(
                "Tried to unpack values from a list where message modulus \
                ({:?}) is != carry modulus ({:?}), this is not supported.",
                self.message_modulus, self.carry_modulus,
            )));
        }

        if end_block_index >= packed_list.bodies_count {
            return Err(crate::Error::new(format!(
                "Tried getting index {end_block_index} for CompressedCiphertextList \
                with {} elements, out of bound access.",
                packed_list.bodies_count
            )));
        }

        let indexes_array = (start_block_index..=end_block_index)
            .map(|x| x as u32)
            .collect_vec();

        let encryption_glwe_dimension = self.glwe_dimension;
        let encryption_polynomial_size = self.polynomial_size;
        let compression_glwe_dimension = packed_list.glwe_dimension;
        let compression_polynomial_size = packed_list.polynomial_size;
        let indexes_array_len = LweCiphertextCount(indexes_array.len());

        let message_modulus = self.message_modulus;
        let carry_modulus = self.carry_modulus;
        let ciphertext_modulus = self.ciphertext_modulus;
        let storage_log_modulus = packed_list.storage_log_modulus;

        match &self.blind_rotate_key {
            CudaBootstrappingKey::Classic(bsk) => {
                let lwe_dimension = bsk.output_lwe_dimension();

                let mut output_lwe = CudaLweCiphertextList::new(
                    lwe_dimension,
                    indexes_array_len,
                    ciphertext_modulus,
                    streams,
                );

                unsafe {
                    decompress_integer_radix_async(
                        streams,
                        &mut output_lwe.0.d_vec,
                        &packed_list.data,
                        &bsk.d_vec,
                        packed_list.bodies_count as u32,
                        message_modulus,
                        carry_modulus,
                        encryption_glwe_dimension,
                        encryption_polynomial_size,
                        compression_glwe_dimension,
                        compression_polynomial_size,
                        lwe_dimension,
                        bsk.decomp_base_log(),
                        bsk.decomp_level_count(),
                        storage_log_modulus.0 as u32,
                        indexes_array.as_slice(),
                        indexes_array_len.0 as u32,
                    );
                }

                streams.synchronize();

                let degree = match kind {
                    DataKind::Unsigned(_) | DataKind::Signed(_) | DataKind::String { .. } => {
                        Degree::new(message_modulus.0 - 1)
                    }
                    DataKind::Boolean => Degree::new(1),
                };

                let first_block_info = CudaBlockInfo {
                    degree,
                    message_modulus,
                    carry_modulus,
                    pbs_order: PBSOrder::KeyswitchBootstrap,
                    noise_level: NoiseLevel::NOMINAL,
                };

                let blocks = vec![first_block_info; output_lwe.0.lwe_ciphertext_count.0];

                Ok(CudaRadixCiphertext {
                    d_blocks: output_lwe,
                    info: CudaRadixCiphertextInfo { blocks },
                })
            }
            CudaBootstrappingKey::MultiBit(_) => {
                panic! {"Compression is currently not compatible with Multi-Bit PBS"}
            }
        }
    }
}
