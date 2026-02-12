use crate::core_crypto::gpu::entities::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::packed_integers::PackedIntegers;
use crate::core_crypto::prelude::{
    glwe_mask_size, CiphertextModulus, CiphertextModulusLog, GlweCiphertextCount,
    LweBskGroupingFactor, LweCiphertextCount, PolynomialSize, UnsignedInteger,
};
use crate::error;
use crate::high_level_api::keys::expanded::ExpandedDecompressionKey;
use crate::integer::ciphertext::{DataKind, NoiseSquashingCompressionKey};
use crate::integer::compression_keys::CompressionKey;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::squashed_noise::CudaSquashedNoiseRadixCiphertext;
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    cuda_backend_compress, cuda_backend_decompress, cuda_backend_get_compression_size_on_gpu,
    cuda_backend_get_decompression_size_on_gpu, extract_glwe, PBSType,
};
use crate::prelude::CastInto;
use crate::shortint::ciphertext::{
    CompressedCiphertextList,
    CompressedSquashedNoiseCiphertextList as ShortintCompressedSquashedNoiseCiphertextList, Degree,
    NoiseLevel,
};
use crate::shortint::parameters::AtomicPatternKind;
use crate::shortint::prelude::{GlweDimension, LweDimension};
use crate::shortint::{CarryModulus, MessageModulus, PBSOrder};
use itertools::Itertools;
use tfhe_cuda_backend::cuda_bind::cuda_memcpy_async_gpu_to_gpu;

#[derive(Debug)]
pub struct CudaCompressionKey {
    pub packing_key_switching_key: CudaLwePackingKeyswitchKey<u64>,
    pub lwe_per_glwe: LweCiphertextCount,
    pub storage_log_modulus: CiphertextModulusLog,
}

pub struct CudaNoiseSquashingCompressionKey {
    pub packing_key_switching_key: CudaLwePackingKeyswitchKey<u128>,
    pub lwe_per_glwe: LweCiphertextCount,
}

pub struct CudaDecompressionKey {
    pub blind_rotate_key: CudaBootstrappingKey<u64>,
    pub lwe_per_glwe: LweCiphertextCount,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

#[derive(Copy, Clone)]
pub struct CudaPackedGlweCiphertextListMeta<T: UnsignedInteger> {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus<T>,
    pub storage_log_modulus: CiphertextModulusLog,
    pub lwe_per_glwe: LweCiphertextCount,
    // Number of lwe bodies that are compressed in this list
    pub total_lwe_bodies_count: usize,
    // Number of elements (u64) the uncompressed GLWE list had
    // keep in mind the last GLWE may not be full
    pub initial_len: usize,
}

pub struct CudaPackedGlweCiphertextList<T: UnsignedInteger> {
    // The compressed GLWE list's elements
    pub data: CudaVec<T>,
    pub meta: Option<CudaPackedGlweCiphertextListMeta<T>>,
}

impl<T: UnsignedInteger> CudaPackedGlweCiphertextList<T> {
    pub(crate) fn from_glwe_ciphertext_list(
        ct_list: &ShortintCompressedSquashedNoiseCiphertextList,
        streams: &CudaStreams,
    ) -> Self {
        let input_meta = ct_list.meta.clone().unwrap();
        let total_lwe_bodies_count: usize = ct_list
            .glwe_ciphertext_list
            .iter()
            .map(|ct| ct.bodies_count().0)
            .sum();
        let glwe_dimension = ct_list
            .glwe_ciphertext_list
            .first()
            .unwrap()
            .glwe_dimension();
        let polynomial_size = ct_list
            .glwe_ciphertext_list
            .first()
            .unwrap()
            .polynomial_size();
        let log_modulus = ct_list
            .glwe_ciphertext_list
            .first()
            .unwrap()
            .packed_integers()
            .log_modulus();
        let num_glwes = ct_list.glwe_ciphertext_list.len();
        let mask_size = glwe_mask_size(glwe_dimension, polynomial_size);
        let initial_len = num_glwes * mask_size + total_lwe_bodies_count;

        // GPU expects uniform stride per GLWE. The last GLWE on the CPU side
        // may have fewer packed elements (fewer bodies), so we pad each GLWE's
        // packed coefficients to the uniform stride.
        let lwe_per_glwe = input_meta.lwe_per_glwe.0;
        let per_glwe_uncompressed = mask_size + lwe_per_glwe;
        let per_glwe_packed = (per_glwe_uncompressed * log_modulus.0).div_ceil(T::BITS);

        let flat_packed_integers: Vec<T> = ct_list
            .glwe_ciphertext_list
            .iter()
            .flat_map(|ct| {
                ct.packed_integers()
                    .packed_coeffs()
                    .iter()
                    .map(|&x| x.cast_into())
                    .chain(std::iter::repeat(T::ZERO))
                    .take(per_glwe_packed)
            })
            .collect();

        let data = unsafe {
            CudaVec::from_cpu_async(
                flat_packed_integers.as_slice(),
                streams,
                streams.gpu_indexes[0].get(),
            )
        };

        let meta = Some(CudaPackedGlweCiphertextListMeta::<T> {
            glwe_dimension,
            polynomial_size,
            message_modulus: ct_list.message_modulus().unwrap(),
            carry_modulus: input_meta.carry_modulus,
            ciphertext_modulus: CiphertextModulus::new_native(),
            storage_log_modulus: log_modulus,
            lwe_per_glwe: input_meta.lwe_per_glwe,
            total_lwe_bodies_count,
            initial_len,
        });

        Self { data, meta }
    }

    // Split PackedIntegers considering their GLWE representation.
    //
    // GPU stores packed data with uniform stride per GLWE:
    //   per_glwe_packed = ceil((k*N + lwe_per_glwe) * log_modulus / Scalar::BITS)
    // The last GLWE may have fewer meaningful body elements (zero-padded to
    // lwe_per_glwe on the GPU side), so its PackedIntegers is truncated to match
    // the actual body count.
    pub(crate) fn to_vec_packed_integers(&self, streams: &CudaStreams) -> Vec<PackedIntegers<T>> {
        let mut packed_coeffs: Vec<T> = vec![T::ZERO; self.data.len()];

        unsafe {
            self.data
                .copy_to_cpu_async(packed_coeffs.as_mut_slice(), streams, 0);
        }
        streams.synchronize();

        let meta = self.meta.unwrap();
        let glwe_mask_size = glwe_mask_size(meta.glwe_dimension, meta.polynomial_size);
        let lwe_per_glwe = meta.lwe_per_glwe.0;
        let log_modulus = meta.storage_log_modulus;
        let total_bodies = meta.total_lwe_bodies_count;
        let num_glwes = total_bodies.div_ceil(lwe_per_glwe);

        let per_glwe_uncompressed = glwe_mask_size + lwe_per_glwe;
        let per_glwe_packed = (per_glwe_uncompressed * log_modulus.0).div_ceil(T::BITS);

        packed_coeffs
            .chunks(per_glwe_packed)
            .enumerate()
            .map(|(i, chunk)| {
                let body_count = if i == num_glwes - 1 {
                    let remainder = total_bodies % lwe_per_glwe;
                    if remainder == 0 {
                        lwe_per_glwe
                    } else {
                        remainder
                    }
                } else {
                    lwe_per_glwe
                };
                let initial_len = glwe_mask_size + body_count;
                let expected_packed = (initial_len * log_modulus.0).div_ceil(T::BITS);
                PackedIntegers::from_raw_parts(
                    chunk[..expected_packed].to_vec(),
                    log_modulus,
                    initial_len,
                )
            })
            .collect_vec()
    }

    /// Returns the message modulus of the Ciphertexts in the list, or None if the list is empty
    pub fn message_modulus(&self) -> Option<MessageModulus> {
        self.meta.as_ref().map(|meta| meta.message_modulus)
    }

    pub fn bodies_count(&self) -> usize {
        // If there is no metadata, the list is empty
        self.meta
            .map(|meta| meta.total_lwe_bodies_count)
            .unwrap_or_default()
    }

    pub fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        let Some(meta) = self.meta.as_ref() else {
            return GlweCiphertextCount(0);
        };

        GlweCiphertextCount(meta.total_lwe_bodies_count.div_ceil(meta.lwe_per_glwe.0))
    }

    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            data: self.data.duplicate(streams),
            meta: self.meta,
        }
    }
    pub fn extract_glwe(
        &self,
        glwe_index: usize,
        streams: &CudaStreams,
    ) -> CudaGlweCiphertextList<T> {
        let meta = self
            .meta
            .as_ref()
            .expect("CudaPackedGlweCiphertextList meta must be set to extract GLWE");

        let mut output_cuda_glwe_list = CudaGlweCiphertextList::new(
            meta.glwe_dimension,
            meta.polynomial_size,
            GlweCiphertextCount(1),
            meta.ciphertext_modulus,
            streams,
        );

        extract_glwe(streams, &mut output_cuda_glwe_list, self, glwe_index as u32);
        output_cuda_glwe_list
    }
}

impl<T: UnsignedInteger> Clone for CudaPackedGlweCiphertextList<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            meta: self.meta,
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

    fn flatten(
        ciphertexts_slice: &[CudaRadixCiphertext],
        streams: &CudaStreams,
    ) -> CudaLweCiphertextList<u64> {
        let first_ct = &ciphertexts_slice.first().unwrap().d_blocks;

        // We assume all ciphertexts will have the same lwe dimension
        let lwe_dimension = first_ct.lwe_dimension();
        let ciphertext_modulus = first_ct.ciphertext_modulus();

        // Compute total number of lwe ciphertexts we will be handling
        let total_num_blocks: usize = ciphertexts_slice
            .iter()
            .map(|x| x.d_blocks.lwe_ciphertext_count().0)
            .sum();

        let lwe_ciphertext_count = LweCiphertextCount(total_num_blocks);

        let mut d_vec = unsafe {
            CudaVec::new_async(
                lwe_dimension.to_lwe_size().0 * lwe_ciphertext_count.0,
                streams,
                0,
            )
        };
        let mut offset: usize = 0;
        for ciphertext in ciphertexts_slice {
            let dest_ptr = unsafe {
                d_vec
                    .as_mut_c_ptr(0)
                    .add(offset * std::mem::size_of::<u64>())
            };
            let size = ciphertext.d_blocks.0.d_vec.len * std::mem::size_of::<u64>();
            unsafe {
                cuda_memcpy_async_gpu_to_gpu(
                    dest_ptr,
                    ciphertext.d_blocks.0.d_vec.as_c_ptr(0),
                    size as u64,
                    streams.ptr[0],
                    streams.gpu_indexes[0].get(),
                );
            }
            streams.synchronize();

            offset += ciphertext.d_blocks.0.d_vec.len;
        }

        CudaLweCiphertextList::from_cuda_vec(d_vec, lwe_ciphertext_count, ciphertext_modulus)
    }

    pub fn compress_ciphertexts_into_list(
        &self,
        ciphertexts: &[CudaRadixCiphertext],
        streams: &CudaStreams,
    ) -> CudaPackedGlweCiphertextList<u64> {
        let lwe_pksk = &self.packing_key_switching_key;

        let ciphertext_modulus = lwe_pksk.ciphertext_modulus();
        let compressed_polynomial_size = lwe_pksk.output_polynomial_size();
        let compressed_glwe_size = lwe_pksk.output_glwe_size();

        let num_lwes: usize = ciphertexts
            .iter()
            .map(|x| x.d_blocks.lwe_ciphertext_count().0)
            .sum();

        let num_glwes = num_lwes.div_ceil(self.lwe_per_glwe.0);
        let glwe_mask_size = glwe_mask_size(
            compressed_glwe_size.to_glwe_dimension(),
            compressed_polynomial_size,
        );
        // Each GLWE is packed independently with uniform stride, even the last
        // one (its body is zero-padded to lwe_per_glwe in the pack step).
        // This matches the per-GLWE packed layout that decompression expects.
        let per_glwe_uncompressed = glwe_mask_size + self.lwe_per_glwe.0;
        let per_glwe_packed =
            (per_glwe_uncompressed * self.storage_log_modulus.0).div_ceil(u64::BITS as usize);
        let compressed_len = num_glwes * per_glwe_packed;
        let uncompressed_len = num_glwes * glwe_mask_size + num_lwes;
        let packed_glwe_list = CudaVec::new(compressed_len, streams, 0);

        if ciphertexts.is_empty() {
            return CudaPackedGlweCiphertextList {
                data: packed_glwe_list,
                meta: None,
            };
        }

        // Ok to unwrap because list is not empty
        let first_ct = ciphertexts.first().unwrap();
        let first_ct_info = first_ct.info.blocks.first().unwrap();
        let message_modulus = first_ct_info.message_modulus;
        let carry_modulus = first_ct_info.carry_modulus;
        let lwe_dimension = first_ct.d_blocks.lwe_dimension();

        let mut glwe_array_out = CudaPackedGlweCiphertextList {
            data: packed_glwe_list,
            meta: Some(CudaPackedGlweCiphertextListMeta {
                glwe_dimension: compressed_glwe_size.to_glwe_dimension(),
                polynomial_size: compressed_polynomial_size,
                message_modulus,
                carry_modulus,
                ciphertext_modulus,
                storage_log_modulus: self.storage_log_modulus,
                lwe_per_glwe: self.lwe_per_glwe,
                total_lwe_bodies_count: num_lwes,
                initial_len: uncompressed_len,
            }),
        };

        let input_lwes = Self::flatten(ciphertexts, streams);
        unsafe {
            cuda_backend_compress(
                streams,
                &mut glwe_array_out,
                &input_lwes,
                &self.packing_key_switching_key.d_vec,
                message_modulus,
                carry_modulus,
                compressed_glwe_size.to_glwe_dimension(),
                compressed_polynomial_size,
                lwe_dimension,
                lwe_pksk.decomposition_base_log(),
                lwe_pksk.decomposition_level_count(),
                self.lwe_per_glwe.0 as u32,
                num_lwes as u32,
            );
        }

        streams.synchronize();

        glwe_array_out
    }
    pub fn get_compression_size_on_gpu(
        &self,
        num_lwes: u32,
        lwe_dimension: LweDimension,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        streams: &CudaStreams,
    ) -> u64 {
        let lwe_pksk = &self.packing_key_switching_key;
        let compressed_polynomial_size = lwe_pksk.output_polynomial_size();
        let compressed_glwe_size = lwe_pksk.output_glwe_size();

        cuda_backend_get_compression_size_on_gpu(
            streams,
            message_modulus,
            carry_modulus,
            compressed_glwe_size.to_glwe_dimension(),
            compressed_polynomial_size,
            lwe_dimension,
            lwe_pksk.decomposition_base_log(),
            lwe_pksk.decomposition_level_count(),
            self.lwe_per_glwe.0 as u32,
            num_lwes,
        )
    }
}

impl CudaDecompressionKey {
    /// Creates a `CudaDecompressionKey` from an expanded (standard domain) decompression key.
    pub(crate) fn from_expanded_decompression_key(
        expanded: &ExpandedDecompressionKey,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        ciphertext_modulus: CiphertextModulus<u64>,
        streams: &CudaStreams,
    ) -> crate::Result<Self> {
        let ExpandedDecompressionKey { bsk, lwe_per_glwe } = expanded;

        let blind_rotate_key = CudaBootstrappingKey::from_expanded_bootstrapping_key(bsk, streams)?;

        Ok(Self {
            blind_rotate_key,
            lwe_per_glwe: *lwe_per_glwe,
            glwe_dimension,
            polynomial_size,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
        })
    }

    pub fn unpack(
        &self,
        packed_list: &CudaPackedGlweCiphertextList<u64>,
        kind: DataKind,
        start_block_index: usize,
        end_block_index: usize,
        streams: &CudaStreams,
    ) -> Result<CudaRadixCiphertext, crate::Error> {
        if self.message_modulus.0 != self.carry_modulus.0 {
            return Err(error!(
                "Tried to unpack values from a list where message modulus \
                ({:?}) is != carry modulus ({:?}), this is not supported.",
                self.message_modulus, self.carry_modulus,
            ));
        }

        if end_block_index >= packed_list.bodies_count() {
            return Err(error!(
                "Tried getting index {end_block_index} for CompressedCiphertextList \
                with {} elements, out of bound access.",
                packed_list.bodies_count()
            ));
        }

        let meta = packed_list
            .meta
            .as_ref()
            .ok_or_else(|| error!("Missing ciphertext metadata in CompressedCiphertextList"))?;

        let indexes_array = (start_block_index..=end_block_index)
            .map(|x| x as u32)
            .collect_vec();

        let encryption_glwe_dimension = self.glwe_dimension;
        let encryption_polynomial_size = self.polynomial_size;
        let compression_glwe_dimension = meta.glwe_dimension;
        let compression_polynomial_size = meta.polynomial_size;
        let indexes_array_len = LweCiphertextCount(indexes_array.len());

        let message_modulus = self.message_modulus;
        let carry_modulus = self.carry_modulus;
        let ciphertext_modulus = self.ciphertext_modulus;

        let output_lwe = match &self.blind_rotate_key {
            CudaBootstrappingKey::Classic(bsk) => {
                assert!(
                    bsk.ms_noise_reduction_configuration.is_none(),
                    "Decompression key should not do modulus switch noise reduction"
                );
                let lwe_dimension = bsk.output_lwe_dimension();

                let mut output_lwe = CudaLweCiphertextList::new(
                    lwe_dimension,
                    indexes_array_len,
                    ciphertext_modulus,
                    streams,
                );

                unsafe {
                    cuda_backend_decompress(
                        streams,
                        &mut output_lwe,
                        packed_list,
                        &bsk.d_vec,
                        message_modulus,
                        carry_modulus,
                        encryption_glwe_dimension,
                        encryption_polynomial_size,
                        compression_glwe_dimension,
                        compression_polynomial_size,
                        lwe_dimension,
                        bsk.decomp_base_log(),
                        bsk.decomp_level_count(),
                        LweBskGroupingFactor(0),
                        PBSType::Classical,
                        indexes_array.as_slice(),
                        indexes_array_len.0 as u32,
                    );
                }
                output_lwe
            }
            CudaBootstrappingKey::MultiBit(bsk) => {
                let lwe_dimension = bsk.output_lwe_dimension();

                let mut output_lwe = CudaLweCiphertextList::new(
                    lwe_dimension,
                    indexes_array_len,
                    ciphertext_modulus,
                    streams,
                );

                unsafe {
                    cuda_backend_decompress(
                        streams,
                        &mut output_lwe,
                        packed_list,
                        &bsk.d_vec,
                        message_modulus,
                        carry_modulus,
                        encryption_glwe_dimension,
                        encryption_polynomial_size,
                        compression_glwe_dimension,
                        compression_polynomial_size,
                        lwe_dimension,
                        bsk.decomp_base_log(),
                        bsk.decomp_level_count(),
                        bsk.grouping_factor,
                        PBSType::MultiBit,
                        indexes_array.as_slice(),
                        indexes_array_len.0 as u32,
                    );
                }
                output_lwe
            }
        };

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
            atomic_pattern: AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
            noise_level: NoiseLevel::NOMINAL,
        };

        let blocks = vec![first_block_info; output_lwe.0.lwe_ciphertext_count.0];

        Ok(CudaRadixCiphertext {
            d_blocks: output_lwe,
            info: CudaRadixCiphertextInfo { blocks },
        })
    }
    pub fn get_gpu_list_unpack_size_on_gpu(
        &self,
        packed_list: &CudaPackedGlweCiphertextList<u64>,
        start_block_index: usize,
        end_block_index: usize,
        streams: &CudaStreams,
    ) -> u64 {
        if start_block_index == end_block_index {
            return 0;
        }

        let Some(ref meta) = packed_list.meta else {
            panic!("Missing ciphertext metadata in CompressedCiphertextList")
        };

        let indexes_array = (start_block_index..=end_block_index)
            .map(|x| x as u32)
            .collect_vec();

        let encryption_glwe_dimension = self.glwe_dimension;
        let encryption_polynomial_size = self.polynomial_size;
        let compression_glwe_dimension = meta.glwe_dimension;
        let compression_polynomial_size = meta.polynomial_size;

        let indexes_array_len = LweCiphertextCount(indexes_array.len());

        let message_modulus = self.message_modulus;
        let carry_modulus = self.carry_modulus;

        match &self.blind_rotate_key {
            CudaBootstrappingKey::Classic(bsk) => {
                assert!(
                    bsk.ms_noise_reduction_configuration.is_none(),
                    "Decompression key should not do modulus switch noise reduction"
                );
                let lwe_dimension = bsk.output_lwe_dimension();

                cuda_backend_get_decompression_size_on_gpu(
                    streams,
                    message_modulus,
                    carry_modulus,
                    encryption_glwe_dimension,
                    encryption_polynomial_size,
                    compression_glwe_dimension,
                    compression_polynomial_size,
                    lwe_dimension,
                    bsk.decomp_base_log(),
                    bsk.decomp_level_count(),
                    LweBskGroupingFactor(0),
                    PBSType::Classical,
                    indexes_array_len.0 as u32,
                )
            }
            CudaBootstrappingKey::MultiBit(bsk) => {
                let lwe_dimension = bsk.output_lwe_dimension();

                cuda_backend_get_decompression_size_on_gpu(
                    streams,
                    message_modulus,
                    carry_modulus,
                    encryption_glwe_dimension,
                    encryption_polynomial_size,
                    compression_glwe_dimension,
                    compression_polynomial_size,
                    lwe_dimension,
                    bsk.decomp_base_log(),
                    bsk.decomp_level_count(),
                    bsk.grouping_factor,
                    PBSType::MultiBit,
                    indexes_array_len.0 as u32,
                )
            }
        }
    }
    pub fn get_cpu_list_unpack_size_on_gpu(
        &self,
        packed_list: &CompressedCiphertextList,
        start_block_index: usize,
        end_block_index: usize,
        streams: &CudaStreams,
    ) -> u64 {
        if start_block_index == end_block_index {
            return 0;
        }

        let indexes_array = (start_block_index..=end_block_index)
            .map(|x| x as u32)
            .collect_vec();

        let encryption_glwe_dimension = self.glwe_dimension;
        let encryption_polynomial_size = self.polynomial_size;

        let compression_polynomial_size =
            packed_list.modulus_switched_glwe_ciphertext_list[0].polynomial_size();
        let compression_glwe_dimension =
            packed_list.modulus_switched_glwe_ciphertext_list[0].glwe_dimension();

        let indexes_array_len = LweCiphertextCount(indexes_array.len());

        let message_modulus = self.message_modulus;
        let carry_modulus = self.carry_modulus;

        match &self.blind_rotate_key {
            CudaBootstrappingKey::Classic(bsk) => {
                assert!(
                    bsk.ms_noise_reduction_configuration.is_none(),
                    "Decompression key should not do modulus switch noise reduction"
                );
                let lwe_dimension = bsk.output_lwe_dimension();

                cuda_backend_get_decompression_size_on_gpu(
                    streams,
                    message_modulus,
                    carry_modulus,
                    encryption_glwe_dimension,
                    encryption_polynomial_size,
                    compression_glwe_dimension,
                    compression_polynomial_size,
                    lwe_dimension,
                    bsk.decomp_base_log(),
                    bsk.decomp_level_count(),
                    LweBskGroupingFactor(0),
                    PBSType::Classical,
                    indexes_array_len.0 as u32,
                )
            }
            CudaBootstrappingKey::MultiBit(bsk) => {
                let lwe_dimension = bsk.output_lwe_dimension();

                cuda_backend_get_decompression_size_on_gpu(
                    streams,
                    message_modulus,
                    carry_modulus,
                    encryption_glwe_dimension,
                    encryption_polynomial_size,
                    compression_glwe_dimension,
                    compression_polynomial_size,
                    lwe_dimension,
                    bsk.decomp_base_log(),
                    bsk.decomp_level_count(),
                    bsk.grouping_factor,
                    PBSType::MultiBit,
                    indexes_array_len.0 as u32,
                )
            }
        }
    }
}

impl CudaNoiseSquashingCompressionKey {
    pub fn from_noise_squashing_compression_key(
        compression_key: &NoiseSquashingCompressionKey,
        streams: &CudaStreams,
    ) -> Self {
        Self {
            packing_key_switching_key: CudaLwePackingKeyswitchKey::from_lwe_packing_keyswitch_key(
                compression_key.key.packing_key_switching_key(),
                streams,
            ),
            lwe_per_glwe: compression_key.key.lwe_per_glwe(),
        }
    }

    fn flatten(
        ciphertexts_slice: &[CudaSquashedNoiseRadixCiphertext],
        streams: &CudaStreams,
    ) -> CudaLweCiphertextList<u128> {
        let first_ct = &ciphertexts_slice.first().unwrap().packed_d_blocks;

        // We assume all ciphertexts will have the same lwe dimension
        let lwe_dimension = first_ct.lwe_dimension();
        let ciphertext_modulus = first_ct.ciphertext_modulus();

        // Compute total number of lwe ciphertexts we will be handling
        let total_num_blocks: usize = ciphertexts_slice
            .iter()
            .map(|x| x.packed_d_blocks.lwe_ciphertext_count().0)
            .sum();

        let lwe_ciphertext_count = LweCiphertextCount(total_num_blocks);

        let mut d_vec = unsafe {
            CudaVec::new_async(
                lwe_dimension.to_lwe_size().0 * lwe_ciphertext_count.0,
                streams,
                0,
            )
        };
        let mut offset: usize = 0;
        for ciphertext in ciphertexts_slice {
            let dest_ptr = unsafe {
                d_vec
                    .as_mut_c_ptr(0)
                    .add(offset * std::mem::size_of::<u128>())
            };
            let size = ciphertext.packed_d_blocks.0.d_vec.len * std::mem::size_of::<u128>();
            unsafe {
                cuda_memcpy_async_gpu_to_gpu(
                    dest_ptr,
                    ciphertext.packed_d_blocks.0.d_vec.as_c_ptr(0),
                    size as u64,
                    streams.ptr[0],
                    streams.gpu_indexes[0].get(),
                );
            }
            streams.synchronize();
            offset += ciphertext.packed_d_blocks.0.d_vec.len;
        }

        CudaLweCiphertextList::from_cuda_vec(d_vec, lwe_ciphertext_count, ciphertext_modulus)
    }

    pub fn compress_noise_squashed_ciphertexts_into_list(
        &self,
        ciphertexts: &[CudaSquashedNoiseRadixCiphertext],
        streams: &CudaStreams,
    ) -> CudaPackedGlweCiphertextList<u128> {
        let lwe_pksk = &self.packing_key_switching_key;

        let first_ct = ciphertexts.first().unwrap();
        let ciphertext_modulus = first_ct.packed_d_blocks.ciphertext_modulus();
        let compressed_polynomial_size = lwe_pksk.output_polynomial_size();
        let compressed_glwe_size = lwe_pksk.output_glwe_size();

        let num_lwes: usize = ciphertexts
            .iter()
            .map(|x| x.packed_d_blocks.lwe_ciphertext_count().0)
            .sum();

        let num_glwes = num_lwes.div_ceil(self.lwe_per_glwe.0);
        let glwe_mask_size = glwe_mask_size(
            compressed_glwe_size.to_glwe_dimension(),
            compressed_polynomial_size,
        );
        let ciphertext_modulus_log = ciphertext_modulus.into_modulus_log();
        // Each GLWE is packed independently with uniform stride, even the last
        // one (its body is zero-padded to lwe_per_glwe in the pack step).
        // This matches the per-GLWE packed layout that decompression expects.
        // The CPU implementation uses ciphertext_modulus_log instead of self.storage_log_modulus
        // In the future the noise squash compression might include a modswitch so we will have to
        // update to add a storage_log_modulus param and use this.
        let per_glwe_uncompressed = glwe_mask_size + self.lwe_per_glwe.0;
        let per_glwe_packed =
            (per_glwe_uncompressed * ciphertext_modulus_log.0).div_ceil(u128::BITS as usize);
        let compressed_len = num_glwes * per_glwe_packed;
        let uncompressed_len = num_glwes * glwe_mask_size + num_lwes;
        let packed_glwe_list = CudaVec::new(compressed_len, streams, 0);

        if ciphertexts.is_empty() {
            return CudaPackedGlweCiphertextList {
                data: packed_glwe_list,
                meta: None,
            };
        }

        // Ok to unwrap because list is not empty
        let first_ct_info = first_ct.info.blocks.first().unwrap();
        let message_modulus = first_ct_info.message_modulus;
        let carry_modulus = first_ct_info.carry_modulus;

        let lwe_dimension = first_ct.packed_d_blocks.lwe_dimension();

        let mut glwe_array_out = CudaPackedGlweCiphertextList {
            data: packed_glwe_list,
            meta: Some(CudaPackedGlweCiphertextListMeta {
                glwe_dimension: compressed_glwe_size.to_glwe_dimension(),
                polynomial_size: compressed_polynomial_size,
                message_modulus,
                carry_modulus,
                ciphertext_modulus,
                storage_log_modulus: ciphertext_modulus_log,
                lwe_per_glwe: self.lwe_per_glwe,
                total_lwe_bodies_count: num_lwes,
                initial_len: uncompressed_len,
            }),
        };

        let input_lwes = Self::flatten(ciphertexts, streams);
        unsafe {
            cuda_backend_compress(
                streams,
                &mut glwe_array_out,
                &input_lwes,
                &self.packing_key_switching_key.d_vec,
                message_modulus,
                carry_modulus,
                compressed_glwe_size.to_glwe_dimension(),
                compressed_polynomial_size,
                lwe_dimension,
                lwe_pksk.decomposition_base_log(),
                lwe_pksk.decomposition_level_count(),
                self.lwe_per_glwe.0 as u32,
                num_lwes as u32,
            );

            streams.synchronize();
        };

        glwe_array_out
    }
}
