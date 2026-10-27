use crate::core_crypto::gpu::entities::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::core_crypto::prelude::packed_integers::PackedIntegers;
use crate::core_crypto::prelude::{
    glwe_mask_size, CiphertextModulus, CiphertextModulusLog, GlweCiphertextCount,
    LweCiphertextCount, NonZeroLweCiphertextCount, PolynomialSize, UnsignedInteger,
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
    cuda_backend_get_decompression_size_on_gpu, extract_glwe,
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
    pub lwe_per_glwe: NonZeroLweCiphertextCount,
    // Number of lwe bodies that are compressed in this list
    pub total_lwe_bodies_count: usize,
    // Number of elements (u64) the uncompressed GLWE list had
    // keep in mind the last GLWE may not be full
    pub initial_len: usize,
}

impl<T: UnsignedInteger> CudaPackedGlweCiphertextListMeta<T> {
    /// Number of elements of a GLWE of this list holding `bodies_count` bodies, without padding,
    /// or None if it overflows
    fn packed_glwe_len(&self, bodies_count: usize) -> Option<usize> {
        self.glwe_dimension
            .0
            .checked_mul(self.polynomial_size.0)
            .and_then(|mask_size| mask_size.checked_add(bodies_count))
            .and_then(|glwe_len| glwe_len.checked_mul(self.storage_log_modulus.0))
            .map(|glwe_bits| glwe_bits.div_ceil(T::BITS))
    }
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
    ) -> crate::Result<Self> {
        let (Some(input_meta), Some(first_ct)) =
            (ct_list.meta.as_ref(), ct_list.glwe_ciphertext_list.first())
        else {
            // A list without metadata or without GLWE stores no ciphertext
            return Ok(Self {
                data: CudaVec::new(0, streams, 0),
                meta: None,
            });
        };

        let glwe_dimension = first_ct.glwe_dimension();
        let polynomial_size = first_ct.polynomial_size();
        let log_modulus = first_ct.packed_integers().log_modulus();
        let lwe_per_glwe = input_meta.lwe_per_glwe.get();

        let size_overflow =
            || error!("Invalid CompressedSquashedNoiseCiphertextList metadata: size overflows");
        let mask_size = glwe_dimension
            .0
            .checked_mul(polynomial_size.0)
            .ok_or_else(size_overflow)?;

        // GPU expects uniform stride per GLWE. The last GLWE on the CPU side
        // may have fewer packed elements (fewer bodies), so we pad each GLWE's
        // packed coefficients to the uniform stride.
        let per_glwe_packed = mask_size
            .checked_add(lwe_per_glwe)
            .and_then(|per_glwe_uncompressed| per_glwe_uncompressed.checked_mul(log_modulus.0))
            .ok_or_else(size_overflow)?
            .div_ceil(T::BITS);

        if ct_list.glwe_ciphertext_list.iter().any(|ct| {
            ct.glwe_dimension() != glwe_dimension
                || ct.polynomial_size() != polynomial_size
                || ct.packed_integers().log_modulus() != log_modulus
                || ct.bodies_count().0 > lwe_per_glwe
                || ct.packed_integers().packed_coeffs().len() > per_glwe_packed
        }) {
            return Err(error!(
                "Invalid CompressedSquashedNoiseCiphertextList: its GLWEs do not share the same \
                layout, it cannot be copied to the GPU"
            ));
        }

        let total_lwe_bodies_count = ct_list
            .glwe_ciphertext_list
            .iter()
            .try_fold(0usize, |acc, ct| acc.checked_add(ct.bodies_count().0))
            .ok_or_else(size_overflow)?;
        let initial_len = ct_list
            .glwe_ciphertext_list
            .len()
            .checked_mul(mask_size)
            .and_then(|masks_len| masks_len.checked_add(total_lwe_bodies_count))
            .ok_or_else(size_overflow)?;

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
            message_modulus: input_meta.message_modulus,
            carry_modulus: input_meta.carry_modulus,
            ciphertext_modulus: CiphertextModulus::new_native(),
            storage_log_modulus: log_modulus,
            lwe_per_glwe: input_meta.lwe_per_glwe,
            total_lwe_bodies_count,
            initial_len,
        });

        Ok(Self { data, meta })
    }

    // Split the list into its compressed GLWEs.
    //
    // Every GLWE but the last one holds `lwe_per_glwe` bodies and is packed into
    //   per_glwe_packed = ceil((k*N + lwe_per_glwe) * log_modulus / Scalar::BITS)
    // elements. The last GLWE may hold fewer bodies, and may or may not be padded to
    // `per_glwe_packed` elements depending on how the list was built. Both layouts are accepted,
    // and the returned GLWEs never include the padding.
    pub(crate) fn to_compressed_glwe_list(
        &self,
        streams: &CudaStreams,
    ) -> crate::Result<Vec<CompressedModulusSwitchedGlweCiphertext<T>>> {
        let Some(meta) = self.meta else {
            // If there is no metadata, the list stores no ciphertext
            return Ok(Vec::new());
        };

        let lwe_per_glwe = meta.lwe_per_glwe.get();
        let log_modulus = meta.storage_log_modulus;

        if log_modulus.0 == 0
            || log_modulus.0 > CiphertextModulusLog::from(meta.ciphertext_modulus).0
        {
            return Err(error!(
                "Invalid CudaPackedGlweCiphertextList metadata: storage log modulus {} is not in \
                [1, log2({})]",
                log_modulus.0, meta.ciphertext_modulus
            ));
        }

        let size_overflow =
            || error!("Invalid CudaPackedGlweCiphertextList metadata: size overflows");
        let glwe_mask_size = meta
            .glwe_dimension
            .0
            .checked_mul(meta.polynomial_size.0)
            .ok_or_else(size_overflow)?;

        // Only accept the two layouts described above: the last GLWE padded to the size of a full
        // one, or not padded at all
        let num_glwes = meta.total_lwe_bodies_count.div_ceil(lwe_per_glwe);
        let (padded_len, unpadded_len) = match num_glwes.checked_sub(1) {
            None => (0, 0),
            Some(num_full_glwes) => {
                let per_glwe_packed = meta
                    .packed_glwe_len(lwe_per_glwe)
                    .ok_or_else(size_overflow)?;
                let last_glwe_bodies = num_full_glwes
                    .checked_mul(lwe_per_glwe)
                    .and_then(|full_glwes_bodies| {
                        meta.total_lwe_bodies_count.checked_sub(full_glwes_bodies)
                    })
                    .ok_or_else(size_overflow)?;
                let full_glwes_len = per_glwe_packed
                    .checked_mul(num_full_glwes)
                    .ok_or_else(size_overflow)?;

                (
                    full_glwes_len
                        .checked_add(per_glwe_packed)
                        .ok_or_else(size_overflow)?,
                    full_glwes_len
                        .checked_add(
                            meta.packed_glwe_len(last_glwe_bodies)
                                .ok_or_else(size_overflow)?,
                        )
                        .ok_or_else(size_overflow)?,
                )
            }
        };

        if self.data.len() != padded_len && self.data.len() != unpadded_len {
            return Err(error!(
                "Invalid CudaPackedGlweCiphertextList: it holds {} elements, whereas its \
                metadata describes {unpadded_len} elements, or {padded_len} with padding",
                self.data.len()
            ));
        }

        let mut packed_coeffs: Vec<T> = vec![T::ZERO; self.data.len()];

        unsafe {
            self.data
                .copy_to_cpu_async(packed_coeffs.as_mut_slice(), streams, 0);
        }
        streams.synchronize();

        let mut glwe_list = Vec::new();
        let mut num_bodies_left = meta.total_lwe_bodies_count;
        let mut chunk_start = 0usize;
        while num_bodies_left != 0 {
            let bodies_count = num_bodies_left.min(lwe_per_glwe);
            let initial_len = glwe_mask_size
                .checked_add(bodies_count)
                .ok_or_else(size_overflow)?;
            let len = meta
                .packed_glwe_len(bodies_count)
                .ok_or_else(size_overflow)?;
            let chunk = chunk_start
                .checked_add(len)
                .and_then(|chunk_end| packed_coeffs.get(chunk_start..chunk_end))
                .ok_or_else(|| {
                    error!(
                        "Invalid CudaPackedGlweCiphertextList: its metadata describes more data \
                        than the {} elements it holds",
                        packed_coeffs.len()
                    )
                })?;

            let packed_integers =
                PackedIntegers::from_raw_parts(chunk.to_vec(), log_modulus, initial_len)?;

            glwe_list.push(CompressedModulusSwitchedGlweCiphertext::from_raw_parts(
                packed_integers,
                meta.glwe_dimension,
                meta.polynomial_size,
                LweCiphertextCount(bodies_count),
                meta.ciphertext_modulus,
            ));
            num_bodies_left -= bodies_count;
            chunk_start += len;
        }

        Ok(glwe_list)
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

        GlweCiphertextCount(
            meta.total_lwe_bodies_count
                .div_ceil(meta.lwe_per_glwe.get()),
        )
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

/// Concatenates the given LWE lists into a single contiguous list on GPU 0.
///
/// All lists must have `lwe_dimension` as their LWE dimension, callers are
/// responsible for checking this. The iterator must not be empty.
fn flatten_lwe_lists<'a, T, I>(
    lwe_lists: I,
    lwe_dimension: LweDimension,
    streams: &CudaStreams,
) -> CudaLweCiphertextList<T>
where
    T: UnsignedInteger,
    I: IntoIterator<Item = &'a CudaLweCiphertextList<T>>,
    I::IntoIter: Clone,
{
    let lwe_lists = lwe_lists.into_iter();
    let ciphertext_modulus = lwe_lists.clone().next().unwrap().ciphertext_modulus();

    // Compute total number of lwe ciphertexts we will be handling
    let total_num_blocks: usize = lwe_lists.clone().map(|x| x.lwe_ciphertext_count().0).sum();

    let lwe_ciphertext_count = LweCiphertextCount(total_num_blocks);

    let mut d_vec = unsafe {
        CudaVec::new_async(
            lwe_dimension.to_lwe_size().0 * lwe_ciphertext_count.0,
            streams,
            0,
        )
    };
    let mut offset: usize = 0;
    for lwe_list in lwe_lists {
        let dest_ptr = unsafe { d_vec.as_mut_c_ptr(0).add(offset * std::mem::size_of::<T>()) };
        let size = lwe_list.0.d_vec.len * std::mem::size_of::<T>();
        unsafe {
            cuda_memcpy_async_gpu_to_gpu(
                dest_ptr,
                lwe_list.0.d_vec.as_c_ptr(0),
                size as u64,
                streams.ptr[0],
                streams.gpu_indexes[0].get(),
            );
        }
        streams.synchronize();

        offset += lwe_list.0.d_vec.len;
    }

    CudaLweCiphertextList::from_cuda_vec(d_vec, lwe_ciphertext_count, ciphertext_modulus)
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
        let input_ciphertext_modulus = first_ct.d_blocks.ciphertext_modulus();

        assert!(
            self.lwe_per_glwe.0 <= compressed_polynomial_size.0,
            "Cannot pack more than polynomial_size(={}) elements per glwe, {} requested",
            compressed_polynomial_size.0,
            self.lwe_per_glwe.0,
        );

        let lwe_dimension = lwe_pksk.input_key_lwe_dimension();
        for ct in ciphertexts {
            assert_eq!(
                lwe_dimension,
                ct.d_blocks.lwe_dimension(),
                "All ciphertexts do not have the same lwe dimension as the packing keyswitch key"
            );
            assert_eq!(
                input_ciphertext_modulus,
                ct.d_blocks.ciphertext_modulus(),
                "All ciphertexts do not have the same ciphertext modulus"
            );
            for block in &ct.info.blocks {
                assert_eq!(
                    message_modulus, block.message_modulus,
                    "All ciphertexts do not have the same message modulus"
                );
                assert_eq!(
                    carry_modulus, block.carry_modulus,
                    "All ciphertexts do not have the same carry modulus"
                );
            }
        }

        let mut glwe_array_out = CudaPackedGlweCiphertextList {
            data: packed_glwe_list,
            meta: Some(CudaPackedGlweCiphertextListMeta {
                glwe_dimension: compressed_glwe_size.to_glwe_dimension(),
                polynomial_size: compressed_polynomial_size,
                message_modulus,
                carry_modulus,
                ciphertext_modulus,
                storage_log_modulus: self.storage_log_modulus,
                lwe_per_glwe: NonZeroLweCiphertextCount::try_from(self.lwe_per_glwe)
                    .expect("Cannot pack ciphertexts with a key storing 0 LWE per GLWE"),
                total_lwe_bodies_count: num_lwes,
                initial_len: uncompressed_len,
            }),
        };

        let input_lwes = flatten_lwe_lists(
            ciphertexts.iter().map(|ct| &ct.d_blocks),
            lwe_dimension,
            streams,
        );
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
                lwe_pksk.params_ffi(),
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
            lwe_pksk.params_ffi(),
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

        if let CudaBootstrappingKey::Classic(bsk) = &self.blind_rotate_key {
            assert!(
                bsk.ms_noise_reduction_configuration.is_none(),
                "Decompression key should not do modulus switch noise reduction"
            );
        }
        let lwe_dimension = self.blind_rotate_key.output_lwe_dimension();

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
                message_modulus,
                carry_modulus,
                encryption_glwe_dimension,
                encryption_polynomial_size,
                compression_glwe_dimension,
                compression_polynomial_size,
                &self.blind_rotate_key,
                indexes_array.as_slice(),
                indexes_array_len.0 as u32,
            );
        }

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

        if let CudaBootstrappingKey::Classic(bsk) = &self.blind_rotate_key {
            assert!(
                bsk.ms_noise_reduction_configuration.is_none(),
                "Decompression key should not do modulus switch noise reduction"
            );
        }
        cuda_backend_get_decompression_size_on_gpu(
            streams,
            message_modulus,
            carry_modulus,
            encryption_glwe_dimension,
            encryption_polynomial_size,
            compression_glwe_dimension,
            compression_polynomial_size,
            &self.blind_rotate_key,
            indexes_array_len.0 as u32,
        )
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

        if let CudaBootstrappingKey::Classic(bsk) = &self.blind_rotate_key {
            assert!(
                bsk.ms_noise_reduction_configuration.is_none(),
                "Decompression key should not do modulus switch noise reduction"
            );
        }
        cuda_backend_get_decompression_size_on_gpu(
            streams,
            message_modulus,
            carry_modulus,
            encryption_glwe_dimension,
            encryption_polynomial_size,
            compression_glwe_dimension,
            compression_polynomial_size,
            &self.blind_rotate_key,
            indexes_array_len.0 as u32,
        )
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

    pub fn compress_noise_squashed_ciphertexts_into_list(
        &self,
        ciphertexts: &[CudaSquashedNoiseRadixCiphertext],
        streams: &CudaStreams,
    ) -> CudaPackedGlweCiphertextList<u128> {
        let lwe_pksk = &self.packing_key_switching_key;

        if ciphertexts.is_empty() {
            return CudaPackedGlweCiphertextList {
                data: CudaVec::new(0, streams, 0),
                meta: None,
            };
        }

        // Ok to unwrap because list is not empty
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

        let first_ct_info = first_ct.info.blocks.first().unwrap();
        let message_modulus = first_ct_info.message_modulus;
        let carry_modulus = first_ct_info.carry_modulus;

        assert!(
            ciphertext_modulus.is_power_of_two(),
            "Squashed noise ciphertext modulus should be a power of 2 for compression, got {ciphertext_modulus:?}"
        );
        assert!(
            self.lwe_per_glwe.0 <= compressed_polynomial_size.0,
            "Cannot pack more than polynomial_size(={}) elements per glwe, {} requested",
            compressed_polynomial_size.0,
            self.lwe_per_glwe.0,
        );

        let lwe_dimension = lwe_pksk.input_key_lwe_dimension();
        for ct in ciphertexts {
            assert_eq!(
                lwe_dimension,
                ct.packed_d_blocks.lwe_dimension(),
                "All ciphertexts do not have the same lwe dimension as the packing keyswitch key"
            );
            assert_eq!(
                ciphertext_modulus,
                ct.packed_d_blocks.ciphertext_modulus(),
                "All ciphertexts do not have the same ciphertext modulus"
            );
            for block in &ct.info.blocks {
                assert_eq!(
                    message_modulus, block.message_modulus,
                    "All ciphertexts do not have the same message modulus"
                );
                assert_eq!(
                    carry_modulus, block.carry_modulus,
                    "All ciphertexts do not have the same carry modulus"
                );
            }
        }

        let mut glwe_array_out = CudaPackedGlweCiphertextList {
            data: packed_glwe_list,
            meta: Some(CudaPackedGlweCiphertextListMeta {
                glwe_dimension: compressed_glwe_size.to_glwe_dimension(),
                polynomial_size: compressed_polynomial_size,
                message_modulus,
                carry_modulus,
                ciphertext_modulus,
                storage_log_modulus: ciphertext_modulus_log,
                lwe_per_glwe: NonZeroLweCiphertextCount::try_from(self.lwe_per_glwe)
                    .expect("Cannot pack ciphertexts with a key storing 0 LWE per GLWE"),
                total_lwe_bodies_count: num_lwes,
                initial_len: uncompressed_len,
            }),
        };

        let input_lwes = flatten_lwe_lists(
            ciphertexts.iter().map(|ct| &ct.packed_d_blocks),
            lwe_dimension,
            streams,
        );
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
                lwe_pksk.params_ffi(),
                self.lwe_per_glwe.0 as u32,
                num_lwes as u32,
            );

            streams.synchronize();
        };

        glwe_array_out
    }
}
