pub mod boolean_value;
pub mod compact_list;
pub mod compressed_ciphertext_list;
pub mod info;
pub mod squashed_noise;

use crate::core_crypto::gpu::lwe_bootstrap_key::{
    prepare_cuda_ms_noise_reduction_key_ffi, CudaModulusSwitchNoiseReductionKey,
};
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{
    LweBskGroupingFactor, LweCiphertextList, LweCiphertextOwned, Numeric, UnsignedInteger,
};
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::PBSType;
use crate::integer::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::integer::{IntegerCiphertext, RadixCiphertext, SignedRadixCiphertext};
use crate::shortint::{CarryModulus, Ciphertext, EncryptionKeyChoice, MessageModulus};
use crate::GpuIndex;
use tfhe_cuda_backend::bindings::{
    cleanup_expand_without_verification_64, cuda_expand_without_verification_64,
    scratch_cuda_expand_without_verification_64,
};

pub trait CudaIntegerRadixCiphertext: Sized {
    const IS_SIGNED: bool;
    fn as_ref(&self) -> &CudaRadixCiphertext;
    fn as_mut(&mut self) -> &mut CudaRadixCiphertext;
    fn from(ct: CudaRadixCiphertext) -> Self;

    fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self::from(self.as_ref().duplicate(streams))
    }

    /// Moves `self` to the gpu on which the CudaStreams is
    ///
    /// no-op if self is already on the correct gpu
    fn move_to_stream(self, streams: &CudaStreams) -> Self {
        if self.gpu_indexes() == streams.gpu_indexes() {
            self
        } else {
            self.duplicate(streams)
        }
    }

    fn into_inner(self) -> CudaRadixCiphertext;

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    unsafe fn duplicate_async(&self, streams: &CudaStreams) -> Self {
        Self::from(self.as_ref().duplicate_async(streams))
    }

    fn block_carries_are_empty(&self) -> bool {
        self.as_ref()
            .info
            .blocks
            .iter()
            .all(CudaBlockInfo::carry_is_empty)
    }

    fn holds_boolean_value(&self) -> bool {
        self.as_ref().info.blocks[0].degree.get() <= 1
            && self.as_ref().info.blocks[1..]
                .iter()
                .all(|cuda_block_info| cuda_block_info.degree.get() == 0)
    }

    fn is_equal(&self, other: &Self, streams: &CudaStreams) -> bool {
        self.as_ref().is_equal(other.as_ref(), streams)
    }

    fn gpu_indexes(&self) -> &[GpuIndex] {
        &self.as_ref().d_blocks.0.d_vec.gpu_indexes
    }
}

pub struct CudaRadixCiphertext {
    pub d_blocks: CudaLweCiphertextList<u64>,
    pub info: CudaRadixCiphertextInfo,
}

pub struct CudaUnsignedRadixCiphertext {
    pub ciphertext: CudaRadixCiphertext,
}

pub struct CudaSignedRadixCiphertext {
    pub ciphertext: CudaRadixCiphertext,
}

impl CudaIntegerRadixCiphertext for CudaUnsignedRadixCiphertext {
    const IS_SIGNED: bool = false;

    fn as_ref(&self) -> &CudaRadixCiphertext {
        &self.ciphertext
    }

    fn as_mut(&mut self) -> &mut CudaRadixCiphertext {
        &mut self.ciphertext
    }

    fn from(ct: CudaRadixCiphertext) -> Self {
        Self { ciphertext: ct }
    }

    fn into_inner(self) -> CudaRadixCiphertext {
        self.ciphertext
    }
}

impl CudaIntegerRadixCiphertext for CudaSignedRadixCiphertext {
    const IS_SIGNED: bool = true;

    fn as_ref(&self) -> &CudaRadixCiphertext {
        &self.ciphertext
    }

    fn as_mut(&mut self) -> &mut CudaRadixCiphertext {
        &mut self.ciphertext
    }

    fn from(ct: CudaRadixCiphertext) -> Self {
        Self { ciphertext: ct }
    }

    fn into_inner(self) -> CudaRadixCiphertext {
        self.ciphertext
    }
}

impl CudaRadixCiphertext {
    pub fn from_cpu_blocks(blocks: &[Ciphertext], streams: &CudaStreams) -> Self {
        let mut h_radix_ciphertext = blocks
            .iter()
            .flat_map(|block| block.ct.clone().into_container())
            .collect::<Vec<_>>();

        let lwe_size = blocks.first().unwrap().ct.lwe_size();
        let ciphertext_modulus = blocks.first().unwrap().ct.ciphertext_modulus();

        let h_ct = LweCiphertextList::from_container(
            h_radix_ciphertext.as_mut_slice(),
            lwe_size,
            ciphertext_modulus,
        );
        let d_blocks = CudaLweCiphertextList::from_lwe_ciphertext_list(&h_ct, streams);

        let info = CudaRadixCiphertextInfo {
            blocks: blocks
                .iter()
                .map(|block| CudaBlockInfo {
                    degree: block.degree,
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    atomic_pattern: block.atomic_pattern,
                    noise_level: block.noise_level(),
                })
                .collect(),
        };

        Self { d_blocks, info }
    }

    pub fn to_cpu_blocks(&self, streams: &CudaStreams) -> Vec<Ciphertext> {
        let h_lwe_ciphertext_list = self.d_blocks.to_lwe_ciphertext_list(streams);
        let ciphertext_modulus = h_lwe_ciphertext_list.ciphertext_modulus();
        let lwe_size = h_lwe_ciphertext_list.lwe_size().0;

        h_lwe_ciphertext_list
            .into_container()
            .chunks(lwe_size)
            .zip(&self.info.blocks)
            .map(|(data, i)| {
                Ciphertext::new(
                    LweCiphertextOwned::from_container(data.to_vec(), ciphertext_modulus),
                    i.degree,
                    i.noise_level,
                    i.message_modulus,
                    i.carry_modulus,
                    i.atomic_pattern,
                )
            })
            .collect()
    }
    pub fn from_radix_ciphertext_vec<T: CudaIntegerRadixCiphertext>(
        list: &[T],
        streams: &CudaStreams,
    ) -> Self {
        let lwes = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            list.iter().map(|ciphertext| &ciphertext.as_ref().d_blocks),
            streams,
        );
        let info = CudaRadixCiphertextInfo {
            blocks: list
                .iter()
                .flat_map(|ciphertext| ciphertext.as_ref().info.blocks.iter())
                .copied()
                .collect::<Vec<CudaBlockInfo>>(),
        };
        Self::new(lwes, info)
    }
}

impl CudaUnsignedRadixCiphertext {
    pub fn new(d_blocks: CudaLweCiphertextList<u64>, info: CudaRadixCiphertextInfo) -> Self {
        Self {
            ciphertext: CudaRadixCiphertext { d_blocks, info },
        }
    }
    /// Copies a RadixCiphertext to the GPU memory
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// let size = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     size,
    ///     &streams,
    /// );
    ///
    /// let clear: u64 = 255;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt(clear);
    ///
    /// let d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    /// let h_ctxt = d_ctxt.to_radix_ciphertext(&streams);
    ///
    /// assert_eq!(h_ctxt, ctxt);
    /// ```
    pub fn from_radix_ciphertext(radix: &RadixCiphertext, streams: &CudaStreams) -> Self {
        Self {
            ciphertext: CudaRadixCiphertext::from_cpu_blocks(radix.blocks(), streams),
        }
    }

    pub fn copy_from_radix_ciphertext(&mut self, radix: &RadixCiphertext, streams: &CudaStreams) {
        let mut h_radix_ciphertext = radix
            .blocks
            .iter()
            .flat_map(|block| block.ct.clone().into_container())
            .collect::<Vec<_>>();

        unsafe {
            self.ciphertext.d_blocks.0.d_vec.copy_from_cpu_async(
                h_radix_ciphertext.as_mut_slice(),
                streams,
                0,
            );
        }
        streams.synchronize();

        self.ciphertext.info = CudaRadixCiphertextInfo {
            blocks: radix
                .blocks
                .iter()
                .map(|block| CudaBlockInfo {
                    degree: block.degree,
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    atomic_pattern: block.atomic_pattern,
                    noise_level: block.noise_level(),
                })
                .collect(),
        };
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     num_blocks,
    ///     &streams,
    /// );
    ///
    /// let msg1 = 10u32;
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let ct2 = d_ct1.to_radix_ciphertext(&streams);
    /// let msg2 = cks.decrypt(&ct2);
    ///
    /// assert_eq!(msg1, msg2);
    /// ```
    pub fn to_radix_ciphertext(&self, streams: &CudaStreams) -> RadixCiphertext {
        RadixCiphertext::from(self.ciphertext.to_cpu_blocks(streams))
    }
}

impl CudaSignedRadixCiphertext {
    pub fn new(d_blocks: CudaLweCiphertextList<u64>, info: CudaRadixCiphertextInfo) -> Self {
        Self {
            ciphertext: CudaRadixCiphertext { d_blocks, info },
        }
    }
    /// Copies a RadixCiphertext to the GPU memory
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// let size = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     size,
    ///     &streams,
    /// );
    ///
    /// let clear: i64 = 255;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed(clear);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    /// let h_ctxt = d_ctxt.to_signed_radix_ciphertext(&streams);
    ///
    /// assert_eq!(h_ctxt, ctxt);
    /// ```
    pub fn from_signed_radix_ciphertext(
        radix: &SignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> Self {
        Self {
            ciphertext: CudaRadixCiphertext::from_cpu_blocks(radix.blocks(), streams),
        }
    }

    pub fn copy_from_signed_radix_ciphertext(
        &mut self,
        radix: &SignedRadixCiphertext,
        streams: &CudaStreams,
    ) {
        let mut h_radix_ciphertext = radix
            .blocks
            .iter()
            .flat_map(|block| block.ct.clone().into_container())
            .collect::<Vec<_>>();

        unsafe {
            self.ciphertext.d_blocks.0.d_vec.copy_from_cpu_async(
                h_radix_ciphertext.as_mut_slice(),
                streams,
                0,
            );
        }
        streams.synchronize();

        self.ciphertext.info = CudaRadixCiphertextInfo {
            blocks: radix
                .blocks
                .iter()
                .map(|block| CudaBlockInfo {
                    degree: block.degree,
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    atomic_pattern: block.atomic_pattern,
                    noise_level: block.noise_level(),
                })
                .collect(),
        };
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     num_blocks,
    ///     &streams,
    /// );
    ///
    /// let msg1 = 10i32;
    /// let ct1 = cks.encrypt_signed(msg1);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct1, &streams);
    /// let ct2 = d_ct1.to_signed_radix_ciphertext(&streams);
    /// let msg2 = cks.decrypt_signed(&ct2);
    ///
    /// assert_eq!(msg1, msg2);
    /// ```
    pub fn to_signed_radix_ciphertext(&self, streams: &CudaStreams) -> SignedRadixCiphertext {
        SignedRadixCiphertext::from(self.ciphertext.to_cpu_blocks(streams))
    }
}

impl CudaRadixCiphertext {
    pub fn new(d_blocks: CudaLweCiphertextList<u64>, info: CudaRadixCiphertextInfo) -> Self {
        Self { d_blocks, info }
    }
    /// ```rust
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     num_blocks,
    ///     &streams,
    /// );
    ///
    /// let msg = 10i32;
    /// let ct = cks.encrypt_signed(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
    /// let d_ct_copied = d_ct.duplicate(&streams);
    ///
    /// let ct_copied = d_ct_copied.to_signed_radix_ciphertext(&streams);
    /// let msg_copied = cks.decrypt_signed(&ct_copied);
    ///
    /// assert_eq!(msg, msg_copied);
    /// ```
    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        let ct = unsafe { self.duplicate_async(streams) };
        streams.synchronize();
        ct
    }
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn duplicate_async(&self, streams: &CudaStreams) -> Self {
        let lwe_ciphertext_count = self.d_blocks.lwe_ciphertext_count();
        let ciphertext_modulus = self.d_blocks.ciphertext_modulus();

        let mut d_ct = CudaVec::new_async(self.d_blocks.0.d_vec.len(), streams, 0);
        d_ct.copy_from_gpu_async(&self.d_blocks.0.d_vec, streams, 0);

        let d_blocks =
            CudaLweCiphertextList::from_cuda_vec(d_ct, lwe_ciphertext_count, ciphertext_modulus);

        Self {
            d_blocks,
            info: self.info.clone(),
        }
    }

    fn is_equal(&self, other: &Self, streams: &CudaStreams) -> bool {
        let self_size = self.d_blocks.0.d_vec.len();
        let other_size = other.d_blocks.0.d_vec.len();
        let mut self_container: Vec<u64> = vec![0; self_size];
        let mut other_container: Vec<u64> = vec![0; other_size];

        unsafe {
            self.d_blocks
                .0
                .d_vec
                .copy_to_cpu_async(self_container.as_mut_slice(), streams, 0);
            other
                .d_blocks
                .0
                .d_vec
                .copy_to_cpu_async(other_container.as_mut_slice(), streams, 0);
        }
        streams.synchronize();

        self_container == other_container
    }
}

#[repr(u32)]
#[derive(Debug)]
pub enum KsType {
    BigToSmall = 0,
    SmallToBig = 1,
}

impl From<EncryptionKeyChoice> for KsType {
    fn from(value: EncryptionKeyChoice) -> Self {
        match value {
            EncryptionKeyChoice::Big => Self::SmallToBig,
            EncryptionKeyChoice::Small => Self::BigToSmall,
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
///
///
/// In this method, the input `lwe_flattened_compact_array_in` represents a flattened compact list.
/// Instead of receiving a `Vec<CompactCiphertextList>`, it takes a concatenation of all LWEs
/// that were inside that vector of compact list. Handling the input this way removes the need
/// to process multiple compact lists separately, simplifying GPU-based operations. The variable
/// name `lwe_flattened_compact_array_in` makes this intent explicit.
pub unsafe fn expand_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaLweCiphertextList<T>,
    lwe_flattened_compact_array_in: &CudaVec<T>,
    bootstrapping_key: &CudaVec<B>,
    computing_ks_key: &CudaVec<T>,
    casting_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    computing_glwe_dimension: GlweDimension,
    computing_polynomial_size: PolynomialSize,
    computing_lwe_dimension: LweDimension,
    computing_ks_level: DecompositionLevelCount,
    computing_ks_base_log: DecompositionBaseLog,
    casting_input_lwe_dimension: LweDimension,
    casting_output_lwe_dimension: LweDimension,
    casting_ks_level: DecompositionLevelCount,
    casting_ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    pbs_type: PBSType,
    casting_key_type: KsType,
    grouping_factor: LweBskGroupingFactor,
    num_lwes_per_compact_list: &[u32],
    is_boolean: &[bool],
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    let ct_modulus = lwe_array_out.ciphertext_modulus().raw_modulus_float();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let num_compact_lists = num_lwes_per_compact_list.len();

    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();

    scratch_cuda_expand_without_verification_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        computing_glwe_dimension.0 as u32,
        computing_polynomial_size.0 as u32,
        computing_glwe_dimension
            .to_equivalent_lwe_dimension(computing_polynomial_size)
            .0 as u32,
        computing_lwe_dimension.0 as u32,
        computing_ks_level.0 as u32,
        computing_ks_base_log.0 as u32,
        casting_input_lwe_dimension.0 as u32,
        casting_output_lwe_dimension.0 as u32,
        casting_ks_level.0 as u32,
        casting_ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_lwes_per_compact_list.as_ptr(),
        is_boolean.as_ptr(),
        num_compact_lists as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        casting_key_type as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_expand_without_verification_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        lwe_array_out.0.d_vec.as_mut_c_ptr(0),
        lwe_flattened_compact_array_in.as_c_ptr(0),
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        computing_ks_key.ptr.as_ptr(),
        casting_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_expand_without_verification_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
}
