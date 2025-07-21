use crate::core_crypto::entities::{LweCiphertextList, LweCiphertextOwned};
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CiphertextModulus, LweSize};
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::{CudaRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::BooleanBlock;
use crate::shortint::Ciphertext;

use super::CudaIntegerRadixCiphertext;

/// Wrapper type used to signal that the inner value encrypts 0 or 1
///
/// Since values ares encrypted, it is not possible to know whether a
/// ciphertext encrypts a boolean value (0 or 1). However, some algorithms
/// require that the ciphertext does indeed encrypt a boolean value.
///
/// This wrapper serves as making it explicit that it is known that the value
/// encrypted is 0 or 1. And that if a function taking a CudaBooleanBlock as input
/// returns incorrect value, it may be due to the value not really being 0 or 1.
///
/// Also, some function such as comparisons are known to return an encrypted value
/// that is either 0 or 1, and thus return a CudaCiphertext wrapped in a [CudaBooleanBlock].
pub struct CudaBooleanBlock(pub CudaUnsignedRadixCiphertext);

impl CudaBooleanBlock {
    /// Creates a new CudaBooleanBlock.
    ///
    /// The input ciphertext has only one block and encrypts 0 or 1 otherwise
    /// functions expecting a CudaBooleanBlock could result in wrong computation
    pub fn from_cuda_radix_ciphertext(ct: CudaRadixCiphertext) -> Self {
        assert_eq!(
            ct.info.blocks.len(),
            1,
            "CudaBooleanBlock needs to have 1 block, got {}",
            ct.info.blocks.len()
        );
        assert!(
            ct.info.blocks.first().unwrap().degree.get() <= 1,
            "CudaBooleanBlock needs to have degree <= 1, got {}",
            ct.info.blocks.first().unwrap().degree.get()
        );
        assert_eq!(
            ct.d_blocks.0.lwe_ciphertext_count.0, 1,
            "CudaBooleanBlock needs to have 1 block, got {}",
            ct.d_blocks.0.lwe_ciphertext_count.0
        );
        assert_eq!(
            ct.d_blocks.0.d_vec.len(),
            ct.d_blocks.0.lwe_dimension.0 + 1,
            "CudaBooleanBlock needs to have a length of LWE size, got {}",
            ct.d_blocks.0.lwe_dimension.0 + 1
        );
        Self(CudaUnsignedRadixCiphertext { ciphertext: ct })
    }

    pub fn from_boolean_block(boolean_block: &BooleanBlock, streams: &CudaStreams) -> Self {
        let mut h_boolean_block = boolean_block.clone();

        let lwe_size = boolean_block.0.ct.as_ref().len();

        let h_ct = LweCiphertextList::from_container(
            h_boolean_block.0.ct.as_mut(),
            LweSize(lwe_size),
            CiphertextModulus::new_native(),
        );
        let d_blocks = CudaLweCiphertextList::from_lwe_ciphertext_list(&h_ct, streams);

        let info = CudaBlockInfo {
            degree: boolean_block.0.degree,
            message_modulus: boolean_block.0.message_modulus,
            carry_modulus: boolean_block.0.carry_modulus,
            atomic_pattern: boolean_block.0.atomic_pattern,
            noise_level: boolean_block.0.noise_level(),
        };
        let radix_info = vec![info; 1];
        let info = CudaRadixCiphertextInfo { blocks: radix_info };

        Self(CudaUnsignedRadixCiphertext {
            ciphertext: CudaRadixCiphertext { d_blocks, info },
        })
    }

    pub fn copy_from_boolean_block(&mut self, boolean_block: &BooleanBlock, streams: &CudaStreams) {
        unsafe {
            self.0.ciphertext.d_blocks.0.d_vec.copy_from_cpu_async(
                boolean_block.0.ct.as_ref(),
                streams,
                0,
            );
        }
        streams.synchronize();

        let info = CudaBlockInfo {
            degree: boolean_block.0.degree,
            message_modulus: boolean_block.0.message_modulus,
            carry_modulus: boolean_block.0.carry_modulus,
            atomic_pattern: boolean_block.0.atomic_pattern,
            noise_level: boolean_block.0.noise_level(),
        };
        let radix_info = vec![info; 1];
        self.0.ciphertext.info = CudaRadixCiphertextInfo { blocks: radix_info };
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 1;
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     num_blocks,
    ///     &stream,
    /// );
    ///
    /// let msg1 = true;
    /// let ct1 = cks.encrypt_bool(msg1);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaBooleanBlock::from_boolean_block(&ct1, &stream);
    /// let ct2 = d_ct1.to_boolean_block(&stream);
    /// let res = cks.decrypt_bool(&ct2);
    ///
    /// assert_eq!(msg1, res);
    /// ```
    pub fn to_boolean_block(&self, streams: &CudaStreams) -> BooleanBlock {
        let h_lwe_ciphertext_list = self.0.ciphertext.d_blocks.to_lwe_ciphertext_list(streams);
        let ciphertext_modulus = h_lwe_ciphertext_list.ciphertext_modulus();

        let block = Ciphertext::new(
            LweCiphertextOwned::from_container(
                h_lwe_ciphertext_list.into_container(),
                ciphertext_modulus,
            ),
            self.0.ciphertext.info.blocks[0].degree,
            self.0.ciphertext.info.blocks[0].noise_level,
            self.0.ciphertext.info.blocks[0].message_modulus,
            self.0.ciphertext.info.blocks[0].carry_modulus,
            self.0.ciphertext.info.blocks[0].atomic_pattern,
        );

        BooleanBlock::new_unchecked(block)
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub(crate) unsafe fn duplicate_async(&self, streams: &CudaStreams) -> Self {
        let lwe_ciphertext_count = self.0.ciphertext.d_blocks.lwe_ciphertext_count();
        let ciphertext_modulus = self.0.ciphertext.d_blocks.ciphertext_modulus();

        let mut d_ct = CudaVec::new_async(self.0.ciphertext.d_blocks.0.d_vec.len(), streams, 0);
        d_ct.copy_from_gpu_async(&self.0.ciphertext.d_blocks.0.d_vec, streams, 0);

        let d_blocks =
            CudaLweCiphertextList::from_cuda_vec(d_ct, lwe_ciphertext_count, ciphertext_modulus);

        Self(CudaUnsignedRadixCiphertext {
            ciphertext: CudaRadixCiphertext {
                d_blocks,
                info: self.0.ciphertext.info.clone(),
            },
        })
    }

    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        let ct = unsafe { self.duplicate_async(streams) };
        streams.synchronize();
        ct
    }

    pub fn move_to_stream(self, streams: &CudaStreams) -> Self {
        Self(self.0.move_to_stream(streams))
    }

    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        self.0.gpu_indexes()
    }
}

impl AsRef<CudaUnsignedRadixCiphertext> for CudaBooleanBlock {
    fn as_ref(&self) -> &CudaUnsignedRadixCiphertext {
        &self.0
    }
}
impl AsMut<CudaUnsignedRadixCiphertext> for CudaBooleanBlock {
    fn as_mut(&mut self) -> &mut CudaUnsignedRadixCiphertext {
        &mut self.0
    }
}
