use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{cuda_backend_count_of_consecutive_bits, cuda_backend_ilog2, PBSType};
use crate::integer::server_key::radix_parallel::ilog2::{BitValue, Direction};

impl CudaServerKey {
    /// Counts how many consecutive bits there are
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    pub(crate) fn count_consecutive_bits<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        direction: Direction,
        bit_value: BitValue,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let num_bits_in_message = self.message_modulus.0.ilog2();
        let original_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;

        let num_bits_in_ciphertext = num_bits_in_message
            .checked_mul(original_num_blocks as u32)
            .expect("Number of bits encrypted exceeds u32::MAX");

        let counter_num_blocks =
            (num_bits_in_ciphertext.ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let mut result: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(counter_num_blocks, streams);

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_count_of_consecutive_bits(
                        streams,
                        result.as_mut(),
                        ct.as_ref(),
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_bsk.input_lwe_dimension(),
                        d_bsk.glwe_dimension(),
                        d_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count(),
                        d_bsk.decomp_base_log(),
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        direction as u32,
                        bit_value as u32,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_count_of_consecutive_bits(
                        streams,
                        result.as_mut(),
                        ct.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_multibit_bsk.input_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension(),
                        d_multibit_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count(),
                        d_multibit_bsk.decomp_base_log(),
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        direction as u32,
                        bit_value as u32,
                        None,
                    );
                }
            }
        }

        result
    }

    //==============================================================================================
    //  Unchecked
    //==============================================================================================

    /// See [Self::trailing_zeros]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_trailing_zeros<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Trailing, BitValue::Zero, streams)
    }

    /// See [Self::trailing_ones]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_trailing_ones<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Trailing, BitValue::One, streams)
    }

    /// See [Self::leading_zeros]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_leading_zeros<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Leading, BitValue::Zero, streams)
    }

    /// See [Self::leading_ones]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_leading_ones<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Leading, BitValue::One, streams)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// See [Self::ilog2] for an example
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_ilog2<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        if ct.as_ref().d_blocks.0.d_vec.is_empty() {
            return self.create_trivial_zero_radix(0, streams);
        }

        let num_bits_in_message = self.message_modulus.0.ilog2();
        let input_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;

        let num_bits_in_ciphertext = num_bits_in_message
            .checked_mul(input_num_blocks as u32)
            .expect("Number of bits encrypted exceeds u32::MAX");

        if num_bits_in_ciphertext == 0 {
            return self.create_trivial_zero_radix(1, streams);
        }

        let counter_num_blocks = ((num_bits_in_ciphertext - 1).ilog2() + 1 + 1)
            .div_ceil(self.message_modulus.0.ilog2()) as usize;

        let trivial_ct_neg_n: CudaSignedRadixCiphertext = self.create_trivial_radix(
            -(num_bits_in_ciphertext as i32 - 1i32),
            counter_num_blocks,
            streams,
        );

        let trivial_ct_2: CudaSignedRadixCiphertext =
            self.create_trivial_radix(2u32, counter_num_blocks, streams);

        let trivial_ct_m_minus_1_block: CudaSignedRadixCiphertext =
            self.create_trivial_radix(self.message_modulus.0 - 1, 1, streams);

        let mut result: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(counter_num_blocks, streams);

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_ilog2(
                        streams,
                        result.as_mut(),
                        ct.as_ref(),
                        trivial_ct_neg_n.as_ref(),
                        trivial_ct_2.as_ref(),
                        trivial_ct_m_minus_1_block.as_ref(),
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_bsk.input_lwe_dimension(),
                        d_bsk.glwe_dimension(),
                        d_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count(),
                        d_bsk.decomp_base_log(),
                        LweBskGroupingFactor(0),
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::Classical,
                        input_num_blocks as u32,
                        counter_num_blocks as u32,
                        num_bits_in_ciphertext,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_ilog2(
                        streams,
                        result.as_mut(),
                        ct.as_ref(),
                        trivial_ct_neg_n.as_ref(),
                        trivial_ct_2.as_ref(),
                        trivial_ct_m_minus_1_block.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_multibit_bsk.input_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension(),
                        d_multibit_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count(),
                        d_multibit_bsk.decomp_base_log(),
                        d_multibit_bsk.grouping_factor,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::MultiBit,
                        input_num_blocks as u32,
                        counter_num_blocks as u32,
                        num_bits_in_ciphertext,
                        None,
                    );
                }
            }
        }
        result
    }

    /// Returns the number of trailing zeros in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = -4i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically trailing zeros
    /// let d_ct_res = sks.trailing_zeros(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.trailing_zeros());
    /// ```
    pub fn trailing_zeros<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate(streams);
            self.full_propagate_assign(&mut tmp, streams);
            &tmp
        };
        self.unchecked_trailing_zeros(ct, streams)
    }

    /// Returns the number of trailing ones in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = -4i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically trailing ones
    /// let d_ct_res = sks.trailing_ones(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.trailing_ones());
    /// ```
    pub fn trailing_ones<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate(streams);
            self.full_propagate_assign(&mut tmp, streams);
            &tmp
        };
        self.unchecked_trailing_ones(ct, streams)
    }

    /// Returns the number of leading zeros in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = -4i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically leading zeros
    /// let d_ct_res = sks.leading_zeros(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.leading_zeros());
    /// ```
    pub fn leading_zeros<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate(streams);
            self.full_propagate_assign(&mut tmp, streams);
            &tmp
        };
        self.unchecked_leading_zeros(ct, streams)
    }

    /// Returns the number of leading ones in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = -4i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically leading ones
    /// let d_ct_res = sks.leading_ones(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.leading_ones());
    /// ```
    pub fn leading_ones<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate(streams);
            self.full_propagate_assign(&mut tmp, streams);
            &tmp
        };
        self.unchecked_leading_ones(ct, streams)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = 5i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically a log2
    /// let d_ct_res = sks.ilog2(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.ilog2());
    /// ```
    pub fn ilog2<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate(streams);
            self.full_propagate_assign(&mut tmp, streams);
            &tmp
        };

        self.unchecked_ilog2(ct, streams)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// Also returns a BooleanBlock, encrypting true (1) if the result is
    /// valid (input is > 0), otherwise 0.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = 5i8;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    /// // Compute homomorphically a log2 and a check if input is valid
    /// let (d_ct_res, d_is_oks) = sks.checked_ilog2(&d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.ilog2());
    /// let is_oks = d_is_oks.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&is_oks);
    /// assert!(is_ok);
    pub fn checked_ilog2<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate(streams);
            self.full_propagate_assign(&mut tmp, streams);
            &tmp
        };

        (self.ilog2(ct, streams), self.scalar_gt(ct, 0, streams))
    }
}
