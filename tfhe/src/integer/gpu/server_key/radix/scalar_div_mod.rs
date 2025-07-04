use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    get_full_propagate_assign_size_on_gpu, get_scalar_div_integer_radix_kb_size_on_gpu,
    get_scalar_div_rem_integer_radix_kb_size_on_gpu,
    get_signed_scalar_div_integer_radix_kb_size_on_gpu,
    get_signed_scalar_div_rem_integer_radix_kb_size_on_gpu,
    unchecked_signed_scalar_div_integer_radix_kb_assign_async,
    unchecked_signed_scalar_div_rem_integer_radix_kb_assign_async,
    unchecked_unsigned_scalar_div_integer_radix_kb_assign_async,
    unchecked_unsigned_scalar_div_rem_integer_radix_kb_assign_async, CudaServerKey, PBSType,
};
use crate::integer::server_key::radix_parallel::scalar_div_mod::SignedReciprocable;
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::integer::server_key::{MiniUnsignedInteger, Reciprocable, ScalarMultiplier};
use crate::prelude::CastInto;

impl CudaServerKey {
    /// Computes homomorphically a division between a ciphertext and a scalar.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     size,
    ///     &streams,
    /// );
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar division:
    /// let d_ct_res = sks.unchecked_scalar_div(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg / scalar, clear);
    /// ```
    pub fn unchecked_scalar_div<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable,
    {
        let res = unsafe { self.unchecked_scalar_div_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_scalar_div_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let numerator_bits = self.message_modulus.0.ilog2()
            * numerator.ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
            >= to the number of bits encrypted in the ciphertext: \n\
            encrypted bits: {numerator_bits}, scalar bits: {}
            ",
            Scalar::BITS
        );

        let mut quotient = unsafe { numerator.duplicate_async(streams) };

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_unsigned_scalar_div_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    divisor,
                    &self.key_switching_key.d_vec,
                    &d_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    d_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    PBSType::Classical,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_unsigned_scalar_div_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    divisor,
                    &self.key_switching_key.d_vec,
                    &d_multibit_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    d_multibit_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    PBSType::MultiBit,
                    None,
                );
            }
        }

        quotient
    }

    /// Computes homomorphically a division between a ciphertext and a scalar.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.scalar_div(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg / scalar, clear);
    /// ```
    pub fn scalar_div<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable,
    {
        let res = unsafe { self.unchecked_scalar_div_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn scalar_div_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_scalar_div_async(numerator, divisor, streams)
    }

    pub fn unchecked_scalar_div_rem<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext)
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let (quotient, remainder) =
            unsafe { self.unchecked_scalar_div_rem_async(numerator, divisor, streams) };

        streams.synchronize();

        (quotient, remainder)
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_scalar_div_rem_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext)
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let numerator_bits = self.message_modulus.0.ilog2()
            * numerator.ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
        >= to the number of bits encrypted in the ciphertext: \n\
        encrypted bits: {numerator_bits}, scalar bits: {}",
            Scalar::BITS
        );

        let mut quotient: CudaUnsignedRadixCiphertext =
            unsafe { numerator.duplicate_async(streams) };
        let mut remainder: CudaUnsignedRadixCiphertext = unsafe {
            self.create_trivial_zero_radix_async(
                numerator.as_ref().d_blocks.lwe_ciphertext_count().0,
                streams,
            )
        };

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_unsigned_scalar_div_rem_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    remainder.as_mut(),
                    divisor,
                    &self.key_switching_key.d_vec,
                    &d_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    d_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    PBSType::Classical,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_unsigned_scalar_div_rem_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    remainder.as_mut(),
                    divisor,
                    &self.key_switching_key.d_vec,
                    &d_multibit_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    d_multibit_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    PBSType::MultiBit,
                    None,
                );
            }
        }

        (quotient, remainder)
    }

    /// Computes homomorphically a division between a ciphertext and a scalar and returns the
    /// encrypted quotient and remainder.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let (d_ct_q, d_ct_r) = sks.scalar_div_rem(&d_ct, scalar, &streams);
    /// let ct_q = d_ct_q.to_radix_ciphertext(&streams);
    /// let ct_r = d_ct_r.to_radix_ciphertext(&streams);
    ///
    /// let quotient: u64 = cks.decrypt(&ct_q);
    /// let remainder: u64 = cks.decrypt(&ct_r);
    /// assert_eq!(msg / scalar, quotient);
    /// assert_eq!(msg % scalar, remainder);
    /// ```
    pub fn scalar_div_rem<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext)
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let res = unsafe { self.unchecked_scalar_div_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn scalar_div_rem_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext)
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_scalar_div_rem_async(numerator, divisor, streams)
    }

    pub fn unchecked_scalar_rem<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let res = unsafe { self.unchecked_scalar_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_scalar_rem_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        self.unchecked_scalar_div_rem_async(numerator, divisor, streams)
            .1
    }

    /// Computes homomorphically a division between a ciphertext and a scalar.
    ///
    /// The result is returned as a new ciphertext that encrypts the remainder.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.scalar_rem(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg % scalar, clear);
    /// ```
    pub fn scalar_rem<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let res = unsafe { self.unchecked_scalar_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn scalar_rem_async<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_scalar_rem_async(numerator, divisor, streams)
    }

    pub fn unchecked_signed_scalar_div<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let res = unsafe { self.unchecked_signed_scalar_div_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_signed_scalar_div_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let numerator_bits = self.message_modulus.0.ilog2()
            * numerator.ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is\
    >= to the number of bits encrypted in the ciphertext"
        );

        let mut quotient: CudaSignedRadixCiphertext = numerator.duplicate_async(streams);

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_signed_scalar_div_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    divisor,
                    &self.key_switching_key.d_vec,
                    &d_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    d_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    PBSType::Classical,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_signed_scalar_div_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    divisor,
                    &self.key_switching_key.d_vec,
                    &d_multibit_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    d_multibit_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    PBSType::MultiBit,
                    None,
                );
            }
        }

        let _carry = self.propagate_single_carry_assign_async(
            &mut quotient,
            streams,
            None,
            OutputFlag::None,
        );

        quotient
    }

    /// Computes homomorphically a division between a signed ciphertext and a scalar.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = -3;
    ///
    /// let ct = cks.encrypt_signed(msg);
    /// let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar division:
    /// let d_ct_res = sks.signed_scalar_div(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    ///
    /// let clear: i64 = cks.decrypt_signed(&ct_res);
    /// assert_eq!(msg / scalar, clear);
    /// ```
    pub fn signed_scalar_div<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let res = unsafe { self.signed_scalar_div_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn signed_scalar_div_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_signed_scalar_div_async(numerator, divisor, streams)
    }

    pub fn unchecked_signed_scalar_div_rem<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext)
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let res =
            unsafe { self.unchecked_signed_scalar_div_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_signed_scalar_div_rem_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext)
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let numerator_bits = self.message_modulus.0.ilog2()
            * numerator.ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is\
>= to the number of bits encrypted in the ciphertext"
        );

        let mut quotient: CudaSignedRadixCiphertext = numerator.duplicate_async(streams);
        let mut remainder: CudaSignedRadixCiphertext = self.create_trivial_zero_radix_async(
            numerator.as_ref().d_blocks.lwe_ciphertext_count().0,
            streams,
        );

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_signed_scalar_div_rem_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    remainder.as_mut(),
                    divisor,
                    &self.key_switching_key.d_vec,
                    &d_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    d_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    PBSType::Classical,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_signed_scalar_div_rem_integer_radix_kb_assign_async(
                    streams,
                    quotient.as_mut(),
                    remainder.as_mut(),
                    divisor,
                    &self.key_switching_key.d_vec,
                    &d_multibit_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    d_multibit_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    PBSType::MultiBit,
                    None,
                );
            }
        }

        (quotient, remainder)
    }

    /// Computes homomorphically a division between a signed ciphertext and a scalar.
    ///
    /// The result is returned as a two new ciphertexts for the quotient and remainder.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = -3;
    ///
    /// let ct = cks.encrypt_signed(msg);
    /// let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar division:
    /// let (d_ct_q, d_ct_r) = sks.signed_scalar_div_rem(&d_ct, scalar, &streams);
    /// let ct_q = d_ct_q.to_signed_radix_ciphertext(&streams);
    /// let ct_r = d_ct_r.to_signed_radix_ciphertext(&streams);
    ///
    /// let quotient: i64 = cks.decrypt_signed(&ct_q);
    /// let remainder: i64 = cks.decrypt_signed(&ct_r);
    /// assert_eq!(msg / scalar, quotient);
    /// assert_eq!(msg % scalar, remainder);
    /// ```
    pub fn signed_scalar_div_rem<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext)
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let res = unsafe { self.signed_scalar_div_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn signed_scalar_div_rem_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext)
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_signed_scalar_div_rem_async(numerator, divisor, streams)
    }

    pub fn unchecked_signed_scalar_rem<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let remainder =
            unsafe { self.unchecked_signed_scalar_rem_async(numerator, divisor, streams) };
        streams.synchronize();

        remainder
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn unchecked_signed_scalar_rem_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let (_, remainder) =
            self.unchecked_signed_scalar_div_rem_async(numerator, divisor, streams);

        remainder
    }

    /// Computes homomorphically a division between a ciphertext and a scalar.
    ///
    /// The result is returned as a new ciphertext that encrypts the remainder of the division.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 30;
    /// let scalar = -3;
    ///
    /// let ct = cks.encrypt_signed(msg);
    /// let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.signed_scalar_rem(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    ///
    /// let clear: i64 = cks.decrypt_signed(&ct_res);
    /// assert_eq!(msg % scalar, clear);
    /// ```
    pub fn signed_scalar_rem<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let res = unsafe { self.signed_scalar_rem_async(numerator, divisor, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn signed_scalar_rem_async<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            tmp_numerator = numerator.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_numerator, streams);
            &tmp_numerator
        };

        self.unchecked_signed_scalar_rem_async(numerator, divisor, streams)
    }

    pub fn get_scalar_div_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let num_blocks = numerator.ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;
        let numerator_bits = self.message_modulus.0.ilog2() * num_blocks;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
>= to the number of bits encrypted in the ciphertext: \n\
encrypted bits: {numerator_bits}, scalar bits: {}
",
            Scalar::BITS
        );

        let full_prop_mem = if numerator.block_carries_are_empty() {
            0
        } else {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => get_full_propagate_assign_size_on_gpu(
                    streams,
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
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                ),
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    get_full_propagate_assign_size_on_gpu(
                        streams,
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
                        None,
                    )
                }
            }
        };

        let scalar_div_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => get_scalar_div_integer_radix_kb_size_on_gpu(
                streams,
                divisor,
                self.message_modulus,
                self.carry_modulus,
                d_bsk.glwe_dimension,
                d_bsk.polynomial_size,
                d_bsk.input_lwe_dimension,
                self.key_switching_key.decomposition_level_count(),
                self.key_switching_key.decomposition_base_log(),
                d_bsk.decomp_level_count,
                d_bsk.decomp_base_log,
                LweBskGroupingFactor(0),
                num_blocks,
                PBSType::Classical,
                d_bsk.d_ms_noise_reduction_key.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                get_scalar_div_integer_radix_kb_size_on_gpu(
                    streams,
                    divisor,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    d_multibit_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                    PBSType::MultiBit,
                    None,
                )
            }
        };

        full_prop_mem.max(scalar_div_mem)
    }

    pub fn get_scalar_div_rem_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let numerator_bits = self.message_modulus.0.ilog2() * num_blocks;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
>= to the number of bits encrypted in the ciphertext: \n\
encrypted bits: {numerator_bits}, scalar bits: {}
",
            Scalar::BITS
        );

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    get_scalar_div_rem_integer_radix_kb_size_on_gpu(
                        streams,
                        divisor,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        d_bsk.input_lwe_dimension,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        num_blocks,
                        PBSType::Classical,
                        d_bsk.d_ms_noise_reduction_key.as_ref(),
                    )
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    get_scalar_div_rem_integer_radix_kb_size_on_gpu(
                        streams,
                        divisor,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        d_multibit_bsk.input_lwe_dimension,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        num_blocks,
                        PBSType::MultiBit,
                        None,
                    )
                }
            }
        }
    }

    pub fn get_scalar_rem_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        if MiniUnsignedInteger::is_power_of_two(divisor) {
            return self.get_scalar_bitand_size_on_gpu(numerator, streams);
        }

        self.get_scalar_div_rem_size_on_gpu(numerator, divisor, streams)
    }

    pub fn get_signed_scalar_div_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: SignedReciprocable,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let numerator_bits = self.message_modulus.0.ilog2() * num_blocks;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is\
>= to the number of bits encrypted in the ciphertext"
        );

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                get_signed_scalar_div_integer_radix_kb_size_on_gpu(
                    streams,
                    divisor,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    d_bsk.input_lwe_dimension,
                    d_bsk.decomp_base_log,
                    d_bsk.decomp_level_count,
                    self.key_switching_key.decomposition_base_log(),
                    self.key_switching_key.decomposition_level_count(),
                    LweBskGroupingFactor(0),
                    num_blocks,
                    PBSType::Classical,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                )
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                get_signed_scalar_div_integer_radix_kb_size_on_gpu(
                    streams,
                    divisor,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    d_multibit_bsk.input_lwe_dimension,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.decomp_level_count,
                    self.key_switching_key.decomposition_base_log(),
                    self.key_switching_key.decomposition_level_count(),
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                    PBSType::MultiBit,
                    None,
                )
            }
        }
    }

    pub fn get_signed_scalar_div_rem_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let numerator_bits = self.message_modulus.0.ilog2() * num_blocks;

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is\
>= to the number of bits encrypted in the ciphertext"
        );

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    get_signed_scalar_div_rem_integer_radix_kb_size_on_gpu(
                        streams,
                        divisor,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        d_bsk.input_lwe_dimension,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        num_blocks,
                        PBSType::Classical,
                        d_bsk.d_ms_noise_reduction_key.as_ref(),
                    )
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    get_signed_scalar_div_rem_integer_radix_kb_size_on_gpu(
                        streams,
                        divisor,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        d_multibit_bsk.input_lwe_dimension,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        num_blocks,
                        PBSType::MultiBit,
                        None,
                    )
                }
            }
        }
    }

    pub fn get_signed_scalar_rem_size_on_gpu<Scalar>(
        &self,
        numerator: &CudaSignedRadixCiphertext,
        divisor: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        self.get_signed_scalar_div_rem_size_on_gpu(numerator, divisor, streams)
            + 2 * self.get_ciphertext_size_on_gpu(numerator)
    }
}
