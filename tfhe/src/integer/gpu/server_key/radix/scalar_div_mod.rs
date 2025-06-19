use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{LweBskGroupingFactor, Numeric};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    get_full_propagate_assign_size_on_gpu, get_scalar_div_integer_radix_kb_size_on_gpu,
    unchecked_unsigned_scalar_div_integer_radix_kb_assign_async, CudaServerKey, PBSType,
};
use crate::integer::server_key::radix_parallel::scalar_div_mod::{
    choose_multiplier, SignedReciprocable,
};
use crate::integer::server_key::{MiniUnsignedInteger, Reciprocable, ScalarMultiplier};
use crate::prelude::{CastFrom, CastInto};

impl CudaServerKey {
    fn get_scalar_mul_high_size_on_gpu<T, Scalar>(
        &self,
        lhs: &T,
        rhs: Scalar,
        streams: &CudaStreams,
    ) -> u64
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { lhs.duplicate_async(streams) };
        unsafe {
            result = self.extend_radix_with_trivial_zero_blocks_msb_async(
                &result,
                lhs.as_ref().d_blocks.lwe_ciphertext_count().0,
                streams,
            );
        }
        streams.synchronize();
        let scalar_mul_size = self.get_scalar_mul_size_on_gpu(&result, rhs, streams);
        scalar_mul_size + self.get_ciphertext_size_on_gpu(&result)
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    unsafe fn signed_scalar_mul_high_async<Scalar>(
        &self,
        lhs: &CudaSignedRadixCiphertext,
        rhs: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let num_additional_blocks = lhs.as_ref().d_blocks.lwe_ciphertext_count().0;
        let mut result = self.extend_radix_with_sign_msb_async(lhs, num_additional_blocks, streams);
        self.scalar_mul_assign_async(&mut result, rhs, streams);
        self.trim_radix_blocks_lsb_async(&result, num_additional_blocks, streams)
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
        let numerator_bits = numerator
            .as_ref()
            .info
            .blocks
            .first()
            .unwrap()
            .message_modulus
            .0
            .ilog2()
            * numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
        >= to the number of bits encrypted in the ciphertext: \n\
        encrypted bits: {numerator_bits}, scalar bits: {}
        ",
            Scalar::BITS
        );

        let is_divisor_power_of_two = MiniUnsignedInteger::is_power_of_two(divisor);

        let log2_divisor_exceeds_threshold =
            MiniUnsignedInteger::ceil_ilog2(divisor) > numerator_bits;

        let ilog2_divisor = MiniUnsignedInteger::ilog2(divisor);

        let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

        let shift_pre = if chosen_multiplier.multiplier
            >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
            && crate::integer::server_key::radix_parallel::scalar_div_mod::is_even(divisor)
            && !is_divisor_power_of_two
            && !log2_divisor_exceeds_threshold
        {
            let divisor_dp = Scalar::DoublePrecision::cast_from(divisor);
            let two_pow_e = divisor_dp
                & ((Scalar::DoublePrecision::ONE << numerator_bits as usize) - divisor_dp);
            let e = MiniUnsignedInteger::ilog2(two_pow_e);
            let divisor_odd_dp = divisor_dp / two_pow_e;

            assert!(numerator_bits > e && e <= Scalar::BITS as u32);
            let divisor_odd: Scalar = divisor_odd_dp.cast_into();
            chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
            e as u64
        } else {
            0
        };

        let mut quotient = unsafe { numerator.duplicate_async(streams) };

        let multiplier_exceeds_threshold = chosen_multiplier.multiplier
            >= (Scalar::DoublePrecision::ONE << numerator_bits as usize);

        let rhs = if multiplier_exceeds_threshold {
            chosen_multiplier.multiplier - (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        } else {
            chosen_multiplier.multiplier
        };

        self.unchecked_unsigned_scalar_div_assign_async(
            &mut quotient,
            rhs,
            streams,
            multiplier_exceeds_threshold,
            is_divisor_power_of_two,
            log2_divisor_exceeds_threshold,
            ilog2_divisor,
            shift_pre,
            chosen_multiplier.shift_post,
        );

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
        let quotient = self.unchecked_scalar_div(numerator, divisor, streams);
        let remainder = if MiniUnsignedInteger::is_power_of_two(divisor) {
            // unchecked_scalar_div would have panicked if divisor was zero
            self.scalar_bitand(numerator, divisor - Scalar::ONE, streams)
        } else {
            // remainder = numerator - (quotient * divisor)
            let tmp = self.unchecked_scalar_mul(&quotient, divisor, streams);
            self.sub(numerator, &tmp, streams)
        };

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
        let quotient = self.unchecked_scalar_div_async(numerator, divisor, streams);
        let remainder = if MiniUnsignedInteger::is_power_of_two(divisor) {
            // unchecked_scalar_div would have panicked if divisor was zero
            let mut tmp = numerator.duplicate_async(streams);
            self.scalar_bitand_assign_async(&mut tmp, divisor - Scalar::ONE, streams);
            tmp
        } else {
            // remainder = numerator - (quotient * divisor)
            let mut tmp = quotient.duplicate_async(streams);
            self.unchecked_scalar_mul_assign_async(&mut tmp, divisor, streams);
            self.sub_async(numerator, &tmp, streams)
        };

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
        if MiniUnsignedInteger::is_power_of_two(divisor) {
            // The remainder is simply the bits that would get 'shifted out'
            let mut tmp = numerator.duplicate_async(streams);
            self.scalar_bitand_assign_async(&mut tmp, divisor - Scalar::ONE, streams);
            return tmp;
        }

        let (_, remainder) = self.unchecked_scalar_div_rem_async(numerator, divisor, streams);
        remainder
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

        // wrappings_abs returns Scalar::MIN when its input is Scalar::MIN (since in signed numbers
        // Scalar::MIN's absolute value cannot be represented.
        // However, casting Scalar::MIN to signed value will give the correct abs value
        // If Scalar and Scalar::Unsigned have the same number of bits
        let absolute_divisor = Scalar::Unsigned::cast_from(divisor.wrapping_abs());

        if absolute_divisor == Scalar::Unsigned::ONE {
            // Strangely, the paper says: Issue q = d;
            return if divisor < Scalar::ZERO {
                // quotient = -quotient;
                self.neg_async(numerator, streams)
            } else {
                numerator.duplicate_async(streams)
            };
        }

        let chosen_multiplier =
            choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);

        if chosen_multiplier.l >= numerator_bits {
            return self.create_trivial_zero_radix_async(
                numerator.ciphertext.d_blocks.lwe_ciphertext_count().0,
                streams,
            );
        }

        let quotient;
        if absolute_divisor == (Scalar::Unsigned::ONE << chosen_multiplier.l as usize) {
            // Issue q = SRA(n + SRL(SRA(n, l − 1), N − l), l);
            let l = chosen_multiplier.l;

            // SRA(n, l − 1)
            let mut tmp = self.unchecked_scalar_right_shift_async(numerator, l - 1, streams);

            // SRL(SRA(n, l − 1), N − l)
            self.unchecked_scalar_right_shift_logical_assign_async(
                &mut tmp,
                (numerator_bits - l) as usize,
                streams,
            );
            // n + SRL(SRA(n, l − 1), N − l)
            self.add_assign_async(&mut tmp, numerator, streams);
            // SRA(n + SRL(SRA(n, l − 1), N − l), l);
            quotient = self.unchecked_scalar_right_shift_async(&tmp, l, streams);
        } else if chosen_multiplier.multiplier
            < (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1))
        {
            // in the condition above works (it makes more values take this branch,
            // but results still seemed correct)

            // multiplier is less than the max possible value of Scalar
            // Issue q = SRA(MULSH(m, n), shpost) − XSIGN(n);

            let (mut tmp, xsign) = rayon::join(
                move || {
                    // MULSH(m, n)
                    let mut tmp = self.signed_scalar_mul_high_async(
                        numerator,
                        chosen_multiplier.multiplier,
                        streams,
                    );

                    // SRA(MULSH(m, n), shpost)
                    self.unchecked_scalar_right_shift_assign_async(
                        &mut tmp,
                        chosen_multiplier.shift_post,
                        streams,
                    );
                    tmp
                },
                || {
                    // XSIGN is: -1 if x < 0 { -1 } else { 0 }
                    // It is equivalent to SRA(x, N − 1)
                    self.unchecked_scalar_right_shift_async(numerator, numerator_bits - 1, streams)
                },
            );

            self.sub_assign_async(&mut tmp, &xsign, streams);
            quotient = tmp;
        } else {
            // Issue q = SRA(n + MULSH(m − 2^N , n), shpost) − XSIGN(n);
            // Note from the paper: m - 2^N is negative

            let (mut tmp, xsign) = rayon::join(
                move || {
                    // The subtraction may overflow.
                    // We then cast the result to a signed type.
                    // Overall, this will work fine due to two's complement representation
                    let cst = chosen_multiplier.multiplier
                        - (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE
                            << numerator_bits);
                    let cst = Scalar::DoublePrecision::cast_from(cst);

                    // MULSH(m - 2^N, n)
                    let mut tmp = self.signed_scalar_mul_high_async(numerator, cst, streams);

                    // n + MULSH(m − 2^N , n)
                    self.add_assign_async(&mut tmp, numerator, streams);

                    // SRA(n + MULSH(m - 2^N, n), shpost)
                    tmp = self.unchecked_scalar_right_shift_async(
                        &tmp,
                        chosen_multiplier.shift_post,
                        streams,
                    );

                    tmp
                },
                || {
                    // XSIGN is: -1 if x < 0 { -1 } else { 0 }
                    // It is equivalent to SRA(x, N − 1)
                    self.unchecked_scalar_right_shift_async(numerator, numerator_bits - 1, streams)
                },
            );

            self.sub_assign_async(&mut tmp, &xsign, streams);
            quotient = tmp;
        }

        if divisor < Scalar::ZERO {
            self.neg_async(&quotient, streams)
        } else {
            quotient
        }
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
        let quotient = self.unchecked_signed_scalar_div_async(numerator, divisor, streams);

        // remainder = numerator - (quotient * divisor)
        let mut tmp = quotient.duplicate_async(streams);
        self.unchecked_scalar_mul_assign_async(&mut tmp, divisor, streams);
        let remainder = self.sub_async(numerator, &tmp, streams);

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
        let numerator_bits = numerator
            .as_ref()
            .info
            .blocks
            .first()
            .unwrap()
            .message_modulus
            .0
            .ilog2()
            * numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        // Rust has a check on all division, so we shall also have one
        assert_ne!(divisor, Scalar::ZERO, "attempt to divide by 0");

        assert!(
            Scalar::BITS >= numerator_bits as usize,
            "The scalar divisor type must have a number of bits that is \
            >= to the number of bits encrypted in the ciphertext: \n\
            encrypted bits: {numerator_bits}, scalar bits: {}
            ",
            Scalar::BITS
        );

        let lwe_ciphertext_count = numerator.as_ref().d_blocks.lwe_ciphertext_count();

        let is_divisor_power_of_two = MiniUnsignedInteger::is_power_of_two(divisor);

        let log2_divisor_exceeds_threshold =
            MiniUnsignedInteger::ceil_ilog2(divisor) > numerator_bits;

        let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

        if chosen_multiplier.multiplier >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
            && crate::integer::server_key::radix_parallel::scalar_div_mod::is_even(divisor)
        {
            let divisor = Scalar::DoublePrecision::cast_from(divisor);
            // Find e such that d = (1 << e) * divisor_odd
            // where divisor_odd is odd
            let two_pow_e =
                divisor & ((Scalar::DoublePrecision::ONE << numerator_bits as usize) - divisor);
            let e = MiniUnsignedInteger::ilog2(two_pow_e);
            let divisor_odd = divisor / two_pow_e;

            assert!(numerator_bits > e && e <= Scalar::BITS as u32);
            let divisor_odd: Scalar = divisor_odd.cast_into(); // cast to lower precision
            chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
        }

        let multiplier_exceeds_threshold = chosen_multiplier.multiplier
            >= (Scalar::DoublePrecision::ONE << numerator_bits as usize);

        let rhs = if multiplier_exceeds_threshold {
            chosen_multiplier.multiplier - (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        } else {
            chosen_multiplier.multiplier
        };

        let ilog2_divisor = MiniUnsignedInteger::ilog2(divisor);

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
                rhs,
                self.message_modulus,
                self.carry_modulus,
                d_bsk.glwe_dimension,
                d_bsk.polynomial_size,
                self.key_switching_key
                    .output_key_lwe_size()
                    .to_lwe_dimension(),
                d_bsk.decomp_base_log,
                d_bsk.decomp_level_count,
                self.key_switching_key.decomposition_base_log(),
                self.key_switching_key.decomposition_level_count(),
                LweBskGroupingFactor(0),
                lwe_ciphertext_count.0 as u32,
                PBSType::Classical,
                is_divisor_power_of_two,
                log2_divisor_exceeds_threshold,
                multiplier_exceeds_threshold,
                ilog2_divisor,
                d_bsk.d_ms_noise_reduction_key.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                get_scalar_div_integer_radix_kb_size_on_gpu(
                    streams,
                    rhs,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.decomp_level_count,
                    self.key_switching_key.decomposition_base_log(),
                    self.key_switching_key.decomposition_level_count(),
                    d_multibit_bsk.grouping_factor,
                    lwe_ciphertext_count.0 as u32,
                    PBSType::MultiBit,
                    is_divisor_power_of_two,
                    log2_divisor_exceeds_threshold,
                    multiplier_exceeds_threshold,
                    ilog2_divisor,
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
        let scalar_div_size = self.get_scalar_div_size_on_gpu(numerator, divisor, streams);
        let remainder_size = if MiniUnsignedInteger::is_power_of_two(divisor) {
            self.get_scalar_bitand_size_on_gpu(numerator, streams)
        } else {
            let scalar_mul_size = self.get_scalar_mul_size_on_gpu(numerator, divisor, streams);
            let sub_size = self.get_sub_size_on_gpu(numerator, numerator, streams);
            scalar_mul_size.max(sub_size)
        };
        scalar_div_size.max(remainder_size) + self.get_ciphertext_size_on_gpu(numerator)
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
        Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
    {
        let numerator_bits = self.message_modulus.0.ilog2()
            * numerator.ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;

        let absolute_divisor = Scalar::Unsigned::cast_from(divisor.wrapping_abs());

        if absolute_divisor == Scalar::Unsigned::ONE {
            return if divisor < Scalar::ZERO {
                self.get_neg_size_on_gpu(numerator, streams)
            } else {
                0
            };
        }

        let chosen_multiplier =
            choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);

        if chosen_multiplier.l >= numerator_bits {
            return 0;
        }

        if absolute_divisor == (Scalar::Unsigned::ONE << chosen_multiplier.l as usize) {
            let scalar_right_shift_size =
                self.get_scalar_right_shift_size_on_gpu(numerator, streams);

            let add_size = self.get_add_size_on_gpu(numerator, numerator, streams);

            scalar_right_shift_size.max(add_size)
        } else if chosen_multiplier.multiplier
            < (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1))
        {
            let scalar_mul_high_size = self.get_scalar_mul_high_size_on_gpu(
                numerator,
                chosen_multiplier.multiplier,
                streams,
            );

            let scalar_right_shift_size =
                self.get_scalar_right_shift_size_on_gpu(numerator, streams);

            let sub_size = self.get_sub_size_on_gpu(numerator, numerator, streams);

            scalar_mul_high_size
                .max(scalar_right_shift_size)
                .max(sub_size)
        } else {
            let cst = chosen_multiplier.multiplier
                - (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits);
            let cst = Scalar::DoublePrecision::cast_from(cst);

            let scalar_mul_high_size =
                self.get_scalar_mul_high_size_on_gpu(numerator, cst, streams);

            let add_size = self.get_add_size_on_gpu(numerator, numerator, streams);

            let scalar_right_shift_size =
                self.get_scalar_right_shift_size_on_gpu(numerator, streams);

            scalar_mul_high_size
                .max(add_size)
                .max(scalar_right_shift_size)
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
        let scalar_div_size = self.get_signed_scalar_div_size_on_gpu(numerator, divisor, streams)
            + self.get_ciphertext_size_on_gpu(numerator);

        let scalar_mul_size = self.get_scalar_mul_size_on_gpu(numerator, divisor, streams)
            + self.get_ciphertext_size_on_gpu(numerator);
        let sub_size = self.get_sub_size_on_gpu(numerator, numerator, streams);

        scalar_div_size.max(scalar_mul_size).max(sub_size)
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

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn unchecked_unsigned_scalar_div_assign_async<Scalar, T>(
        &self,
        numerator: &mut T,
        rhs: Scalar,
        streams: &CudaStreams,
        multiplier_exceeds_threshold: bool,
        is_divisor_power_of_two: bool,
        log2_divisor_exceeds_threshold: bool,
        ilog2_divisor: u32,
        shift_pre: u64,
        shift_post: u32,
    ) where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let lwe_dimension = self
            .key_switching_key
            .output_key_lwe_size()
            .to_lwe_dimension();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_unsigned_scalar_div_integer_radix_kb_assign_async(
                    streams,
                    numerator.as_mut(),
                    rhs,
                    self.message_modulus.0.ilog2() as usize,
                    &self.key_switching_key.d_vec,
                    &d_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    num_blocks,
                    multiplier_exceeds_threshold,
                    is_divisor_power_of_two,
                    log2_divisor_exceeds_threshold,
                    ilog2_divisor,
                    shift_pre,
                    shift_post,
                    PBSType::Classical,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_unsigned_scalar_div_integer_radix_kb_assign_async(
                    streams,
                    numerator.as_mut(),
                    rhs,
                    self.message_modulus.0.ilog2() as usize,
                    &self.key_switching_key.d_vec,
                    &d_multibit_bsk.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                    multiplier_exceeds_threshold,
                    is_divisor_power_of_two,
                    log2_divisor_exceeds_threshold,
                    ilog2_divisor,
                    shift_pre,
                    shift_post,
                    PBSType::MultiBit,
                    None,
                );
            }
        }
    }
}
