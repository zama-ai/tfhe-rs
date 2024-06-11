use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::Numeric;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::scalar_div_mod::choose_multiplier;
use crate::integer::server_key::{MiniUnsignedInteger, Reciprocable, ScalarMultiplier};
use crate::prelude::{CastFrom, CastInto};

impl CudaServerKey {
    fn scalar_mul_high<Scalar>(
        &self,
        lhs: &CudaUnsignedRadixCiphertext,
        rhs: Scalar,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let mut result = lhs.duplicate(streams);
        result = self.extend_radix_with_trivial_zero_blocks_msb(
            &result,
            lhs.ciphertext.d_blocks.lwe_ciphertext_count().0,
            streams,
        );
        self.scalar_mul_assign(&mut result, rhs, streams);
        result = self.trim_radix_blocks_lsb(
            &result,
            lhs.ciphertext.d_blocks.lwe_ciphertext_count().0,
            streams,
        );
        result
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
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut streams);
    ///
    /// // Compute homomorphically a scalar division:
    /// let d_ct_res = sks.unchecked_scalar_div(&d_ct, scalar, &mut streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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

        if MiniUnsignedInteger::is_power_of_two(divisor) {
            // Even in FHE, shifting is faster than multiplying / dividing
            return self.unchecked_scalar_right_shift(
                numerator,
                MiniUnsignedInteger::ilog2(divisor) as u64,
                streams,
            );
        }

        let log2_divisor = MiniUnsignedInteger::ceil_ilog2(divisor);
        if log2_divisor > numerator_bits {
            return self.create_trivial_zero_radix(
                numerator.as_ref().d_blocks.lwe_ciphertext_count().0,
                streams,
            );
        }

        let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

        let shift_pre = if chosen_multiplier.multiplier
            >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
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
            e as u64
        } else {
            0
        };

        if chosen_multiplier.multiplier >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        {
            assert!(shift_pre == 0);

            let inverse = chosen_multiplier.multiplier
                - (Scalar::DoublePrecision::ONE << numerator_bits as usize);
            let t1 = self.scalar_mul_high(numerator, inverse, streams);

            // Compute: quotient = (t1 + ((numerator - t1) >> 1)) >> sh_post -1)
            assert_eq!(
                t1.as_ref().d_blocks.lwe_ciphertext_count().0,
                numerator.as_ref().d_blocks.lwe_ciphertext_count().0
            );
            // Due to the use of a shifts, we can't use unchecked_add/sub
            let mut quotient = self.sub(numerator, &t1, streams);
            unsafe {
                self.unchecked_scalar_right_shift_assign_async(&mut quotient, 1, streams);
            }
            self.add_assign(&mut quotient, &t1, streams);
            assert!(chosen_multiplier.shift_post > 0);

            unsafe {
                self.unchecked_scalar_right_shift_assign_async(
                    &mut quotient,
                    chosen_multiplier.shift_post as u64 - 1,
                    streams,
                );
            }
            streams.synchronize();
            quotient
        } else {
            let shifted_n = self.unchecked_scalar_right_shift(numerator, shift_pre, streams);
            let mut quotient =
                self.scalar_mul_high(&shifted_n, chosen_multiplier.multiplier, streams);
            unsafe {
                self.unchecked_scalar_right_shift_assign_async(
                    &mut quotient,
                    chosen_multiplier.shift_post as u64,
                    streams,
                );
            }
            streams.synchronize();
            quotient
        }
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
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.scalar_div(&d_ct, scalar, &mut streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            unsafe {
                tmp_numerator = numerator.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_numerator, streams);
            }
            &tmp_numerator
        };

        self.unchecked_scalar_div(numerator, divisor, streams)
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
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let (d_ct_q, d_ct_r) = sks.scalar_div_rem(&d_ct, scalar, &mut streams);
    /// let ct_q = d_ct_q.to_radix_ciphertext(&mut streams);
    /// let ct_r = d_ct_r.to_radix_ciphertext(&mut streams);
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
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            unsafe {
                tmp_numerator = numerator.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_numerator, streams);
            }
            &tmp_numerator
        };

        self.unchecked_scalar_div_rem(numerator, divisor, streams)
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
        if MiniUnsignedInteger::is_power_of_two(divisor) {
            // The remainder is simply the bits that would get 'shifted out'
            return self.scalar_bitand(numerator, divisor - Scalar::ONE, streams);
        }

        let (_quotient, remainder) = self.unchecked_scalar_div_rem(numerator, divisor, streams);
        remainder
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
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut streams);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.scalar_rem(&d_ct, scalar, &mut streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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
        let mut tmp_numerator;
        let numerator = if numerator.block_carries_are_empty() {
            numerator
        } else {
            unsafe {
                tmp_numerator = numerator.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_numerator, streams);
            }
            &tmp_numerator
        };

        self.unchecked_scalar_rem(numerator, divisor, streams)
    }
}
