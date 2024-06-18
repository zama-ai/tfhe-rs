use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::Numeric;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::scalar_div_mod::{
    choose_multiplier, SignedReciprocable,
};
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

    fn signed_scalar_mul_high<Scalar>(
        &self,
        lhs: &CudaSignedRadixCiphertext,
        rhs: Scalar,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    {
        let num_blocks = lhs.as_ref().d_blocks.lwe_ciphertext_count().0;
        let mut result = self.extend_radix_with_sign_msb(lhs, num_blocks, streams);
        self.scalar_mul_assign(&mut result, rhs, streams);
        self.trim_radix_blocks_lsb(&result, num_blocks, streams)
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
                self.neg(numerator, streams)
            } else {
                numerator.duplicate(streams)
            };
        }

        let chosen_multiplier =
            choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);

        if chosen_multiplier.l >= numerator_bits {
            return self.create_trivial_zero_radix(
                numerator.ciphertext.d_blocks.lwe_ciphertext_count().0,
                streams,
            );
        }

        let quotient;
        if absolute_divisor == (Scalar::Unsigned::ONE << chosen_multiplier.l as usize) {
            // Issue q = SRA(n + SRL(SRA(n, l − 1), N − l), l);
            let l = chosen_multiplier.l;

            // SRA(n, l − 1)
            let mut tmp = self.unchecked_scalar_right_shift(numerator, l - 1, streams);

            // SRL(SRA(n, l − 1), N − l)
            unsafe {
                self.unchecked_scalar_right_shift_logical_assign_async(
                    &mut tmp,
                    (numerator_bits - l) as usize,
                    streams,
                );
            }
            streams.synchronize();
            // n + SRL(SRA(n, l − 1), N − l)
            self.add_assign(&mut tmp, numerator, streams);
            // SRA(n + SRL(SRA(n, l − 1), N − l), l);
            quotient = self.unchecked_scalar_right_shift(&tmp, l, streams);
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
                    let mut tmp = self.signed_scalar_mul_high(
                        numerator,
                        chosen_multiplier.multiplier,
                        streams,
                    );

                    // SRA(MULSH(m, n), shpost)
                    unsafe {
                        self.unchecked_scalar_right_shift_assign_async(
                            &mut tmp,
                            chosen_multiplier.shift_post,
                            streams,
                        );
                    }
                    streams.synchronize();
                    tmp
                },
                || {
                    // XSIGN is: -1 if x < 0 { -1 } else { 0 }
                    // It is equivalent to SRA(x, N − 1)
                    self.unchecked_scalar_right_shift(numerator, numerator_bits - 1, streams)
                },
            );

            self.sub_assign(&mut tmp, &xsign, streams);
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
                    let mut tmp = self.signed_scalar_mul_high(numerator, cst, streams);

                    // n + MULSH(m − 2^N , n)
                    self.add_assign(&mut tmp, numerator, streams);

                    // SRA(n + MULSH(m - 2^N, n), shpost)
                    tmp = self.unchecked_scalar_right_shift(
                        &tmp,
                        chosen_multiplier.shift_post,
                        streams,
                    );

                    tmp
                },
                || {
                    // XSIGN is: -1 if x < 0 { -1 } else { 0 }
                    // It is equivalent to SRA(x, N − 1)
                    self.unchecked_scalar_right_shift(numerator, numerator_bits - 1, streams)
                },
            );

            self.sub_assign(&mut tmp, &xsign, streams);
            quotient = tmp;
        }

        if divisor < Scalar::ZERO {
            self.neg(&quotient, streams)
        } else {
            quotient
        }
    }

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

        self.unchecked_signed_scalar_div(numerator, divisor, streams)
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
        let quotient = self.unchecked_signed_scalar_div(numerator, divisor, streams);

        // remainder = numerator - (quotient * divisor)
        let tmp = self.unchecked_scalar_mul(&quotient, divisor, streams);
        let remainder = self.sub(numerator, &tmp, streams);

        (quotient, remainder)
    }

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

        self.unchecked_signed_scalar_div_rem(numerator, divisor, streams)
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
        let (_, remainder) = self.unchecked_signed_scalar_div_rem(numerator, divisor, streams);

        remainder
    }

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

        self.unchecked_signed_scalar_rem(numerator, divisor, streams)
    }
}
