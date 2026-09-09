//! Fixed-point fused multiply-add with an asymmetric right operand.
//!
//! These are the two multiplications a Goldschmidt divider needs. Both share
//! the invariant that makes the shape tractable: **the result is exactly as
//! wide as the left operand**, so the output width is never a parameter. The
//! right operand is the short one - the iteration factor, a handful of blocks
//! against the running numerator's tens of blocks.
//!
//! The low columns of the product whose worst-case weight stays below one
//! output ulp are never bootstrapped, which is what keeps the block-product
//! count down to what the CPU implementation performs.

use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaRadixCiphertext};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::integer::gpu::{
    cuda_backend_mul_add_fixed_point_with_rescaling, cuda_backend_mul_low_partial_sum,
};

impl CudaServerKey {
    /// Computes, over a radix of base `beta = message_modulus`:
    ///
    /// ```text
    ///     result[L] = trunc_beta^s( lhs[L] * rhs[R] + added[L] * beta^s )
    /// ```
    ///
    /// where `L = lhs.blocks()`, `R = rhs.blocks()` and `s = R + rescaling` is
    /// the number of low blocks dropped from the product, so that `result` has
    /// as many blocks as `lhs`.
    ///
    /// `precision` is the weight, in bits, of one output ulp: the low columns
    /// of the product whose combined worst case stays below `2^precision` are
    /// skipped entirely. The result is therefore the exact value or one ulp
    /// below it, never above.
    ///
    /// # Panics
    ///
    /// Panics if `rescaling` pushes the truncation threshold into the retained
    /// output blocks, or if either operand holds a block with a non-empty
    /// carry.
    pub fn mul_add_fixed_point_with_rescaling<T: CudaIntegerRadixCiphertext>(
        &self,
        lhs: &T,
        rhs: &T,
        added: Option<&T>,
        rescaling: u32,
        precision: u32,
        streams: &CudaStreams,
    ) -> T {
        let lhs_blocks = lhs.as_ref().d_blocks.lwe_ciphertext_count().0;
        assert!(
            rhs.as_ref().d_blocks.lwe_ciphertext_count().0 <= lhs_blocks,
            "The right operand must not be wider than the left one"
        );
        if let Some(added) = added {
            assert_eq!(
                added.as_ref().d_blocks.lwe_ciphertext_count().0,
                lhs_blocks,
                "The accumulator operand must have as many blocks as the left operand"
            );
        }

        let mut result: T = self.create_trivial_zero_radix(lhs_blocks, streams);
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_mul_add_fixed_point_with_rescaling(
                        streams,
                        result.as_mut(),
                        lhs.as_ref(),
                        rhs.as_ref(),
                        added.map(|a| a.as_ref()),
                        rescaling,
                        precision,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk,
                        computing_ks_key.params_ffi(),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_mul_add_fixed_point_with_rescaling(
                        streams,
                        result.as_mut(),
                        lhs.as_ref(),
                        rhs.as_ref(),
                        added.map(|a| a.as_ref()),
                        rescaling,
                        precision,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk,
                        computing_ks_key.params_ffi(),
                        None,
                    );
                }
            }
        }
        streams.synchronize();
        result
    }

    /// [`Self::mul_add_fixed_point_with_rescaling`] with no rescaling, i.e.
    /// `result[L] = trunc_beta^R(lhs[L] * rhs[R] + added[L] * beta^R)`.
    pub fn mul_add_fixed_point<T: CudaIntegerRadixCiphertext>(
        &self,
        lhs: &T,
        rhs: &T,
        added: Option<&T>,
        precision: u32,
        streams: &CudaStreams,
    ) -> T {
        self.mul_add_fixed_point_with_rescaling(lhs, rhs, added, 0, precision, streams)
    }

    /// Low half of `lhs * rhs` plus `extra_terms`, all of the same width:
    ///
    /// ```text
    ///     result[n] = (lhs[n] * rhs[n] + sum(extra_terms)) mod beta^n
    /// ```
    ///
    /// With `propagate_carries` the result comes back with clean carries. Left
    /// unset, it is the raw column sum - blocks may hold non-empty carries -
    /// which is what a Goldschmidt remainder step wants, since it inverts the
    /// message and carry halves itself rather than propagating them.
    pub fn mul_low_partial_sum<T: CudaIntegerRadixCiphertext>(
        &self,
        lhs: &T,
        rhs: &T,
        extra_terms: &[T],
        propagate_carries: bool,
        streams: &CudaStreams,
    ) -> T {
        let num_blocks = lhs.as_ref().d_blocks.lwe_ciphertext_count().0;
        assert_eq!(
            rhs.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_blocks,
            "The mul-low shape expects two operands of the same width"
        );
        assert!(
            extra_terms
                .iter()
                .all(|t| t.as_ref().d_blocks.lwe_ciphertext_count().0 == num_blocks),
            "Every extra term must have as many blocks as the operands"
        );

        let mut result: T = self.create_trivial_zero_radix(num_blocks, streams);
        let extra_list = if extra_terms.is_empty() {
            None
        } else {
            Some(CudaRadixCiphertext::from_radix_ciphertext_vec(
                extra_terms,
                streams,
            ))
        };
        let num_extra_terms = u32::try_from(extra_terms.len()).unwrap();

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_mul_low_partial_sum(
                        streams,
                        result.as_mut(),
                        lhs.as_ref(),
                        rhs.as_ref(),
                        extra_list.as_ref(),
                        num_extra_terms,
                        propagate_carries,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk,
                        computing_ks_key.params_ffi(),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_mul_low_partial_sum(
                        streams,
                        result.as_mut(),
                        lhs.as_ref(),
                        rhs.as_ref(),
                        extra_list.as_ref(),
                        num_extra_terms,
                        propagate_carries,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk,
                        computing_ks_key.params_ffi(),
                        None,
                    );
                }
            }
        }
        streams.synchronize();
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use crate::integer::gpu::server_key::CudaServerKey;
    use crate::integer::{ClientKey, RadixClientKey};
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use rand::Rng;

    const BITS_PER_BLOCK: u32 = 2;

    /// The five shapes the Goldschmidt divider drives these operations with, for
    /// u64 operands at 2 bits per block: (lhs blocks, rhs blocks, rescaling,
    /// precision bits). Fixed point is 34 blocks; the schedule (s, t) is
    /// (5, 9), (9, 17), (16, 32) after the seed step.
    fn fixed_point_shapes() -> Vec<(usize, usize, u32, u32)> {
        vec![
            (34, 5, 0, 10),   // seed: n, d <- n, d * (1 + x0)
            (34, 5, 4, 18),   // iteration 0
            (34, 9, 8, 34),   // iteration 1
            (34, 16, 16, 64), // iteration 2 (numerator only)
        ]
    }

    fn keys(
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> (ClientKey, RadixClientKey, CudaServerKey) {
        let cks = RadixClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks);
        let sks = CudaServerKey::new(&cks, streams);
        (cks.as_ref().clone(), cks, sks)
    }

    /// Exact reference for `(lhs * rhs + added * beta^s) >> s`.
    ///
    /// Written as `added + (lhs * rhs) >> s` rather than shifting `added` up
    /// first: the two are equal because `added * beta^s` is a multiple of
    /// `beta^s`, and this form stays inside u128 (`added << 64` would not for
    /// the last iteration's shape).
    fn reference(lhs: u128, rhs: u128, added: Option<u128>, shift_blocks: u32) -> u128 {
        let shift_bits = shift_blocks * BITS_PER_BLOCK;
        added.unwrap_or(0) + ((lhs * rhs) >> shift_bits)
    }

    #[test]
    fn test_mul_add_fixed_point_with_rescaling_goldschmidt_shapes() {
        let streams = CudaStreams::new_multi_gpu();
        let mut rng = rand::thread_rng();

        for (lhs_blocks, rhs_blocks, rescaling, precision) in fixed_point_shapes() {
            let (cpu_cks, _cks, sks) = keys(lhs_blocks, &streams);
            let shift_blocks = rhs_blocks as u32 + rescaling;

            for with_added in [false, true] {
                for _ in 0..3 {
                    // Keep the accumulator inside its beta^W window, exactly as the
                    // divider does: n * (1 + x) < beta^L holds there because
                    // n < beta^L / 2.
                    let lhs_bits = lhs_blocks as u32 * BITS_PER_BLOCK - 1;
                    let clear_lhs: u128 = rng.gen_range(0..(1u128 << lhs_bits));
                    let clear_rhs: u128 =
                        rng.gen_range(0..(1u128 << (rhs_blocks as u32 * BITS_PER_BLOCK)));
                    let clear_added = if with_added { Some(clear_lhs) } else { None };

                    let ct_lhs = cpu_cks.encrypt_radix(clear_lhs, lhs_blocks);
                    let ct_rhs = cpu_cks.encrypt_radix(clear_rhs, rhs_blocks);
                    let d_lhs =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_lhs, &streams);
                    let d_rhs =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_rhs, &streams);
                    let d_added = clear_added.map(|v| {
                        let ct = cpu_cks.encrypt_radix(v, lhs_blocks);
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams)
                    });

                    let d_res = sks.mul_add_fixed_point_with_rescaling(
                        &d_lhs,
                        &d_rhs,
                        d_added.as_ref(),
                        rescaling,
                        precision,
                        &streams,
                    );
                    let res: u128 = cpu_cks.decrypt_radix(&d_res.to_radix_ciphertext(&streams));

                    let expected = reference(clear_lhs, clear_rhs, clear_added, shift_blocks);
                    assert!(
                        res <= expected && expected - res <= 1,
                        "shape L={lhs_blocks} R={rhs_blocks} rescaling={rescaling} \
                         precision={precision} added={with_added}: got {res}, expected \
                         {expected} (truncation may only lose one ulp, and only downwards)"
                    );
                }
            }
        }
    }

    /// The seed step and the three iterations all keep `d` in [1/2, 1) and
    /// `1 + x` in [1, 2). This drives the operation with operands of that
    /// shape rather than uniform ones, since that is where the divider lives.
    #[test]
    fn test_mul_add_fixed_point_normalized_operands() {
        let streams = CudaStreams::new_multi_gpu();
        let mut rng = rand::thread_rng();
        let lhs_blocks = 34usize;
        let (cpu_cks, _cks, sks) = keys(lhs_blocks, &streams);

        for (rhs_blocks, rescaling, precision) in [(5usize, 0u32, 10u32), (16, 16, 64)] {
            let shift_blocks = rhs_blocks as u32 + rescaling;
            // d in [1/2, 1) as a Q0.68 fixed point: the top bit of the 68-bit
            // field is set.
            let clear_lhs: u128 = (1u128 << 67) | (rng.gen::<u128>() & ((1u128 << 67) - 1));
            let clear_rhs: u128 = rng.gen_range(0..(1u128 << (rhs_blocks as u32 * BITS_PER_BLOCK)));

            let ct_lhs = cpu_cks.encrypt_radix(clear_lhs, lhs_blocks);
            let ct_rhs = cpu_cks.encrypt_radix(clear_rhs, rhs_blocks);
            let d_lhs = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_lhs, &streams);
            let d_rhs = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_rhs, &streams);

            let d_res = sks.mul_add_fixed_point_with_rescaling(
                &d_lhs, &d_rhs, None, rescaling, precision, &streams,
            );
            let res: u128 = cpu_cks.decrypt_radix(&d_res.to_radix_ciphertext(&streams));
            let expected = reference(clear_lhs, clear_rhs, None, shift_blocks);
            assert!(
                res <= expected && expected - res <= 1,
                "R={rhs_blocks} rescaling={rescaling}: got {res}, expected {expected}"
            );
        }
    }

    #[test]
    fn test_mul_low_partial_sum() {
        let streams = CudaStreams::new_multi_gpu();
        let mut rng = rand::thread_rng();
        let num_blocks = 32usize;
        let (cpu_cks, _cks, sks) = keys(num_blocks, &streams);

        for num_extra in [0usize, 1, 2] {
            for _ in 0..2 {
                let clear_lhs: u64 = rng.gen();
                let clear_rhs: u64 = rng.gen();
                let clear_extras: Vec<u64> = (0..num_extra).map(|_| rng.gen()).collect();

                let ct_lhs = cpu_cks.encrypt_radix(clear_lhs, num_blocks);
                let ct_rhs = cpu_cks.encrypt_radix(clear_rhs, num_blocks);
                let d_lhs = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_lhs, &streams);
                let d_rhs = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_rhs, &streams);
                let d_extras: Vec<CudaUnsignedRadixCiphertext> = clear_extras
                    .iter()
                    .map(|v| {
                        let ct = cpu_cks.encrypt_radix(*v, num_blocks);
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams)
                    })
                    .collect();

                let d_res = sks.mul_low_partial_sum(&d_lhs, &d_rhs, &d_extras, true, &streams);
                let res: u64 = cpu_cks.decrypt_radix(&d_res.to_radix_ciphertext(&streams));

                let expected = clear_extras
                    .iter()
                    .fold(clear_lhs.wrapping_mul(clear_rhs), |acc, e| {
                        acc.wrapping_add(*e)
                    });
                assert_eq!(
                    res, expected,
                    "mul-low with {num_extra} extra terms: {clear_lhs} * {clear_rhs} + \
                     {clear_extras:?}"
                );
            }
        }
    }

    /// The exact term list the Goldschmidt remainder step builds:
    /// `q * d + !n + 1`, whose two's complement is `n - q * d`.
    #[test]
    fn test_mul_low_partial_sum_remainder_terms() {
        let streams = CudaStreams::new_multi_gpu();
        let num_blocks = 32usize;
        let (cpu_cks, _cks, sks) = keys(num_blocks, &streams);

        for (n, d) in [
            (12_345_678_901_234_567u64, 987_654_321u64),
            (u64::MAX, 3),
            (1024, 16),
            (0, 7),
        ] {
            let q = n / d;
            let ct_q = cpu_cks.encrypt_radix(q, num_blocks);
            let ct_d = cpu_cks.encrypt_radix(d, num_blocks);
            let ct_not_n = cpu_cks.encrypt_radix(!n, num_blocks);
            let ct_one = cpu_cks.encrypt_radix(1u64, num_blocks);

            let d_q = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_q, &streams);
            let d_d = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_d, &streams);
            let d_extras = vec![
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_not_n, &streams),
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_one, &streams),
            ];

            let d_res = sks.mul_low_partial_sum(&d_q, &d_d, &d_extras, true, &streams);
            let res: u64 = cpu_cks.decrypt_radix(&d_res.to_radix_ciphertext(&streams));

            // q*d + !n + 1 == q*d - n, so the remainder is its negation.
            let expected = q.wrapping_mul(d).wrapping_sub(n);
            assert_eq!(res, expected, "remainder terms for {n} / {d}");
            assert_eq!(
                res.wrapping_neg(),
                n - q * d,
                "negating the term sum should give the remainder for {n} / {d}"
            );
        }
    }
}
