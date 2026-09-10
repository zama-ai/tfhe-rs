//! Goldschmidt division.
//!
//! Divides by iterating a fixed-point reciprocal instead of doing long
//! division, trading a sequential step per bit for a handful of wide
//! multiplications. Both operands are rescaled so the denominator lands in
//! [1/2, 1), then a 512-entry table seeds `1 + x0 ~ 1/d` to 9 bits and three
//! rounds of `d <- d * (1 + x)` with `x = 1 - d` double the correct bits each
//! time, driving `d` to 1 and the numerator to the quotient.
//!
//! Every truncation rounds down and `d` stays below 1 throughout, so the
//! quotient never overshoots; a single `+1` correction, decided by whether the
//! recovered remainder still reaches the denominator, makes it exact.

use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::cuda_backend_goldschmidt_division;
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};

impl CudaServerKey {
    /// Computes the quotient and remainder of `numerator / denominator`.
    ///
    /// Only 64-bit unsigned operands at 2 bits per block are supported - that
    /// is the shape the truncation schedule is proved for.
    ///
    /// When the denominator is zero the quotient is all ones and the remainder
    /// is the numerator, matching [`Self::div_rem`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(0));
    /// let num_blocks = 32;
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     num_blocks,
    ///     &streams,
    /// );
    ///
    /// let n = 1003u64;
    /// let d = 7u64;
    /// let ct_n = cks.encrypt(n);
    /// let ct_d = cks.encrypt(d);
    /// let d_n = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_n, &streams);
    /// let d_d = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_d, &streams);
    ///
    /// let (d_q, d_r) = sks.goldschmidt_division(&d_n, &d_d, &streams);
    /// let q: u64 = cks.decrypt(&d_q.to_radix_ciphertext(&streams));
    /// let r: u64 = cks.decrypt(&d_r.to_radix_ciphertext(&streams));
    /// assert_eq!((q, r), (n / d, n % d));
    /// ```
    pub fn goldschmidt_division<T: CudaIntegerRadixCiphertext>(
        &self,
        numerator: &T,
        denominator: &T,
        streams: &CudaStreams,
    ) -> (T, T) {
        assert!(
            T::IS_SIGNED == false,
            "Goldschmidt division is only implemented for unsigned integers"
        );
        assert_eq!(
            self.message_modulus.0, 4,
            "Goldschmidt division requires 2 bits per block"
        );
        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0;
        assert_eq!(
            denominator.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_blocks,
            "Numerator and denominator must have the same number of blocks"
        );
        assert_eq!(
            num_blocks * self.message_modulus.0.ilog2() as usize,
            64,
            "Goldschmidt division is only implemented for 64-bit operands"
        );

        let mut quotient: T = self.create_trivial_zero_radix(num_blocks, streams);
        let mut remainder: T = self.create_trivial_zero_radix(num_blocks, streams);

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_goldschmidt_division(
                        streams,
                        quotient.as_mut(),
                        remainder.as_mut(),
                        numerator.as_ref(),
                        denominator.as_ref(),
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk,
                        computing_ks_key.params_ffi(),
                        num_blocks as u32,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_goldschmidt_division(
                        streams,
                        quotient.as_mut(),
                        remainder.as_mut(),
                        numerator.as_ref(),
                        denominator.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk,
                        computing_ks_key.params_ffi(),
                        num_blocks as u32,
                        None,
                    );
                }
            }
        }
        streams.synchronize();
        (quotient, remainder)
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

    const NUM_BLOCKS: usize = 32;

    fn keys(streams: &CudaStreams) -> (ClientKey, CudaServerKey) {
        let cks = RadixClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, NUM_BLOCKS);
        let sks = CudaServerKey::new(&cks, streams);
        (cks.as_ref().clone(), sks)
    }

    fn check(cks: &ClientKey, sks: &CudaServerKey, streams: &CudaStreams, n: u64, d: u64) {
        let ct_n = cks.encrypt_radix(n, NUM_BLOCKS);
        let ct_d = cks.encrypt_radix(d, NUM_BLOCKS);
        let d_n = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_n, streams);
        let d_d = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_d, streams);

        let (d_q, d_r) = sks.goldschmidt_division(&d_n, &d_d, streams);
        let q: u64 = cks.decrypt_radix(&d_q.to_radix_ciphertext(streams));
        let r: u64 = cks.decrypt_radix(&d_r.to_radix_ciphertext(streams));

        // A zero denominator returns the all-ones quotient and the numerator.
        let (expected_q, expected_r) = if d == 0 {
            (u64::MAX, n)
        } else {
            (n / d, n % d)
        };
        assert_eq!(
            (q, r),
            (expected_q, expected_r),
            "{n} / {d}: got q={q} r={r}, expected q={expected_q} r={expected_r}"
        );
    }

    #[test]
    fn test_goldschmidt_division_edge_cases() {
        let streams = CudaStreams::new_multi_gpu();
        let (cks, sks) = keys(&streams);

        for (n, d) in [
            (1003u64, 7u64),
            (1024, 16), // exact
            (0, 123),   // zero numerator
            (3, 2),
            (2, 3),         // quotient zero
            (12345, 12345), // equal
            (42, 1),
            (u64::MAX, 1),
            (u64::MAX, 2),
            (u64::MAX, u64::MAX),
            (u64::MAX - 1, u64::MAX),
            (u64::MAX, u64::MAX - 1),
            (1 << 63, 1),
            (1 << 63, 1 << 62),
            ((1 << 63) - 1, 1 << 62),
            (123_456_789, 256), // power-of-two denominator
            (1_000_001, 1_000_000),
            (1_000_000, 1_000_001),
            // division by zero
            (0, 0),
            (123, 0),
            (u64::MAX, 0),
        ] {
            check(&cks, &sks, &streams, n, d);
        }
    }

    /// Exact multiples are the worst case for the single `+1` correction: the
    /// fixed-point result lands exactly on an integer, so any downward error
    /// forces the correction to fire. Denominators whose normalised top ten
    /// bits are `0b1000000000` maximise the seed's error, so they are swept at
    /// every shift position.
    #[test]
    fn test_goldschmidt_division_correction_boundary() {
        let streams = CudaStreams::new_multi_gpu();
        let (cks, sks) = keys(&streams);
        let mut rng = rand::thread_rng();

        for j in 0..16 {
            let d = (((1u64 << 63) + (rng.gen::<u64>() >> 11)) >> (j * 4)).max(1);
            let q = (u64::MAX / d).max(1);
            check(&cks, &sks, &streams, q.wrapping_mul(d), d);
            check(&cks, &sks, &streams, q.wrapping_mul(d) - 1, d);
        }
    }

    #[test]
    fn test_goldschmidt_division_random() {
        let streams = CudaStreams::new_multi_gpu();
        let (cks, sks) = keys(&streams);
        let mut rng = rand::thread_rng();

        // A spread of operand magnitudes, since the error budget depends on how
        // many significant bits the denominator has.
        for n_bits in [8u32, 32, 64] {
            for d_bits in [4u32, 20, 40, 64] {
                let n_max = if n_bits == 64 {
                    u64::MAX
                } else {
                    (1u64 << n_bits) - 1
                };
                let d_max = if d_bits == 64 {
                    u64::MAX
                } else {
                    (1u64 << d_bits) - 1
                };
                let n = rng.gen_range(0..=n_max);
                let d = rng.gen_range(1..=d_max);
                check(&cks, &sks, &streams, n, d);
            }
        }
    }

    /// The GPU result must agree with the CPU backend block for block, not just
    /// on the decrypted value.
    #[test]
    fn test_goldschmidt_division_matches_cpu_div_rem() {
        use crate::integer::gen_keys_radix;

        let streams = CudaStreams::new_multi_gpu();
        let (cpu_cks, cpu_sks) =
            gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, NUM_BLOCKS);
        let sks = CudaServerKey::new(&cpu_cks, &streams);
        let mut rng = rand::thread_rng();

        for _ in 0..4 {
            let n: u64 = rng.gen();
            let d: u64 = rng.gen_range(1..=u64::MAX);

            let ct_n = cpu_cks.encrypt(n);
            let ct_d = cpu_cks.encrypt(d);
            let (cpu_q, cpu_r) = cpu_sks.div_rem_parallelized(&ct_n, &ct_d);

            let d_n = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_n, &streams);
            let d_d = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_d, &streams);
            let (d_q, d_r) = sks.goldschmidt_division(&d_n, &d_d, &streams);

            let gpu_q: u64 = cpu_cks.decrypt(&d_q.to_radix_ciphertext(&streams));
            let gpu_r: u64 = cpu_cks.decrypt(&d_r.to_radix_ciphertext(&streams));
            let cpu_q: u64 = cpu_cks.decrypt(&cpu_q);
            let cpu_r: u64 = cpu_cks.decrypt(&cpu_r);
            assert_eq!((gpu_q, gpu_r), (cpu_q, cpu_r), "disagreement on {n} / {d}");
        }
    }
}
