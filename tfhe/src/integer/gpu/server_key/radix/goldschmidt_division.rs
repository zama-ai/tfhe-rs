use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::{
    cuda_backend_goldschmidt_division, cuda_backend_mul_add_fixed_point_with_rescaling, PBSType,
};

impl CudaServerKey {
    /// Computes the division of two encrypted integers using the Goldschmidt algorithm.
    ///
    /// Returns a tuple containing (quotient, remainder).
    ///
    /// # Arguments
    /// * `numerator` - The encrypted numerator.
    /// * `denominator` - The encrypted denominator.
    /// * `iterations` - The number of iterations for the convergence.
    /// * `lut_precision` - The bit precision of the initial approximation LUT (must be odd).
    /// * `streams` - The CUDA streams to use for execution.
    pub fn goldschmidt_division(
        &self,
        numerator: &CudaUnsignedRadixCiphertext,
        denominator: &CudaUnsignedRadixCiphertext,
        iterations: usize,
        lut_precision: usize,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext) {
        assert_eq!(lut_precision % 2, 1, "lut_precision must be odd");
        assert_eq!(
            self.message_modulus.0, 4,
            "Message modulus must be 4 (2 bits per block) for Goldschmidt division"
        );

        let num_blocks = numerator.as_ref().d_blocks.lwe_ciphertext_count().0;
        assert_eq!(
            num_blocks,
            denominator.as_ref().d_blocks.lwe_ciphertext_count().0,
            "Numerator and denominator must have the same number of blocks"
        );

        let mut quotient: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_blocks, streams);
        let mut remainder: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_blocks, streams);

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
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        d_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        PBSType::Classical,
                        iterations as u32,
                        lut_precision as u32,
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
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        d_multibit_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        PBSType::MultiBit,
                        iterations as u32,
                        lut_precision as u32,
                    );
                }
            }
        }

        (quotient, remainder)
    }

    /// Computes the fixed-point multiplication with optional addition and rescaling.
    pub fn mul_add_fixed_point_with_rescaling(
        &self,
        lhs: &CudaUnsignedRadixCiphertext,
        rhs: &CudaUnsignedRadixCiphertext,
        added: Option<&CudaUnsignedRadixCiphertext>,
        rescaling: i32,
        lut_precision: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let num_blocks = std::cmp::max(
            lhs.as_ref().d_blocks.lwe_ciphertext_count().0,
            rhs.as_ref().d_blocks.lwe_ciphertext_count().0,
        );
        let mut result: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_blocks, streams);

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
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        d_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        PBSType::Classical,
                        lut_precision,
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
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        d_multibit_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        PBSType::MultiBit,
                        lut_precision,
                    );
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use crate::integer::gpu::CudaServerKey;
    use crate::integer::{ClientKey, RadixClientKey};
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    fn run_goldschmidt_division_test(
        cks: &ClientKey,
        sks: &CudaServerKey,
        numerator_clear: u64,
        denominator_clear: u64,
        streams: &CudaStreams,
    ) {
        let num_blocks = 32;
        let ctxt_n = cks.encrypt_radix(numerator_clear, num_blocks);
        let ctxt_d = cks.encrypt_radix(denominator_clear, num_blocks);

        let d_ctxt_n = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_n, streams);
        let d_ctxt_d = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_d, streams);

        let iterations = 3;
        let lut_precision = 9;

        let (d_q_res, d_r_res) =
            sks.goldschmidt_division(&d_ctxt_n, &d_ctxt_d, iterations, lut_precision, streams);

        let q_res = d_q_res.to_radix_ciphertext(streams);
        let r_res = d_r_res.to_radix_ciphertext(streams);

        let clear_q: u64 = cks.decrypt_radix(&q_res);
        let clear_r: u64 = cks.decrypt_radix(&r_res);

        let (expected_q, expected_r) = if denominator_clear == 0 {
            (u64::MAX, numerator_clear)
        } else {
            (
                numerator_clear / denominator_clear,
                numerator_clear % denominator_clear,
            )
        };

        println!("\n--- Testing: {numerator_clear} / {denominator_clear} ---");
        println!("Result:   q={clear_q}, r={clear_r}");
        println!("Expected: q={expected_q}, r={expected_r}");

        assert_eq!(
            clear_q, expected_q,
            "Quotient mismatch for {numerator_clear} / {denominator_clear}"
        );
        assert_eq!(
            clear_r, expected_r,
            "Remainder mismatch for {numerator_clear} / {denominator_clear}"
        );
    }

    #[test]
    fn test_goldschmidt_division_all_cases() {
        let streams = CudaStreams::new_multi_gpu();

        let num_blocks = 32;
        let cks = RadixClientKey::new(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            num_blocks,
        );
        let sks = CudaServerKey::new(&cks, &streams);

        run_goldschmidt_division_test(cks.as_ref(), &sks, 1003, 7, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, 1024, 16, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, 3, 2, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, 2, 3, &streams);

        run_goldschmidt_division_test(cks.as_ref(), &sks, 12345, 12345, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, 42, 1, &streams);

        run_goldschmidt_division_test(cks.as_ref(), &sks, 0, 123, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, 123, 0, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, 0, 0, &streams);

        run_goldschmidt_division_test(cks.as_ref(), &sks, u64::MAX, 1, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, u64::MAX, u64::MAX, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, u64::MAX - 1, u64::MAX, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, u64::MAX, u64::MAX - 1, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, u64::MAX, 2, &streams);

        run_goldschmidt_division_test(cks.as_ref(), &sks, 1 << 63, 1, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, 1 << 63, 1 << 62, &streams);
        run_goldschmidt_division_test(cks.as_ref(), &sks, (1 << 63) - 1, 1 << 62, &streams);
    }
}
