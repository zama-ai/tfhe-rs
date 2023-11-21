use super::*;

#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;

fn test_parallel_pfpks_equivalence<Scalar: UnsignedTorus + Send + Sync>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    // Realistic sizes
    {
        let decomp_base_log = DecompositionBaseLog(15);
        let decomp_level_count = DecompositionLevelCount(2);
        let input_key_lwe_dimension = LweDimension(769);
        let output_glwe_dimension = GlweDimension(1);
        let output_glwe_size = output_glwe_dimension.to_glwe_size();
        let output_polynomial_size = PolynomialSize(2048);
        // ~ 2^-20
        let std_dev = StandardDev(0.0000006791658447437413);

        let mut rsc = TestResources::new();

        let mut lwe_pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
            Scalar::ZERO,
            decomp_base_log,
            decomp_level_count,
            input_key_lwe_dimension,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        );

        for _ in 0..NB_TESTS {
            let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                input_key_lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
                output_glwe_dimension,
                output_polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut polynomial = Polynomial::new(Scalar::ZERO, output_polynomial_size);
            rsc.encryption_random_generator
                .fill_slice_with_random_mask(polynomial.as_mut());

            par_generate_lwe_private_functional_packing_keyswitch_key(
                &input_lwe_secret_key,
                &output_glwe_secret_key,
                &mut lwe_pfpksk,
                std_dev,
                &mut rsc.encryption_random_generator,
                UnsignedInteger::wrapping_neg,
                &polynomial,
            );

            let mut random_lwe = LweCiphertext::new(
                Scalar::ZERO,
                input_key_lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );
            rsc.encryption_random_generator
                .fill_slice_with_random_mask(random_lwe.as_mut());

            let mut output_glwe_serial = GlweCiphertext::new(
                Scalar::ZERO,
                output_glwe_size,
                output_polynomial_size,
                ciphertext_modulus,
            );

            let mut output_glwe_parallel = GlweCiphertext::new(
                Scalar::ZERO,
                output_glwe_size,
                output_polynomial_size,
                ciphertext_modulus,
            );

            let start_serial = std::time::Instant::now();
            private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                &lwe_pfpksk,
                &mut output_glwe_serial,
                &random_lwe,
            );
            let elapsed_serial = start_serial.elapsed();
            println!("serial:{elapsed_serial:?}");

            let start_parallel = std::time::Instant::now();
            par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                &lwe_pfpksk,
                &mut output_glwe_parallel,
                &random_lwe,
            );
            let elapsed_parallel = start_parallel.elapsed();
            println!("parallel:{elapsed_parallel:?}");

            assert_eq!(output_glwe_serial, output_glwe_parallel);
        }
    }

    // Small sizes
    {
        for _ in 0..NB_TESTS {
            let decomp_base_log = DecompositionBaseLog(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let decomp_level_count = DecompositionLevelCount(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let input_key_lwe_dimension =
                LweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let output_glwe_dimension =
                GlweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let output_glwe_size = output_glwe_dimension.to_glwe_size();
            let output_polynomial_size = PolynomialSize(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            // ~ 2^-20
            let std_dev = StandardDev(0.0000006791658447437413);

            let mut rsc = TestResources::new();

            let mut lwe_pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
                Scalar::ZERO,
                decomp_base_log,
                decomp_level_count,
                input_key_lwe_dimension,
                output_glwe_size,
                output_polynomial_size,
                ciphertext_modulus,
            );

            for _ in 0..NB_TESTS {
                let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                    input_key_lwe_dimension,
                    &mut rsc.secret_random_generator,
                );

                let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
                    output_glwe_dimension,
                    output_polynomial_size,
                    &mut rsc.secret_random_generator,
                );

                let mut polynomial = Polynomial::new(Scalar::ZERO, output_polynomial_size);
                rsc.encryption_random_generator
                    .fill_slice_with_random_mask(polynomial.as_mut());

                par_generate_lwe_private_functional_packing_keyswitch_key(
                    &input_lwe_secret_key,
                    &output_glwe_secret_key,
                    &mut lwe_pfpksk,
                    std_dev,
                    &mut rsc.encryption_random_generator,
                    UnsignedInteger::wrapping_neg,
                    &polynomial,
                );

                let mut random_lwe = LweCiphertext::new(
                    Scalar::ZERO,
                    input_key_lwe_dimension.to_lwe_size(),
                    ciphertext_modulus,
                );
                rsc.encryption_random_generator
                    .fill_slice_with_random_mask(random_lwe.as_mut());

                let mut output_glwe_serial = GlweCiphertext::new(
                    Scalar::ZERO,
                    output_glwe_size,
                    output_polynomial_size,
                    ciphertext_modulus,
                );

                let mut output_glwe_parallel = GlweCiphertext::new(
                    Scalar::ZERO,
                    output_glwe_size,
                    output_polynomial_size,
                    ciphertext_modulus,
                );

                private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                    &lwe_pfpksk,
                    &mut output_glwe_serial,
                    &random_lwe,
                );

                par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                    &lwe_pfpksk,
                    &mut output_glwe_parallel,
                    &random_lwe,
                );

                assert_eq!(output_glwe_serial, output_glwe_parallel);
            }
        }
    }
}

#[test]
fn test_parallel_pfpks_equivalence_u32_native_mod() {
    test_parallel_pfpks_equivalence::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_parallel_pfpks_equivalence_u64_native_mod() {
    test_parallel_pfpks_equivalence::<u64>(CiphertextModulus::new_native());
}
