use crate::GlweCiphertextGgswCiphertextExternalProductParameters;
use tfhe::core_crypto::algorithms::polynomial_algorithms;
use tfhe::core_crypto::fft_impl::common::pbs_modulus_switch;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertext;
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomial;
use tfhe::core_crypto::prelude::{
    add_external_product_assign_mem_optimized, allocate_and_generate_new_binary_glwe_secret_key,
    allocate_and_generate_new_lwe_multi_bit_bootstrap_key,
    convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_mem_optimized, decrypt_glwe_ciphertext,
    encrypt_glwe_ciphertext, prepare_multi_bit_ggsw_mem_optimized, std_prepare_multi_bit_ggsw,
    ActivatedRandomGenerator, ComputationBuffers, ContiguousEntityContainer,
    EncryptionRandomGenerator, FourierLweMultiBitBootstrapKey, GgswCiphertext, GlweCiphertext,
    LweBskGroupingFactor, LweSecretKey, MonomialDegree, Numeric, PlaintextCount, PlaintextList,
    SecretRandomGenerator,
};

#[allow(clippy::too_many_arguments)]
pub fn multi_bit_pbs_external_product(
    parameters: &GlweCiphertextGgswCiphertextExternalProductParameters<u64>,
    raw_inputs: &mut Vec<Vec<u64>>,
    outputs: &mut Vec<Vec<u64>>,
    sample_size: usize,
    secret_random_generator: &mut SecretRandomGenerator<ActivatedRandomGenerator>,
    encryption_random_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    fft: FftView,
    computation_buffers: &mut ComputationBuffers,
    grouping_factor: LweBskGroupingFactor,
) -> (u128, u128) {
    let lwe_sk = LweSecretKey::from_container(vec![1u64; grouping_factor.0]);
    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        parameters.glwe_dimension,
        parameters.polynomial_size,
        secret_random_generator,
    );

    let bsk = allocate_and_generate_new_lwe_multi_bit_bootstrap_key(
        &lwe_sk,
        &glwe_secret_key,
        parameters.decomposition_base_log,
        parameters.decomposition_level_count,
        grouping_factor,
        parameters.ggsw_noise,
        parameters.ciphertext_modulus,
        encryption_random_generator,
    );

    let mut fbsk = FourierLweMultiBitBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
        bsk.grouping_factor(),
    );

    convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_mem_optimized(
        &bsk,
        &mut fbsk,
        fft,
        computation_buffers.stack(),
    );

    let ggsw_vec: Vec<_> = fbsk.ggsw_iter().collect();

    let grouping_factor = fbsk.grouping_factor();
    let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element();

    assert_eq!(ggsw_vec.len(), ggsw_per_multi_bit_element.0);

    let mut random_mask = vec![0u64; grouping_factor.0];
    encryption_random_generator.fill_slice_with_random_uniform_mask(&mut random_mask);

    // Recompute it here to rotate and negate the input or output vector to compute errors that make
    // sense
    let equivalent_monomial_degree = MonomialDegree(pbs_modulus_switch(
        random_mask.iter().sum::<u64>(),
        parameters.polynomial_size,
    ));

    let mut fourier_a_monomial = FourierPolynomial::new(fbsk.polynomial_size());

    let mut fourier_ggsw = FourierGgswCiphertext::new(
        fbsk.glwe_size(),
        fbsk.polynomial_size(),
        fbsk.decomposition_base_log(),
        fbsk.decomposition_level_count(),
    );

    let prep_start = std::time::Instant::now();
    prepare_multi_bit_ggsw_mem_optimized(
        &mut fourier_ggsw,
        &ggsw_vec,
        &random_mask,
        &mut fourier_a_monomial,
        fft,
    );
    let prep_time_ns = prep_start.elapsed().as_nanos();

    let mut sample_runtime_ns = 0u128;

    for _ in 0..sample_size {
        let mut input_plaintext_list =
            PlaintextList::new(0u64, PlaintextCount(parameters.polynomial_size.0));
        encryption_random_generator
            .fill_slice_with_random_uniform_mask(input_plaintext_list.as_mut());
        // Shift to match the behavior of the previous concrete-core fixtures
        input_plaintext_list
            .as_mut()
            .iter_mut()
            .for_each(|x| *x <<= <u64 as Numeric>::BITS - parameters.decomposition_base_log.0);

        let mut input_glwe_ciphertext = GlweCiphertext::new(
            0u64,
            parameters.glwe_dimension.to_glwe_size(),
            parameters.polynomial_size,
            parameters.ciphertext_modulus,
        );

        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut input_glwe_ciphertext,
            &input_plaintext_list,
            parameters.glwe_noise,
            encryption_random_generator,
        );

        let mut output_glwe_ciphertext = GlweCiphertext::new(
            0u64,
            parameters.glwe_dimension.to_glwe_size(),
            parameters.polynomial_size,
            parameters.ciphertext_modulus,
        );

        let start = std::time::Instant::now();

        add_external_product_assign_mem_optimized(
            &mut output_glwe_ciphertext,
            &fourier_ggsw,
            &input_glwe_ciphertext,
            fft,
            computation_buffers.stack(),
        );

        let elapsed = start.elapsed().as_nanos();
        sample_runtime_ns += elapsed;

        let mut output_plaintext_list = input_plaintext_list.clone();
        decrypt_glwe_ciphertext(
            &glwe_secret_key,
            &output_glwe_ciphertext,
            &mut output_plaintext_list,
        );

        let mut output_pt_list_as_polynomial = output_plaintext_list.as_mut_polynomial();

        // As we performed a monomial multiplication, we need to apply a monomial div to get outputs
        // in the right order
        polynomial_algorithms::polynomial_wrapping_monic_monomial_div_assign(
            &mut output_pt_list_as_polynomial,
            equivalent_monomial_degree,
        );

        raw_inputs.push(input_plaintext_list.into_container());
        outputs.push(output_plaintext_list.into_container());
    }

    (sample_runtime_ns, prep_time_ns)
}

#[allow(clippy::too_many_arguments)]
pub fn std_multi_bit_pbs_external_product(
    parameters: &GlweCiphertextGgswCiphertextExternalProductParameters<u64>,
    raw_inputs: &mut Vec<Vec<u64>>,
    outputs: &mut Vec<Vec<u64>>,
    sample_size: usize,
    secret_random_generator: &mut SecretRandomGenerator<ActivatedRandomGenerator>,
    encryption_random_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    fft: FftView,
    computation_buffers: &mut ComputationBuffers,
    grouping_factor: LweBskGroupingFactor,
) -> (u128, u128) {
    let lwe_sk = LweSecretKey::from_container(vec![1u64; grouping_factor.0]);
    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        parameters.glwe_dimension,
        parameters.polynomial_size,
        secret_random_generator,
    );

    let bsk = allocate_and_generate_new_lwe_multi_bit_bootstrap_key(
        &lwe_sk,
        &glwe_secret_key,
        parameters.decomposition_base_log,
        parameters.decomposition_level_count,
        grouping_factor,
        parameters.ggsw_noise,
        parameters.ciphertext_modulus,
        encryption_random_generator,
    );

    let grouping_factor = bsk.grouping_factor();
    let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element();

    assert_eq!(bsk.entity_count(), ggsw_per_multi_bit_element.0);

    let mut random_mask = vec![0u64; grouping_factor.0];
    encryption_random_generator.fill_slice_with_random_uniform_mask(&mut random_mask);

    // Recompute it here to rotate and negate the input or output vector to compute errors that make
    // sense
    let equivalent_monomial_degree = MonomialDegree(pbs_modulus_switch(
        random_mask.iter().sum::<u64>(),
        parameters.polynomial_size,
    ));

    let mut fourier_ggsw = FourierGgswCiphertext::new(
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );

    let mut std_ggsw = GgswCiphertext::new(
        0u64,
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
        bsk.ciphertext_modulus(),
    );

    let mut tmp_std_ggsw = GgswCiphertext::new(
        0u64,
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
        bsk.ciphertext_modulus(),
    );

    let prep_start = std::time::Instant::now();
    std_prepare_multi_bit_ggsw(&mut std_ggsw, &mut tmp_std_ggsw, &bsk, &random_mask);
    fourier_ggsw.as_mut_view().fill_with_forward_fourier(
        std_ggsw.as_view(),
        fft,
        computation_buffers.stack(),
    );
    let prep_time_ns = prep_start.elapsed().as_nanos();

    let mut sample_runtime_ns = 0u128;

    for _ in 0..sample_size {
        let mut input_plaintext_list =
            PlaintextList::new(0u64, PlaintextCount(parameters.polynomial_size.0));
        encryption_random_generator
            .fill_slice_with_random_uniform_mask(input_plaintext_list.as_mut());
        // Shift to match the behavior of the previous concrete-core fixtures
        input_plaintext_list
            .as_mut()
            .iter_mut()
            .for_each(|x| *x <<= <u64 as Numeric>::BITS - parameters.decomposition_base_log.0);

        let mut input_glwe_ciphertext = GlweCiphertext::new(
            0u64,
            parameters.glwe_dimension.to_glwe_size(),
            parameters.polynomial_size,
            parameters.ciphertext_modulus,
        );

        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut input_glwe_ciphertext,
            &input_plaintext_list,
            parameters.glwe_noise,
            encryption_random_generator,
        );

        let mut output_glwe_ciphertext = GlweCiphertext::new(
            0u64,
            parameters.glwe_dimension.to_glwe_size(),
            parameters.polynomial_size,
            parameters.ciphertext_modulus,
        );

        let start = std::time::Instant::now();

        add_external_product_assign_mem_optimized(
            &mut output_glwe_ciphertext,
            &fourier_ggsw,
            &input_glwe_ciphertext,
            fft,
            computation_buffers.stack(),
        );

        let elapsed = start.elapsed().as_nanos();
        sample_runtime_ns += elapsed;

        let mut output_plaintext_list = input_plaintext_list.clone();
        decrypt_glwe_ciphertext(
            &glwe_secret_key,
            &output_glwe_ciphertext,
            &mut output_plaintext_list,
        );

        let mut output_pt_list_as_polynomial = output_plaintext_list.as_mut_polynomial();

        // As we performed a monomial multiplication, we need to apply a monomial div to get outputs
        // in the right order
        polynomial_algorithms::polynomial_wrapping_monic_monomial_div_assign(
            &mut output_pt_list_as_polynomial,
            equivalent_monomial_degree,
        );

        raw_inputs.push(input_plaintext_list.into_container());
        outputs.push(output_plaintext_list.into_container());
    }

    (sample_runtime_ns, prep_time_ns)
}
