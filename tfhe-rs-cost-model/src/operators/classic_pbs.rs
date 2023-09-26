use crate::GlweCiphertextGgswCiphertextExternalProductParameters;
use aligned_vec::CACHELINE_ALIGN;
use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use tfhe::core_crypto::fft_impl::fft128::crypto::ggsw::{
    add_external_product_assign, Fourier128GgswCiphertext,
};
use tfhe::core_crypto::fft_impl::fft128_u128::crypto::ggsw::add_external_product_assign_split;
use tfhe::core_crypto::fft_impl::fft128_u128::math::fft::Fft128View;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertext;
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::prelude::{
    add_external_product_assign_mem_optimized, allocate_and_generate_new_binary_glwe_secret_key,
    convert_standard_ggsw_ciphertext_to_fourier_mem_optimized, decrypt_glwe_ciphertext,
    encrypt_constant_ggsw_ciphertext, encrypt_glwe_ciphertext, ActivatedRandomGenerator,
    CiphertextModulus, ComputationBuffers, EncryptionRandomGenerator, GgswCiphertext,
    GlweCiphertext, GlweCiphertextMutView, GlweCiphertextView, Numeric, Plaintext, PlaintextCount,
    PlaintextList, SecretRandomGenerator,
};

#[allow(clippy::too_many_arguments)]
pub fn classic_pbs_external_product(
    parameters: &GlweCiphertextGgswCiphertextExternalProductParameters<u64>,
    raw_inputs: &mut Vec<Vec<u64>>,
    outputs: &mut Vec<Vec<u64>>,
    sample_size: usize,
    secret_random_generator: &mut SecretRandomGenerator<ActivatedRandomGenerator>,
    encryption_random_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    fft: FftView,
    computation_buffers: &mut ComputationBuffers,
) -> (u128, u128) {
    let ciphertext_modulus = parameters.ciphertext_modulus;

    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        parameters.glwe_dimension,
        parameters.polynomial_size,
        secret_random_generator,
    );

    let mut std_ggsw = GgswCiphertext::new(
        0u64,
        parameters.glwe_dimension.to_glwe_size(),
        parameters.polynomial_size,
        parameters.decomposition_base_log,
        parameters.decomposition_level_count,
        ciphertext_modulus,
    );

    encrypt_constant_ggsw_ciphertext(
        &glwe_secret_key,
        &mut std_ggsw,
        Plaintext(parameters.ggsw_encrypted_value),
        parameters.ggsw_noise,
        encryption_random_generator,
    );

    let mut fourier_ggsw = FourierGgswCiphertext::new(
        std_ggsw.glwe_size(),
        std_ggsw.polynomial_size(),
        std_ggsw.decomposition_base_log(),
        std_ggsw.decomposition_level_count(),
    );

    convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
        &std_ggsw,
        &mut fourier_ggsw,
        fft,
        computation_buffers.stack(),
    );

    let mut sample_runtime_ns = 0u128;

    for _ in 0..sample_size {
        let mut input_plaintext_list =
            PlaintextList::new(0u64, PlaintextCount(parameters.polynomial_size.0));
        encryption_random_generator.fill_slice_with_random_mask(input_plaintext_list.as_mut());
        let scaling_to_native_torus = parameters
            .ciphertext_modulus
            .get_power_of_two_scaling_to_native_torus();
        // Shift to match the behavior of the previous concrete-core fixtures
        // Divide as encryption will encode the power of two in the MSBs
        input_plaintext_list.as_mut().iter_mut().for_each(|x| {
            *x = (*x << (<u64 as Numeric>::BITS - parameters.decomposition_base_log.0))
                / scaling_to_native_torus
        });

        // Sanity check
        if !ciphertext_modulus.is_native_modulus() {
            let modulus: u64 = ciphertext_modulus.get_custom_modulus() as u64;
            assert!(input_plaintext_list.as_ref().iter().all(|x| *x < modulus));
        }

        let mut input_glwe_ciphertext = GlweCiphertext::new(
            0u64,
            parameters.glwe_dimension.to_glwe_size(),
            parameters.polynomial_size,
            ciphertext_modulus,
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
            ciphertext_modulus,
        );

        let start = std::time::Instant::now();

        add_external_product_assign_mem_optimized(
            &mut output_glwe_ciphertext,
            &fourier_ggsw,
            &input_glwe_ciphertext,
            fft,
            computation_buffers.stack(),
        );

        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            output_glwe_ciphertext
                .as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        let elapsed = start.elapsed().as_nanos();
        sample_runtime_ns += elapsed;

        let mut output_plaintext_list = input_plaintext_list.clone();
        decrypt_glwe_ciphertext(
            &glwe_secret_key,
            &output_glwe_ciphertext,
            &mut output_plaintext_list,
        );

        // Sanity check
        if !ciphertext_modulus.is_native_modulus() {
            let modulus: u64 = ciphertext_modulus.get_custom_modulus() as u64;
            assert!(output_plaintext_list.as_ref().iter().all(|x| *x < modulus));
        }

        raw_inputs.push(input_plaintext_list.into_container());
        outputs.push(output_plaintext_list.into_container());
    }

    // No prep time in this case
    (sample_runtime_ns, 0)
}

#[allow(clippy::too_many_arguments)]
pub fn classic_pbs_external_product_u128_split(
    parameters: &GlweCiphertextGgswCiphertextExternalProductParameters<u128>,
    raw_inputs: &mut Vec<Vec<u128>>,
    outputs: &mut Vec<Vec<u128>>,
    sample_size: usize,
    secret_random_generator: &mut SecretRandomGenerator<ActivatedRandomGenerator>,
    encryption_random_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    fft: Fft128View,
    computation_buffers: &mut ComputationBuffers,
) -> (u128, u128) {
    let ciphertext_modulus = parameters.ciphertext_modulus;

    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        parameters.glwe_dimension,
        parameters.polynomial_size,
        secret_random_generator,
    );

    let mut std_ggsw = GgswCiphertext::new(
        0u128,
        parameters.glwe_dimension.to_glwe_size(),
        parameters.polynomial_size,
        parameters.decomposition_base_log,
        parameters.decomposition_level_count,
        ciphertext_modulus,
    );

    encrypt_constant_ggsw_ciphertext(
        &glwe_secret_key,
        &mut std_ggsw,
        Plaintext(parameters.ggsw_encrypted_value),
        parameters.ggsw_noise,
        encryption_random_generator,
    );

    let mut fourier_ggsw = Fourier128GgswCiphertext::new(
        std_ggsw.glwe_size(),
        std_ggsw.polynomial_size(),
        std_ggsw.decomposition_base_log(),
        std_ggsw.decomposition_level_count(),
    );

    fourier_ggsw
        .as_mut_view()
        .fill_with_forward_fourier(&std_ggsw, fft);

    let mut sample_runtime_ns = 0u128;

    for _ in 0..sample_size {
        let mut input_plaintext_list =
            PlaintextList::new(0u128, PlaintextCount(parameters.polynomial_size.0));
        encryption_random_generator.fill_slice_with_random_mask(input_plaintext_list.as_mut());
        let scaling_to_native_torus = parameters
            .ciphertext_modulus
            .get_power_of_two_scaling_to_native_torus();
        // Shift to match the behavior of the previous concrete-core fixtures
        // Divide as encryption will encode the power of two in the MSBs
        input_plaintext_list.as_mut().iter_mut().for_each(|x| {
            *x = (*x << (<u128 as Numeric>::BITS - parameters.decomposition_base_log.0))
                / scaling_to_native_torus
        });

        // Sanity check
        if !ciphertext_modulus.is_native_modulus() {
            let modulus = ciphertext_modulus.get_custom_modulus();
            assert!(input_plaintext_list.as_ref().iter().all(|x| *x < modulus));
        }

        let mut input_glwe_ciphertext = GlweCiphertext::new(
            0u128,
            parameters.glwe_dimension.to_glwe_size(),
            parameters.polynomial_size,
            ciphertext_modulus,
        );

        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut input_glwe_ciphertext,
            &input_plaintext_list,
            parameters.glwe_noise,
            encryption_random_generator,
        );

        let mut output_glwe_ciphertext = GlweCiphertext::new(
            0u128,
            parameters.glwe_dimension.to_glwe_size(),
            parameters.polynomial_size,
            ciphertext_modulus,
        );

        let stack = computation_buffers.stack();

        let align = CACHELINE_ALIGN;

        let (input_glwe_lo, stack) = stack.collect_aligned(
            align,
            input_glwe_ciphertext.as_ref().iter().map(|i| *i as u64),
        );
        let (input_glwe_hi, stack) = stack.collect_aligned(
            align,
            input_glwe_ciphertext
                .as_ref()
                .iter()
                .map(|i| (*i >> 64) as u64),
        );

        let input_glwe_lo = GlweCiphertextView::from_container(
            &*input_glwe_lo,
            input_glwe_ciphertext.polynomial_size(),
            // Here we split a u128 to two u64 containers and the ciphertext modulus does not
            // match anymore in terms of the underlying Scalar type, so we'll provide a dummy
            // native modulus
            CiphertextModulus::new_native(),
        );
        let input_glwe_hi = GlweCiphertextView::from_container(
            &*input_glwe_hi,
            input_glwe_ciphertext.polynomial_size(),
            // Here we split a u128 to two u64 containers and the ciphertext modulus does not
            // match anymore in terms of the underlying Scalar type, so we'll provide a dummy
            // native modulus
            CiphertextModulus::new_native(),
        );

        let (mut output_glwe_lo, stack) = stack.collect_aligned(
            align,
            output_glwe_ciphertext.as_ref().iter().map(|i| *i as u64),
        );
        let (mut output_glwe_hi, stack) = stack.collect_aligned(
            align,
            output_glwe_ciphertext
                .as_ref()
                .iter()
                .map(|i| (*i >> 64) as u64),
        );

        let mut output_glwe_lo = GlweCiphertextMutView::from_container(
            &mut *output_glwe_lo,
            output_glwe_ciphertext.polynomial_size(),
            // Here we split a u128 to two u64 containers and the ciphertext modulus does not
            // match anymore in terms of the underlying Scalar type, so we'll provide a dummy
            // native modulus
            CiphertextModulus::new_native(),
        );
        let mut output_glwe_hi = GlweCiphertextMutView::from_container(
            &mut *output_glwe_hi,
            output_glwe_ciphertext.polynomial_size(),
            // Here we split a u128 to two u64 containers and the ciphertext modulus does not
            // match anymore in terms of the underlying Scalar type, so we'll provide a dummy
            // native modulus
            CiphertextModulus::new_native(),
        );

        let start = std::time::Instant::now();

        add_external_product_assign_split(
            &mut output_glwe_lo,
            &mut output_glwe_hi,
            &fourier_ggsw,
            &input_glwe_lo,
            &input_glwe_hi,
            fft,
            stack,
        );

        let elapsed = start.elapsed().as_nanos();
        sample_runtime_ns += elapsed;

        output_glwe_ciphertext
            .as_mut()
            .iter_mut()
            .zip(
                output_glwe_lo
                    .as_ref()
                    .iter()
                    .zip(output_glwe_hi.as_ref().iter()),
            )
            .for_each(|(out, (&lo, &hi))| *out = lo as u128 | ((hi as u128) << 64));

        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            output_glwe_ciphertext
                .as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        let mut output_plaintext_list = input_plaintext_list.clone();
        decrypt_glwe_ciphertext(
            &glwe_secret_key,
            &output_glwe_ciphertext,
            &mut output_plaintext_list,
        );

        // Sanity check
        if !ciphertext_modulus.is_native_modulus() {
            let modulus = ciphertext_modulus.get_custom_modulus();
            assert!(output_plaintext_list.as_ref().iter().all(|x| *x < modulus));
        }

        raw_inputs.push(input_plaintext_list.into_container());
        outputs.push(output_plaintext_list.into_container());
    }

    // No prep time in this case
    (sample_runtime_ns, 0)
}

#[allow(clippy::too_many_arguments)]
pub fn classic_pbs_external_product_u128(
    parameters: &GlweCiphertextGgswCiphertextExternalProductParameters<u128>,
    raw_inputs: &mut Vec<Vec<u128>>,
    outputs: &mut Vec<Vec<u128>>,
    sample_size: usize,
    secret_random_generator: &mut SecretRandomGenerator<ActivatedRandomGenerator>,
    encryption_random_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    fft: Fft128View,
    computation_buffers: &mut ComputationBuffers,
) -> (u128, u128) {
    let ciphertext_modulus = parameters.ciphertext_modulus;

    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        parameters.glwe_dimension,
        parameters.polynomial_size,
        secret_random_generator,
    );

    let mut std_ggsw = GgswCiphertext::new(
        0u128,
        parameters.glwe_dimension.to_glwe_size(),
        parameters.polynomial_size,
        parameters.decomposition_base_log,
        parameters.decomposition_level_count,
        ciphertext_modulus,
    );

    encrypt_constant_ggsw_ciphertext(
        &glwe_secret_key,
        &mut std_ggsw,
        Plaintext(parameters.ggsw_encrypted_value),
        parameters.ggsw_noise,
        encryption_random_generator,
    );

    let mut fourier_ggsw = Fourier128GgswCiphertext::new(
        std_ggsw.glwe_size(),
        std_ggsw.polynomial_size(),
        std_ggsw.decomposition_base_log(),
        std_ggsw.decomposition_level_count(),
    );

    fourier_ggsw
        .as_mut_view()
        .fill_with_forward_fourier(&std_ggsw, fft);

    let mut sample_runtime_ns = 0u128;

    for _ in 0..sample_size {
        let mut input_plaintext_list =
            PlaintextList::new(0u128, PlaintextCount(parameters.polynomial_size.0));
        encryption_random_generator.fill_slice_with_random_mask(input_plaintext_list.as_mut());
        let scaling_to_native_torus = parameters
            .ciphertext_modulus
            .get_power_of_two_scaling_to_native_torus();
        // Shift to match the behavior of the previous concrete-core fixtures
        // Divide as encryption will encode the power of two in the MSBs
        input_plaintext_list.as_mut().iter_mut().for_each(|x| {
            *x = (*x << (<u128 as Numeric>::BITS - parameters.decomposition_base_log.0))
                / scaling_to_native_torus
        });

        // Sanity check
        if !ciphertext_modulus.is_native_modulus() {
            let modulus = ciphertext_modulus.get_custom_modulus();
            assert!(input_plaintext_list.as_ref().iter().all(|x| *x < modulus));
        }

        let mut input_glwe_ciphertext = GlweCiphertext::new(
            0u128,
            parameters.glwe_dimension.to_glwe_size(),
            parameters.polynomial_size,
            ciphertext_modulus,
        );

        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut input_glwe_ciphertext,
            &input_plaintext_list,
            parameters.glwe_noise,
            encryption_random_generator,
        );

        let mut output_glwe_ciphertext = GlweCiphertext::new(
            0u128,
            parameters.glwe_dimension.to_glwe_size(),
            parameters.polynomial_size,
            ciphertext_modulus,
        );

        let start = std::time::Instant::now();

        add_external_product_assign(
            &mut output_glwe_ciphertext,
            &fourier_ggsw,
            &input_glwe_ciphertext,
            fft,
            computation_buffers.stack(),
        );

        if !ciphertext_modulus.is_native_modulus() {
            // When we convert back from the fourier domain, integer values will contain up to 53
            // MSBs with information. In our representation of power of 2 moduli < native modulus we
            // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
            // round while keeping the data in the MSBs
            let signed_decomposer = SignedDecomposer::new(
                DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
                DecompositionLevelCount(1),
            );
            output_glwe_ciphertext
                .as_mut()
                .iter_mut()
                .for_each(|x| *x = signed_decomposer.closest_representable(*x));
        }

        let elapsed = start.elapsed().as_nanos();
        sample_runtime_ns += elapsed;

        let mut output_plaintext_list = input_plaintext_list.clone();
        decrypt_glwe_ciphertext(
            &glwe_secret_key,
            &output_glwe_ciphertext,
            &mut output_plaintext_list,
        );

        // Sanity check
        if !ciphertext_modulus.is_native_modulus() {
            let modulus = ciphertext_modulus.get_custom_modulus();
            assert!(output_plaintext_list.as_ref().iter().all(|x| *x < modulus));
        }

        raw_inputs.push(input_plaintext_list.into_container());
        outputs.push(output_plaintext_list.into_container());
    }

    // No prep time in this case
    (sample_runtime_ns, 0)
}
