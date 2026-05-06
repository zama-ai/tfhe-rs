use super::*;
use crate::core_crypto::algorithms::glwe_secret_key_generation::allocate_and_generate_new_binary_glwe_secret_key;
use crate::core_crypto::algorithms::lwe_bootstrap_key_conversion::par_convert_standard_lwe_bootstrap_key_to_fourier;
use crate::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_lwe_bootstrap_key;
use crate::core_crypto::algorithms::lwe_encryption::{
    allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
};
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::generate_programmable_bootstrap_glwe_lut;
use crate::core_crypto::algorithms::lwe_secret_key_generation::allocate_and_generate_new_binary_lwe_secret_key;
use crate::core_crypto::algorithms::misc::check_encrypted_content_respects_mod;
use crate::core_crypto::algorithms::polynomial_algorithms;
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    EncryptionKeyChoice, GlweDimension, GlweSize, LweDimension, MaxNorm2, MessageModulusLog,
    MonomialDegree, PolynomialSize, StandardDev,
};
use crate::core_crypto::commons::traits::{CastInto, ContiguousEntityContainerMut};
use crate::core_crypto::entities::glwe_ciphertext::GlweCiphertext;
use crate::core_crypto::entities::lwe_ciphertext::LweCiphertext;
use crate::core_crypto::entities::plaintext::Plaintext;
use crate::core_crypto::experimental::algorithms::lwe_extended_programmable_bootstrapping::{
    extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized,
    extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized_requirement,
    small_lut_monomial_degree_from_extended_lut_monomial_degree,
    unchecked_split_extended_lut_into_small_luts,
};
use crate::core_crypto::experimental::commons::parameters::LweBootstrapExtensionFactor;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::math::fft::Fft;

// This test checks that the rotation in the extended polynomial ring is correctly performed by
// first moving small polynomials around and then doing a monomial mul in each small polynomial by a
// well chosen X^small_lut_monomial_index
// N' = 2^nu * N
// new_lut_idx = (ai + old_lut_idx) % 2^nu
// hat(ai) = mod_switch(ai, 2*N')
// small_lut_monomial_index = (2^nu + hat(ai) - 1 - new_lut_idx)/2^nu
#[test]
fn test_monic_mul_split_eq() {
    use rand::Rng;

    let mut rng = rand::thread_rng();

    let glwe_size = GlweSize(2);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    for poly_size_log in 5..13 {
        let small_poly_size = PolynomialSize(1usize << poly_size_log);
        let extension_factor = LweBootstrapExtensionFactor::new(1 << rng.gen_range(1..=3));
        let polynomial_size = PolynomialSize(small_poly_size.0 * extension_factor.get());

        let mut extended_lut =
            GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
        extended_lut
            .as_mut()
            .iter_mut()
            .for_each(|x| *x = rng.gen());

        let extended_lut = extended_lut;

        let mut small_luts =
            vec![
                GlweCiphertext::new(0u64, glwe_size, small_poly_size, ciphertext_modulus);
                extension_factor.get()
            ];

        unchecked_split_extended_lut_into_small_luts(
            &extended_lut,
            &mut small_luts,
            extension_factor,
        );
        let ref_small_luts = small_luts;

        // Sweep all monomial degree values in 2 * N' for exhaustiveness
        for monomial_degree in 0..2 * polynomial_size.0 {
            let monomial_degree = MonomialDegree(monomial_degree);

            // Compute the reference for the rotation results as split luts
            let ref_small_rotated_luts = {
                let mut ref_rotated_lut = extended_lut.clone();
                for mut polynomial_to_rotate in ref_rotated_lut.as_mut_polynomial_list().iter_mut()
                {
                    polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign(
                        &mut polynomial_to_rotate,
                        monomial_degree,
                    );
                }

                let mut ref_small_rotated_luts =
                    vec![
                        GlweCiphertext::new(0u64, glwe_size, small_poly_size, ciphertext_modulus);
                        extension_factor.get()
                    ];

                unchecked_split_extended_lut_into_small_luts(
                    &ref_rotated_lut,
                    &mut ref_small_rotated_luts,
                    extension_factor,
                );

                ref_small_rotated_luts
            };

            // Compute the rotation results with the trick
            let small_luts_rotated_with_trick = {
                // Copy the unmodified reference extended LUT as small luts
                let mut small_luts_rotated_with_trick = ref_small_luts.clone();

                // Rotate the lookup tables by the right amount to start simulating the extended LUT
                // rotation
                small_luts_rotated_with_trick
                    .rotate_right(monomial_degree.0 % extension_factor.get());

                // Complete the rotation with the monomial degree "trick" for small LUTs, using a
                // well chosen monomial degree for each small LUT rotation
                for (lut_idx, small_lut) in small_luts_rotated_with_trick.iter_mut().enumerate() {
                    let small_monomial_degree =
                        small_lut_monomial_degree_from_extended_lut_monomial_degree(
                            monomial_degree,
                            extension_factor,
                            lut_idx,
                        );
                    for mut polynomial_to_rotate in small_lut.as_mut_polynomial_list().iter_mut() {
                        polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign(
                            &mut polynomial_to_rotate,
                            small_monomial_degree,
                        )
                    }
                }
                small_luts_rotated_with_trick
            };

            // Verify our formulas work the way we expect by comparing to the reference not using
            // the trick
            assert_eq!(ref_small_rotated_luts, small_luts_rotated_with_trick);
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct ExtendedPBSTestParameters {
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    extension_factor: LweBootstrapExtensionFactor,
    lwe_noise_distribution: DynamicDistribution<u64>,
    glwe_noise_distribution: DynamicDistribution<u64>,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    precision_without_padding: MessageModulusLog,
    max_norm2: MaxNorm2,
    log2_p_fail: f64,
    ciphertext_modulus: CiphertextModulus<u64>,
    encryption_key_choice: EncryptionKeyChoice,
}

// p-fail = 2^-128.147, algorithmic cost ~ 67456140, 2-norm = 5, extension factor = 16,
const TEST_PARAM_MESSAGE_2_CARRY_2_EPBS_EF_16_2M128: ExtendedPBSTestParameters =
    ExtendedPBSTestParameters {
        lwe_dimension: LweDimension(884),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        extension_factor: LweBootstrapExtensionFactor::new(16),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.4999005934396873e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        precision_without_padding: MessageModulusLog(4),
        max_norm2: MaxNorm2(5f64),
        log2_p_fail: -128.0,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

fn lwe_encrypt_extended_pbs_decrypt(params: ExtendedPBSTestParameters) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let plaintext_modulus = 1 << params.precision_without_padding.0;
    let glwe_dimension = params.glwe_dimension;
    let extension_factor = params.extension_factor;
    let base_polynomial_size = params.polynomial_size;
    let extended_polynomial_size = PolynomialSize(base_polynomial_size.0 * extension_factor.get());
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let pbs_base_log = params.pbs_base_log;
    let pbs_level_count = params.pbs_level;
    let ciphertext_modulus = params.ciphertext_modulus;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let f = |x: u64| x;

    let delta: u64 = encoding_with_padding / plaintext_modulus;
    let mut msg = plaintext_modulus;

    let accumulator = generate_programmable_bootstrap_glwe_lut(
        extended_polynomial_size,
        glwe_dimension.to_glwe_size(),
        plaintext_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_encrypted_content_respects_mod(
        &accumulator,
        ciphertext_modulus
    ));

    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        base_polynomial_size,
        &mut rsc.secret_random_generator,
    );

    let output_lwe_secret_key = output_glwe_secret_key.as_lwe_secret_key();

    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        pbs_base_log,
        pbs_level_count,
        glwe_noise_distribution,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    let mut fbsk = FourierLweBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );

    par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);

    let fft = Fft::new(base_polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();

    // TODO: have req for main thread and for workers ?
    use extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized_requirement as rq;

    let requirement = rq::<u64>(
        glwe_dimension.to_glwe_size(),
        base_polynomial_size,
        extension_factor,
        fft,
    )
    .unaligned_bytes_required();

    buffers.resize(requirement);

    let mut thread_buffers = Vec::with_capacity(extension_factor.get());
    for _ in 0..extension_factor.get() {
        let mut buffer = ComputationBuffers::new();
        buffer.resize(requirement);
        thread_buffers.push(buffer);
    }

    let mut thread_stacks: Vec<_> = thread_buffers.iter_mut().map(|x| x.stack()).collect();

    while msg != 0 {
        msg = msg.wrapping_sub(1);

        for _ in 0..10 {
            let plaintext = Plaintext(msg * delta);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                plaintext,
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &lwe_ciphertext_in,
                ciphertext_modulus
            ));

            let mut out_pbs_ct = LweCiphertext::new(
                0,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized(
                &fbsk,
                &mut out_pbs_ct,
                &lwe_ciphertext_in,
                &accumulator,
                extension_factor,
                fft,
                buffers.stack(),
                &mut thread_stacks,
            );

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % plaintext_modulus;

            assert_eq!(decoded, f(msg));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(lwe_encrypt_extended_pbs_decrypt {
    TEST_PARAM_MESSAGE_2_CARRY_2_EPBS_EF_16_2M128,
});

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct SortedExtendedPBSTestParameters {
    extended_params: ExtendedPBSTestParameters,
    shortcut_coeff_count: LweExtendedBootstrapShortcutCoeffCount,
}

// p-fail = 2^-128.018, algorithmic cost ~ 146109605, 2-norm = 5, extension factor = 2,
const TEST_PARAM_MESSAGE_2_CARRY_2_SEPBS_MS_123_EF_2_128: SortedExtendedPBSTestParameters =
    SortedExtendedPBSTestParameters {
        extended_params: ExtendedPBSTestParameters {
            lwe_dimension: LweDimension(859),
            glwe_dimension: GlweDimension(1),
            polynomial_size: PolynomialSize(2048),
            extension_factor: LweBootstrapExtensionFactor::new(2),
            lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                2.3088161607134664e-06,
            )),
            glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                2.845267479601915e-15,
            )),
            pbs_base_log: DecompositionBaseLog(23),
            pbs_level: DecompositionLevelCount(1),
            ks_base_log: DecompositionBaseLog(3),
            ks_level: DecompositionLevelCount(5),
            precision_without_padding: MessageModulusLog(4),
            max_norm2: MaxNorm2(5f64),
            log2_p_fail: -128.018,
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Big,
        },
        shortcut_coeff_count: LweExtendedBootstrapShortcutCoeffCount(123),
    };

fn lwe_encrypt_sorted_extended_pbs_decrypt(params: SortedExtendedPBSTestParameters) {
    let SortedExtendedPBSTestParameters {
        extended_params:
            ExtendedPBSTestParameters {
                lwe_dimension,
                glwe_dimension,
                polynomial_size: base_polynomial_size,
                extension_factor,
                lwe_noise_distribution,
                glwe_noise_distribution,
                pbs_base_log,
                pbs_level: pbs_level_count,
                ks_base_log: _,
                ks_level: _,
                precision_without_padding,
                max_norm2: _,
                log2_p_fail: _,
                ciphertext_modulus,
                encryption_key_choice: _,
            },
        shortcut_coeff_count,
    } = params;

    let plaintext_modulus = 1 << precision_without_padding.0;
    let extended_polynomial_size = PolynomialSize(base_polynomial_size.0 * extension_factor.get());
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let f = |x: u64| x;

    let delta: u64 = encoding_with_padding / plaintext_modulus;
    let mut msg = plaintext_modulus;

    let accumulator = generate_programmable_bootstrap_glwe_lut(
        extended_polynomial_size,
        glwe_dimension.to_glwe_size(),
        plaintext_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_encrypted_content_respects_mod(
        &accumulator,
        ciphertext_modulus
    ));

    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        base_polynomial_size,
        &mut rsc.secret_random_generator,
    );

    let output_lwe_secret_key = output_glwe_secret_key.as_lwe_secret_key();

    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        pbs_base_log,
        pbs_level_count,
        glwe_noise_distribution,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    let mut fbsk = FourierLweBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );

    par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);

    let fft = Fft::new(base_polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();

    // TODO: have req for main thread and for workers ?
    use extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized_requirement as rq;

    let requirement = rq::<u64>(
        glwe_dimension.to_glwe_size(),
        base_polynomial_size,
        extension_factor,
        fft,
    )
    .unaligned_bytes_required();

    buffers.resize(requirement);

    let mut thread_buffers = Vec::with_capacity(extension_factor.get());
    for _ in 0..extension_factor.get() {
        let mut buffer = ComputationBuffers::new();
        buffer.resize(requirement);
        thread_buffers.push(buffer);
    }

    let mut thread_stacks: Vec<_> = thread_buffers.iter_mut().map(|x| x.stack()).collect();

    while msg != 0 {
        msg = msg.wrapping_sub(1);

        for _ in 0..10 {
            let plaintext = Plaintext(msg * delta);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                plaintext,
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &lwe_ciphertext_in,
                ciphertext_modulus
            ));

            let mut out_pbs_ct = LweCiphertext::new(
                0,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            sorted_extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized(
                &fbsk,
                &mut out_pbs_ct,
                &lwe_ciphertext_in,
                &accumulator,
                extension_factor,
                shortcut_coeff_count,
                fft,
                buffers.stack(),
                &mut thread_stacks,
            );

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % plaintext_modulus;

            assert_eq!(decoded, f(msg));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(lwe_encrypt_sorted_extended_pbs_decrypt {
    TEST_PARAM_MESSAGE_2_CARRY_2_SEPBS_MS_123_EF_2_128,
});
