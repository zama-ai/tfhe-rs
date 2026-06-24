use super::*;
use crate::core_crypto::algorithms::misc::check_clear_content_respects_mod;
use crate::core_crypto::commons::test_tools::{
    arithmetic_mean, modular_distance, modular_distance_custom_mod, torus_modular_diff, variance,
};

// This is 1 / 16 which is exactly representable in an f64 (even an f32)
// 1 / 32 is too strict and fails the tests
const RELATIVE_TOLERANCE: f64 = 0.0625;

const NB_TESTS: usize = 1000;

fn lwe_encrypt_decrypt_noise_distribution_custom_mod<Scalar: UnsignedTorus + CastInto<usize>>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let expected_variance = lwe_noise_distribution.gaussian_std_dev().get_variance();

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
    let mut noise_samples = Vec::with_capacity(num_samples);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let mut ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext(
                &lwe_sk,
                &mut ct,
                plaintext,
                lwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);

            let torus_diff = torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus);
            noise_samples.push(torus_diff);
        }
    }

    let measured_variance = variance(&noise_samples);
    let var_abs_diff = (expected_variance.0 - measured_variance.0).abs();
    let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;
    assert!(
        var_abs_diff < tolerance_threshold,
        "Absolute difference for variance: {var_abs_diff}, \
        tolerance threshold: {tolerance_threshold}, \
        got variance: {measured_variance:?}, \
        expected variance: {expected_variance:?}"
    );
}

create_parameterized_test!(lwe_encrypt_decrypt_noise_distribution_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U64,
    TEST_PARAMS_3_BITS_SOLINAS_U64,
    TEST_PARAMS_3_BITS_63_U64
});

pub(crate) fn lwe_compact_public_key_encryption_expected_variance(
    input_noise: impl DispersionParameter,
    lwe_dimension: LweDimension,
) -> Variance {
    let input_variance = input_noise.get_variance();
    Variance(input_variance.0 * (lwe_dimension.to_lwe_size().0 as f64))
}

#[test]
fn test_variance_increase_cpk_formula() {
    let predicted_variance = lwe_compact_public_key_encryption_expected_variance(
        StandardDev(2.0_f64.powi(39)),
        LweDimension(1024),
    );

    assert!(
        (predicted_variance.get_standard_dev().0.log2() - 44.000704097196405f64).abs()
            < f64::EPSILON
    );
}

fn lwe_compact_public_encrypt_noise_distribution_custom_mod<
    Scalar: UnsignedTorus + CastInto<usize>,
>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = LweDimension(params.polynomial_size.0);
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let glwe_variance = glwe_noise_distribution.gaussian_std_dev().get_variance();

    let expected_variance =
        lwe_compact_public_key_encryption_expected_variance(glwe_variance, lwe_dimension);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
    let mut noise_samples = Vec::with_capacity(num_samples);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let lwe_sk = test_allocate_and_generate_binary_lwe_secret_key_with_half_hamming_weight(
                lwe_dimension,
            );

            let pk = allocate_and_generate_new_lwe_compact_public_key(
                &lwe_sk,
                glwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            let mut ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext_with_compact_public_key(
                &pk,
                &mut ct,
                plaintext,
                glwe_noise_distribution,
                glwe_noise_distribution,
                rsc.encryption_random_generator.noise_generator_mut(),
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);

            let torus_diff = torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus);
            noise_samples.push(torus_diff);
        }
    }

    let measured_variance = variance(&noise_samples);
    let var_abs_diff = (expected_variance.0 - measured_variance.0).abs();
    let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;
    assert!(
        var_abs_diff < tolerance_threshold,
        "Absolute difference for variance: {var_abs_diff}, \
        tolerance threshold: {tolerance_threshold}, \
        got variance: {measured_variance:?}, \
        expected variance: {expected_variance:?}"
    );
}

create_parameterized_test!(lwe_compact_public_encrypt_noise_distribution_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U64
});

fn random_noise_roundtrip<Scalar: UnsignedTorus + CastInto<usize>>(
    params: ClassicTestParams<Scalar>,
) {
    let mut rsc = TestResources::new();
    let noise = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let encryption_rng = &mut rsc.encryption_random_generator;

    assert!(matches!(noise, DynamicDistribution::Gaussian(_)));

    let expected_variance = noise.gaussian_std_dev().get_variance();

    let num_outputs = 100_000;

    let mut output: Vec<_> = vec![Scalar::ZERO; num_outputs];

    encryption_rng.fill_slice_with_random_noise_from_distribution_custom_mod(
        &mut output,
        noise,
        ciphertext_modulus,
    );

    assert!(check_clear_content_respects_mod(
        &output,
        ciphertext_modulus
    ));

    for val in output.iter().copied() {
        if ciphertext_modulus.is_native_modulus() {
            let float_torus = val.into_torus();
            let from_torus = Scalar::from_torus(float_torus);
            assert!(
                modular_distance(val, from_torus)
                    < (Scalar::ONE << (Scalar::BITS.saturating_sub(f64::MANTISSA_DIGITS as usize))),
                "val={val}, from_torus={from_torus}, float_torus={float_torus}"
            );
        } else {
            let custom_modulus_as_scalar: Scalar =
                ciphertext_modulus.get_custom_modulus().cast_into();

            let float_torus = val.into_torus_custom_mod(custom_modulus_as_scalar);
            let from_torus = Scalar::from_torus_custom_mod(float_torus, custom_modulus_as_scalar);
            assert!(from_torus < custom_modulus_as_scalar);
            assert!(
                modular_distance_custom_mod(val, from_torus, custom_modulus_as_scalar)
                    < (Scalar::ONE << (Scalar::BITS.saturating_sub(f64::MANTISSA_DIGITS as usize))),
                "val={val}, from_torus={from_torus}, float_torus={float_torus}"
            );
        }
    }

    let output: Vec<_> = output
        .into_iter()
        .map(|x| torus_modular_diff(Scalar::ZERO, x, ciphertext_modulus))
        .collect();

    let measured_variance = variance(&output);
    let var_abs_diff = (expected_variance.0 - measured_variance.0).abs();
    let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;
    assert!(
        var_abs_diff < tolerance_threshold,
        "Absolute difference for variance: {var_abs_diff}, \
            tolerance threshold: {tolerance_threshold}, \
            got variance: {measured_variance:?}, \
            expected variance: {expected_variance:?}"
    );
}

create_parameterized_test!(random_noise_roundtrip {
    TEST_PARAMS_4_BITS_NATIVE_U64,
    TEST_PARAMS_3_BITS_SOLINAS_U64,
    TEST_PARAMS_3_BITS_63_U64
});

use rayon::prelude::*;

#[test]
fn test_pke_noise_bound() {
    // PKE Params
    // CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    // encryption_lwe_dimension: LweDimension(2048),
    // encryption_noise_distribution: DynamicDistribution::new_t_uniform(17),
    // message_modulus: MessageModulus(4),
    // carry_modulus: CarryModulus(4),
    // ciphertext_modulus: CiphertextModulus::new_native(),
    // expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    // zk_scheme: SupportedCompactPkeZkScheme::V2,
    // }

    // KSK params to compute
    // ks_level: DecompositionLevelCount(4),
    // ks_base_log: DecompositionBaseLog(4),

    // Compute params
    // ClassicPBSParameters {
    //     lwe_dimension: LweDimension(918),
    //     glwe_dimension: GlweDimension(1),
    //     polynomial_size: PolynomialSize(2048),
    //     lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    //     glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    //     pbs_base_log: DecompositionBaseLog(23),
    //     pbs_level: DecompositionLevelCount(1),
    //     ks_base_log: DecompositionBaseLog(4),
    //     ks_level: DecompositionLevelCount(4),
    //     message_modulus: MessageModulus(4),
    //     carry_modulus: CarryModulus(4),
    //     max_noise_level: MaxNoiseLevel::new(5),
    //     log2_p_fail: -129.581,
    //     ciphertext_modulus: CiphertextModulus::new_native(),
    //     encryption_key_choice: EncryptionKeyChoice::Big,
    //     modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    // };

    // 1 padding bit + 2 carry bits + 2 message bits
    let rounding_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();
    let pke_lwe_dim = LweDimension(2048);
    let pke_encryption_noise_distribution = DynamicDistribution::new_t_uniform(17);

    let max_tuniform_value = match pke_encryption_noise_distribution {
        DynamicDistribution::Gaussian(_) => unreachable!(),
        DynamicDistribution::TUniform(tuniform) => tuniform.max_value_inclusive() as u64,
    };

    let compute_lwe_dim = LweDimension(918);
    let compute_lwe_encryption_noise_distribution = DynamicDistribution::new_t_uniform(45);
    let compute_polynomial_size = PolynomialSize(2048);
    let br_modulus_log = compute_polynomial_size.to_blind_rotation_input_modulus_log();

    let ksk_ds_base_log = DecompositionBaseLog(4);
    let ksk_ds_level_count = DecompositionLevelCount(4);

    let mut rsc = TestResources::new();

    let pke_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        pke_lwe_dim,
        &mut rsc.secret_random_generator,
    );

    let compute_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        compute_lwe_dim,
        &mut rsc.secret_random_generator,
    );

    let public_key = allocate_and_generate_new_lwe_compact_public_key(
        &pke_lwe_secret_key,
        pke_encryption_noise_distribution,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    let ksk_ds = allocate_and_generate_new_lwe_keyswitch_key(
        &pke_lwe_secret_key,
        &compute_lwe_secret_key,
        ksk_ds_base_log,
        ksk_ds_level_count,
        compute_lwe_encryption_noise_distribution,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    let plaintexts = PlaintextList::new(0u64, PlaintextCount(public_key.lwe_dimension().0));
    // let plaintexts = PlaintextList::new(0u64, PlaintextCount(512));

    println!("plaintexts_len={:?}", plaintexts.plaintext_count());

    let mut compact_lwe_list = LweCompactCiphertextList::new(
        0u64,
        public_key.lwe_dimension().to_lwe_size(),
        LweCiphertextCount(plaintexts.plaintext_count().0),
        ciphertext_modulus,
    );

    encrypt_lwe_compact_ciphertext_list_with_compact_public_key_worst_case(
        &public_key,
        &mut compact_lwe_list,
        &plaintexts,
        max_tuniform_value,
    );

    // Sanity check
    {
        let lwe_list = compact_lwe_list.clone().expand_into_lwe_ciphertext_list();
        for lwe in lwe_list.iter() {
            let plain = decrypt_lwe_ciphertext(&pke_lwe_secret_key, &lwe);
            let rounded = rounding_decomposer.decode_plaintext(plain);
            assert_eq!(rounded.0, 0);
        }
    }

    // ReRand
    let mut rerand_zero = LweCompactCiphertextList::new(
        0u64,
        public_key.lwe_dimension().to_lwe_size(),
        LweCiphertextCount(plaintexts.plaintext_count().0),
        ciphertext_modulus,
    );
    encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
        &public_key,
        &mut rerand_zero,
        &plaintexts,
        pke_encryption_noise_distribution,
        pke_encryption_noise_distribution,
        rsc.encryption_random_generator.noise_generator_mut(),
    );

    // add 0 to rerand
    compact_lwe_list
        .as_mut()
        .iter_mut()
        .zip(rerand_zero.as_ref().iter())
        .for_each(|(dst, src)| *dst = (*dst).wrapping_add(*src));

    // Sanity check
    {
        let lwe_list = compact_lwe_list.clone().expand_into_lwe_ciphertext_list();
        for lwe in lwe_list.iter() {
            let plain = decrypt_lwe_ciphertext(&pke_lwe_secret_key, &lwe);
            let rounded = rounding_decomposer.decode_plaintext(plain);
            assert_eq!(rounded.0, 0);
        }
    }

    // KS
    let expanded_lwe_list = compact_lwe_list.expand_into_lwe_ciphertext_list();

    let ksed_lwes: Vec<_> = expanded_lwe_list
        .par_iter()
        .map(|lwe| {
            let mut ks_ds_output =
                LweCiphertext::new(0u64, ksk_ds.output_lwe_size(), ciphertext_modulus);
            keyswitch_lwe_ciphertext(&ksk_ds, &lwe, &mut ks_ds_output);
            ks_ds_output
        })
        .collect();

    // Sanity check
    {
        for lwe in ksed_lwes.iter() {
            let plain = decrypt_lwe_ciphertext(&compute_lwe_secret_key, &lwe);
            let rounded = rounding_decomposer.decode_plaintext(plain);
            assert_eq!(rounded.0, 0);
        }
    }

    let msed_to_native = u64::BITS - br_modulus_log.0 as u32;

    let msed_lwes: Vec<_> = ksed_lwes
        .iter()
        .map(|lwe| {
            let lazy_msed = lwe_ciphertext_centered_binary_modulus_switch::<u64, u64, _>(
                lwe.as_view(),
                br_modulus_log,
            );

            let mut msed_lwe = LweCiphertext::new(
                0u64,
                lazy_msed.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            msed_lwe
                .get_mut_mask()
                .as_mut()
                .iter_mut()
                .zip(lazy_msed.mask())
                .for_each(|(dst, src)| *dst = src << msed_to_native);

            *msed_lwe.get_mut_body().data = lazy_msed.body() << msed_to_native;

            msed_lwe
        })
        .collect();

    // Sanity check
    {
        let mut noises = vec![];
        for lwe in msed_lwes.iter() {
            let plain = decrypt_lwe_ciphertext(&compute_lwe_secret_key, lwe);

            let noise = torus_modular_diff(0u64, plain.0, ciphertext_modulus);
            // println!("noise={noise}");
            noises.push(noise);

            let rounded = rounding_decomposer.decode_plaintext(plain);
            assert_eq!(rounded.0, 0);
        }

        let mean = arithmetic_mean(&noises);
        println!("mean={mean:?}");
        let var = variance(&noises);
        println!("var={var:?}");
    }
}

fn encrypt_lwe_compact_ciphertext_list_with_compact_public_key_worst_case<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCompactCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    worst_case_tuniform_value: Scalar,
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    use crate::core_crypto::algorithms::slice_algorithms::{
        slice_semi_reverse_negacyclic_convolution, slice_wrapping_add_assign,
    };

    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_compact_public_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input public key. \
    Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_compact_public_key.lwe_dimension()
    );

    assert!(
        lwe_compact_public_key.ciphertext_modulus() == output.ciphertext_modulus(),
        "Mismatch between CiphertextModulus of output ciphertext and input public key. \
    Got {:?} in output, and {:?} in public key.",
        output.ciphertext_modulus(),
        lwe_compact_public_key.ciphertext_modulus()
    );

    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between LweCiphertextCount of output ciphertext and \
        PlaintextCount of input list. Got {:?} in output, and {:?} in input plaintext list.",
        output.lwe_ciphertext_count(),
        encoded.plaintext_count()
    );

    assert!(
        output.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    let (pk_mask, pk_body) = lwe_compact_public_key.get_mask_and_body();
    let (mut output_mask_list, mut output_body_list) = output.get_mut_mask_and_body_list();

    // The worst case for the binary_random_vector is all ones
    let binary_random_vector = vec![Scalar::ONE; output_mask_list.lwe_mask_list_size()];

    let mask_noise = vec![worst_case_tuniform_value; output_mask_list.lwe_mask_list_size()];
    let body_noise = vec![worst_case_tuniform_value; encoded.plaintext_count().0];

    let max_ciphertext_per_bin = lwe_compact_public_key.lwe_dimension().0;
    output_mask_list
        .iter_mut()
        .zip(
            output_body_list
                .chunks_mut(max_ciphertext_per_bin)
                .zip(encoded.chunks(max_ciphertext_per_bin))
                .zip(binary_random_vector.chunks(max_ciphertext_per_bin))
                .zip(mask_noise.as_slice().chunks(max_ciphertext_per_bin))
                .zip(body_noise.as_slice().chunks(max_ciphertext_per_bin)),
        )
        .for_each(
            |(
                mut output_mask,
                (
                    (
                        ((mut output_body_chunk, input_plaintext_chunk), binary_random_slice),
                        mask_noise,
                    ),
                    body_noise,
                ),
            )| {
                // output_body_chunk may not be able to fit the full convolution result so we
                // create a temp buffer to compute the full convolution
                let mut pk_body_convolved = vec![Scalar::ZERO; max_ciphertext_per_bin];

                slice_semi_reverse_negacyclic_convolution(
                    output_mask.as_mut(),
                    pk_mask.as_ref(),
                    binary_random_slice,
                );

                // Fill the temp buffer with b convolved with r
                slice_semi_reverse_negacyclic_convolution(
                    pk_body_convolved.as_mut_slice(),
                    pk_body.as_ref(),
                    binary_random_slice,
                );

                slice_wrapping_add_assign(output_mask.as_mut(), mask_noise);

                // Fill the body chunk afterward manually as it most likely will be smaller than
                // the full convolution result. rev(b convolved r) + Delta * m + e2
                // taking noise from Chi_2 for the body part of the encryption
                output_body_chunk
                    .iter_mut()
                    .zip(
                        pk_body_convolved
                            .iter()
                            .rev()
                            .zip(input_plaintext_chunk.iter()),
                    )
                    .zip(body_noise)
                    .for_each(|((dst, (&src, plaintext)), body_noise)| {
                        *dst.data = src.wrapping_add(*body_noise).wrapping_add(*plaintext.0);
                    });
            },
        );
}
