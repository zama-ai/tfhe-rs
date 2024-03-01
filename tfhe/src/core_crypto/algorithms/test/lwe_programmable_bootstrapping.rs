use super::*;
use crate::core_crypto::keycache::KeyCacheAccess;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

pub fn generate_keys<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize> + Serialize + DeserializeOwned,
>(
    params: ClassicTestParams<Scalar>,
    rsc: &mut TestResources,
) -> ClassicBootstrapKeys<Scalar> {
    // Create the LweSecretKey
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        params.lwe_dimension,
        &mut rsc.secret_random_generator,
    );
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        params.glwe_dimension,
        params.polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    let mut bsk = LweBootstrapKey::new(
        Scalar::ZERO,
        params.glwe_dimension.to_glwe_size(),
        params.polynomial_size,
        params.pbs_base_log,
        params.pbs_level,
        params.lwe_dimension,
        params.ciphertext_modulus,
    );

    par_generate_lwe_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        &mut bsk,
        params.glwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_encrypted_content_respects_mod(
        &*bsk,
        params.ciphertext_modulus
    ));

    let mut fbsk = FourierLweBootstrapKey::new(
        params.lwe_dimension,
        params.glwe_dimension.to_glwe_size(),
        params.polynomial_size,
        params.pbs_base_log,
        params.pbs_level,
    );

    par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);

    ClassicBootstrapKeys {
        small_lwe_sk: input_lwe_secret_key,
        big_lwe_sk: output_lwe_secret_key,
        bsk,
        fbsk,
    }
}

fn lwe_encrypt_pbs_decrypt_custom_mod<Scalar>(params: ClassicTestParams<Scalar>)
where
    Scalar: UnsignedTorus
        + Sync
        + Send
        + CastFrom<usize>
        + CastInto<usize>
        + Serialize
        + DeserializeOwned,
    ClassicTestParams<Scalar>: KeyCacheAccess<Keys = ClassicBootstrapKeys<Scalar>>,
{
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;

    let mut rsc = TestResources::new();

    let f = |x: Scalar| x;

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;

    let accumulator = generate_accumulator(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_encrypted_content_respects_mod(
        &accumulator,
        ciphertext_modulus
    ));

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);

        let mut keys_gen = |params| generate_keys(params, &mut rsc);
        let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
        let (input_lwe_secret_key, output_lwe_secret_key, fbsk) =
            (keys.small_lwe_sk, keys.big_lwe_sk, keys.fbsk);

        for _ in 0..NB_TESTS {
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
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            programmable_bootstrap_lwe_ciphertext(
                &lwe_ciphertext_in,
                &mut out_pbs_ct,
                &accumulator,
                &fbsk,
            );

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parametrized_test!(lwe_encrypt_pbs_decrypt_custom_mod);

// Here we will define a helper function to generate a many lut accumulator for a PBS
fn generate_accumulator_many_lut<Scalar: UnsignedTorus + CastFrom<usize>>(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    message_modulus: usize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    delta: Scalar,
    funcs: &[&dyn Fn(Scalar) -> Scalar],
) -> (GlweCiphertextOwned<Scalar>, usize) {
    // N/(p/2) = size of each block, to correct noise from the input we introduce the
    // notion of box, which manages redundancy to yield a denoised value
    // for several noisy values around a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    let fn_count = funcs.len();
    let fn_count = if fn_count.is_power_of_two() {
        fn_count
    } else {
        fn_count.next_power_of_two()
    };

    assert!(fn_count <= (message_modulus / 2));

    let func_chunk_size = polynomial_size.0 / fn_count;

    // Create the accumulator
    let mut accumulator_scalar = vec![Scalar::ZERO; polynomial_size.0];

    let func_chunks = accumulator_scalar.chunks_exact_mut(func_chunk_size);

    // Fill each box with the encoded denoised value
    for (func, func_chunk) in funcs.iter().zip(func_chunks) {
        for (msg_value, box_) in func_chunk.chunks_exact_mut(box_size).enumerate() {
            let msg_value = Scalar::cast_from(msg_value);

            let func_eval = func(msg_value) * delta;
            box_.fill(func_eval);
        }
    }

    let half_box_size = box_size / 2;

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }
    } else {
        let modulus: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
        for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg_custom_mod(modulus);
        }
    }

    // Rotate the accumulator
    accumulator_scalar.rotate_left(half_box_size);

    let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);

    (
        allocate_and_trivially_encrypt_new_glwe_ciphertext(
            glwe_size,
            &accumulator_plaintext,
            ciphertext_modulus,
        ),
        func_chunk_size,
    )
}

fn lwe_encrypt_pbs_many_lut_decrypt_custom_mod<Scalar>(params: ClassicTestParams<Scalar>)
where
    Scalar: UnsignedTorus
        + Sync
        + Send
        + CastFrom<usize>
        + CastInto<usize>
        + Serialize
        + DeserializeOwned,
    ClassicTestParams<Scalar>: KeyCacheAccess<Keys = ClassicBootstrapKeys<Scalar>>,
{
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;

    let total_plaintext_modulus = msg_modulus;

    let mut rsc = TestResources::new();

    // We need at least two bits of space to manage 4 functions, we could make something even more
    // flexible, but this should be enough
    assert!(total_plaintext_modulus > Scalar::cast_from(4u128));

    let f1 = |x: Scalar| x % total_plaintext_modulus;
    let f2 = |x: Scalar| (x.wrapping_mul(Scalar::cast_from(3u128)) % total_plaintext_modulus);
    let f3 = |x: Scalar| ((x + Scalar::ONE) % total_plaintext_modulus);
    let f4 = |x: Scalar| ((x / Scalar::TWO) % total_plaintext_modulus);

    let funcs: [&dyn Fn(Scalar) -> Scalar; 4] = [&f1, &f2, &f3, &f4];

    for fn_count in 1..=funcs.len() {
        let funcs = &funcs[..fn_count];

        let fn_count = funcs.len();
        // Compute a potentially inflated fn_count to allocate enough bits in the plaintext space
        let fn_count = if fn_count.is_power_of_two() {
            fn_count
        } else {
            fn_count.next_power_of_two()
        };

        // Actual bits used for the msg, will allow enough functions to be computed at the same time
        let msg_modulus = total_plaintext_modulus / Scalar::cast_from(fn_count);

        let mut msg = msg_modulus;

        // Here the separate delta is done on purpose, it's to indicate how a many lut approach
        // could be dealing with two deltas, one for the input (which has to leave some LSB set to
        // 0) and this lut delta which can make use of the full plaintext space
        let delta: Scalar = encoding_with_padding / total_plaintext_modulus;

        // The box size is required to know where to look for the evaluations of the other functions
        let (accumulator, func_chunk_size) = generate_accumulator_many_lut(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            total_plaintext_modulus.cast_into(),
            ciphertext_modulus,
            delta,
            funcs,
        );

        assert!(check_encrypted_content_respects_mod(
            &accumulator,
            ciphertext_modulus
        ));

        while msg != Scalar::ZERO {
            msg = msg.wrapping_sub(Scalar::ONE);

            let mut keys_gen = |params| generate_keys(params, &mut rsc);
            let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
            let (input_lwe_secret_key, output_lwe_secret_key, fbsk) =
                (keys.small_lwe_sk, keys.big_lwe_sk, keys.fbsk);

            for _ in 0..NB_TESTS {
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

                let mut tmp_acc = accumulator.clone();

                blind_rotate_assign(&lwe_ciphertext_in, &mut tmp_acc, &fbsk);

                assert!(check_encrypted_content_respects_mod(
                    &tmp_acc,
                    ciphertext_modulus
                ));

                let mut out_pbs_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    ciphertext_modulus,
                );

                for (fn_idx, func) in funcs.iter().enumerate() {
                    extract_lwe_sample_from_glwe_ciphertext(
                        &tmp_acc,
                        &mut out_pbs_ct,
                        MonomialDegree(fn_idx * func_chunk_size),
                    );

                    assert!(check_encrypted_content_respects_mod(
                        &out_pbs_ct,
                        ciphertext_modulus
                    ));

                    let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

                    let decoded = round_decode(decrypted.0, delta) % total_plaintext_modulus;

                    assert_eq!(decoded, func(msg));
                }
            }

            // In coverage, we break after one while loop iteration, changing message values does
            // not yield higher coverage
            #[cfg(tarpaulin)]
            break;
        }
    }
}

create_parametrized_test!(lwe_encrypt_pbs_many_lut_decrypt_custom_mod);

// DISCLAIMER: all parameters here are not guaranteed to be secure or yield correct computations
pub const TEST_PARAMS_4_BITS_NATIVE_U128: ClassicTestParams<u128> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.9982771e-11,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.6457178e-32,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

pub const TEST_PARAMS_3_BITS_127_U128: ClassicTestParams<u128> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.9982771e-11,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.6457178e-32,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(3),
    ciphertext_modulus: CiphertextModulus::new(1 << 127),
};

fn lwe_encrypt_pbs_f128_decrypt_custom_mod<Scalar>(params: ClassicTestParams<Scalar>)
where
    Scalar: UnsignedTorus
        + Sync
        + Send
        + CastFrom<usize>
        + CastInto<usize>
        + Serialize
        + DeserializeOwned,
    ClassicTestParams<Scalar>: KeyCacheAccess<Keys = ClassicBootstrapKeys<Scalar>>,
{
    let input_lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.pbs_base_log;
    let decomp_level_count = params.pbs_level;

    let mut rsc = TestResources::new();

    let f = |x: Scalar| x;

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;

    let accumulator = generate_accumulator(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_encrypted_content_respects_mod(
        &accumulator,
        ciphertext_modulus
    ));

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);

        let mut keys_gen = |params| generate_keys(params, &mut rsc);

        let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
        let (input_lwe_secret_key, output_lwe_secret_key, bsk) =
            (keys.small_lwe_sk, keys.big_lwe_sk, keys.bsk);

        let mut fbsk = Fourier128LweBootstrapKey::new(
            input_lwe_dimension,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        );

        convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk, &mut fbsk);

        drop(bsk);

        for _ in 0..NB_TESTS {
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
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            programmable_bootstrap_f128_lwe_ciphertext(
                &lwe_ciphertext_in,
                &mut out_pbs_ct,
                &accumulator,
                &fbsk,
            );

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

#[test]
fn lwe_encrypt_pbs_f128_decrypt_custom_mod_test_params_4_bits_native_u128() {
    lwe_encrypt_pbs_f128_decrypt_custom_mod(TEST_PARAMS_4_BITS_NATIVE_U128);
}
#[test]
fn lwe_encrypt_pbs_f128_decrypt_custom_mod_test_params_3_bits_127_u128() {
    lwe_encrypt_pbs_f128_decrypt_custom_mod(TEST_PARAMS_3_BITS_127_U128);
}
