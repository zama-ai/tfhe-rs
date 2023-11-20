use super::lwe_multi_bit_programmable_bootstrapping::generate_keys as multi_bit_gen_keys;
use super::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 1 << 3;
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

    let accumulator = generate_programmable_bootstrap_glwe_lut(
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

    let mut keys_gen = |params| generate_keys(params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let (input_lwe_secret_key, output_lwe_secret_key, fbsk) =
        (keys.small_lwe_sk, keys.big_lwe_sk, keys.fbsk);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);

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

create_parametrized_test!(lwe_encrypt_pbs_decrypt_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U64,
    TEST_PARAMS_8_BITS_NATIVE_U64
});

// Here we will define a helper function to generate a many lut accumulator for a PBS
fn generate_programmable_bootstrap_glwe_lut_many_lut<Scalar: UnsignedTorus + CastFrom<usize>>(
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
        let (accumulator, func_chunk_size) = generate_programmable_bootstrap_glwe_lut_many_lut(
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
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: MessageModulusLog(4),
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
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: MessageModulusLog(3),
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

    let accumulator = generate_programmable_bootstrap_glwe_lut(
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

pub const TEST_PARAMS_8_BITS_NATIVE_U64: ClassicTestParams<u64> = ClassicTestParams {
    lwe_dimension: LweDimension(996),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000006767666038309478,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000000002168404344971009,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus_log: MessageModulusLog(8),
    pfks_level: DecompositionLevelCount(0),
    pfks_base_log: DecompositionBaseLog(0),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

#[allow(dead_code)]
pub const TEST_PARAMS_TOY_8_BITS_NATIVE_U64: ClassicTestParams<u64> = ClassicTestParams {
    lwe_dimension: LweDimension(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus_log: MessageModulusLog(8),
    pfks_level: DecompositionLevelCount(0),
    pfks_base_log: DecompositionBaseLog(0),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

#[allow(dead_code)]
fn ly23_parallelized(params: ClassicTestParams<u64>) {
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = 1u64 << message_modulus_log.0;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    // This is the 2^nu from the paper
    let extension_factor = Ly23ExtensionFactor(1 << 4);
    let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);

    let mut rsc = TestResources::new();

    let f = |x: u64| x.wrapping_rem(msg_modulus);

    let delta: u64 = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;
    const NB_TESTS: usize = 10;

    // To check, if something goes wrong, if format is ok
    let accumulator = generate_programmable_bootstrap_glwe_lut(
        extended_polynomial_size,
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

    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    // TODO update buffer sizes
    buffers.resize(
        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            extension_factor,
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let mut thread_buffers = Vec::with_capacity(extension_factor.0);
    for _ in 0..extension_factor.0 {
        let mut buffer = ComputationBuffers::new();
        buffer.resize(
            add_external_product_assign_mem_optimized_requirement::<u64>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        thread_buffers.push(buffer);
    }

    let mut thread_stacks: Vec<_> = thread_buffers.iter_mut().map(|x| x.stack()).collect();

    let mut keys_gen = |params| generate_keys(params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let (input_lwe_secret_key, output_lwe_secret_key, fbsk) =
        (keys.small_lwe_sk, keys.big_lwe_sk, keys.fbsk);

    while msg != 0u64 {
        msg -= 1;

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
                0u64,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            fbsk.as_view().bootstrap_ly23_parallelized(
                out_pbs_ct.as_mut_view(),
                lwe_ciphertext_in.as_view(),
                accumulator.as_view(),
                extension_factor,
                fft,
                buffers.stack(),
                thread_stacks.as_mut_slice(),
            );

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }
    }
}

#[test]
fn test_ly23_parallelized_toy() {
    ly23_parallelized(TEST_PARAMS_TOY_8_BITS_NATIVE_U64);
}

use crate::shortint::parameters::{ClassicPBSParameters, PARAM_MESSAGE_5_BEST_PBS_MS_20_EF_1_40, PARAM_MESSAGE_6_BEST_PBS_MS_1_EF_3_40, PARAM_MESSAGE_7_BEST_PBS_MS_94_EF_3_40, PARAM_MESSAGE_8_BEST_PBS_MS_90_EF_4_40, PARAM_MESSAGE_9_BEST_PBS_MS_76_EF_5_40, PARAM_MESSAGE_5_BEST_PBS_MS_151_EF_2_80, PARAM_MESSAGE_6_BEST_PBS_MS_255_EF_3_80, PARAM_MESSAGE_7_BEST_PBS_MS_256_EF_4_80, PARAM_MESSAGE_8_BEST_PBS_MS_256_EF_5_80, PARAM_MESSAGE_9_BEST_PBS_MS_255_EF_6_80, PARAM_MESSAGE_5_BEST_PBS_MS_0_EF_2_128, PARAM_MESSAGE_6_BEST_PBS_MS_150_EF_3_128, PARAM_MESSAGE_7_BEST_PBS_MS_148_EF_4_128, PARAM_MESSAGE_8_BEST_PBS_MS_137_EF_5_128, PARAM_MESSAGE_9_BEST_PBS_MS_96_EF_6_128, PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_40, PARAM_MESSAGE_3_CARRY_4_PARALLEL_PBS_MS_0_EF_4_64, PARAM_MESSAGE_3_CARRY_3_PARALLEL_PBS_MS_0_EF_4_64, PARAM_MESSAGE_2_CARRY_3_PARALLEL_PBS_MS_0_EF_4_64, PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_MS_0_EF_4_64, PARAM_MESSAGE_1_CARRY_2_PARALLEL_PBS_MS_0_EF_4_64, PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_64};

//
// fn sepbs_shortint_params(params: ParametersLY23) {
//     test_sepbs_epbs_pbs(params, "se_pbs")
// }
//
// fn epbs_shortint_params(params: ParametersLY23) {
//     test_sepbs_epbs_pbs(params, "e_pbs")
// }
// fn pbs_shortint_params(params: ClassicPBSParameters) {
//     let params = ParametersLY23 {
//         param: params,
//         log_extension_factor: 0,
//     };
//     test_sepbs_epbs_pbs(params, "pbs")
// }
//
fn pepbs_shortint_params(params: ParametersLY23) {
     test_pepbs_sorted_pepbs(params, "pe_pbs")
}
//
// fn spepbs_shortint_params(params: ParametersLY23) {
//     test_pepbs_sorted_pepbs(params, "spe_pbs")
// }


fn test_sepbs_epbs_pbs(params: ParametersLY23MS, test: &str) {
    let log_extension_factor = params.log_extension_factor;
    let shortcut_coeff = params.shortcut_coeff;
    let ct_modulus =
        (params.param.message_modulus.0 * params.param.carry_modulus.0).ilog2() as usize;
    let params = ClassicTestParams {
        lwe_dimension: params.param.lwe_dimension,
        glwe_dimension: params.param.glwe_dimension,
        polynomial_size: params.param.polynomial_size,
        lwe_noise_distribution: params.param.lwe_noise_distribution,
        glwe_noise_distribution: params.param.glwe_noise_distribution,
        pbs_base_log: params.param.pbs_base_log,
        pbs_level: params.param.pbs_level,
        ks_base_log: params.param.ks_base_log,
        ks_level: params.param.ks_level,
        pfks_level: DecompositionLevelCount(0),
        pfks_base_log: DecompositionBaseLog(0),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
        cbs_level: DecompositionLevelCount(0),
        cbs_base_log: DecompositionBaseLog(0),
        message_modulus_log: MessageModulusLog(ct_modulus),
        ciphertext_modulus: CiphertextModulus::new_native(),
    };
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = 1u64 << message_modulus_log.0;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    // This is the 2^nu from the paper
    let extension_factor = Ly23ExtensionFactor(1 << log_extension_factor);
    let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);
    // TODO adapt with parameters
    let shortcut_coeff_count = Ly23ShortcutCoeffCount(shortcut_coeff);

    let mut rsc = TestResources::new();

    let f = |x: u64| x.wrapping_rem(msg_modulus);

    let delta: u64 = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;

    // To check, if something goes wrong, if format is ok
    let accumulator = generate_programmable_bootstrap_glwe_lut(
        extended_polynomial_size,
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

    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    // TODO update buffer sizes
    buffers.resize(
        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            extension_factor,
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let mut keys_gen = |params| generate_keys(params, &mut rsc);
    let keys = crate::core_crypto::keycache::KEY_CACHE.get_key_with_closure(params, &mut keys_gen);
    let (input_lwe_secret_key, output_lwe_secret_key, fbsk) =
        (keys.small_lwe_sk, keys.big_lwe_sk, keys.fbsk);

    while msg != 0u64 {
        msg -= 1;

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
                0u64,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );
            match test {
                "pbs" => fbsk.as_view().bootstrap(
                    out_pbs_ct.as_mut_view(),
                    lwe_ciphertext_in.as_view(),
                    accumulator.as_view(),
                    fft,
                    buffers.stack(),
                ),
                "e_pbs" => fbsk.as_view().bootstrap_ly23(
                    out_pbs_ct.as_mut_view(),
                    lwe_ciphertext_in.as_view(),
                    accumulator.as_view(),
                    extension_factor,
                    fft,
                    buffers.stack(),
                ),
                "se_pbs" => fbsk.as_view().bootstrap_bergerat24(
                    out_pbs_ct.as_mut_view(),
                    lwe_ciphertext_in.as_view(),
                    accumulator.as_view(),
                    extension_factor,
                    shortcut_coeff_count,
                    fft,
                    buffers.stack(),
                ),
                _ => panic!(),
            };

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }
    }
}

fn test_pepbs_sorted_pepbs(params: ParametersLY23, test: &str) {
    let log_extension_factor = params.log_extension_factor;
    let ct_modulus =
        (params.param.message_modulus.0 * params.param.carry_modulus.0).ilog2() as usize;
    let params = ClassicTestParams {
        lwe_dimension: params.param.lwe_dimension,
        glwe_dimension: params.param.glwe_dimension,
        polynomial_size: params.param.polynomial_size,
        lwe_noise_distribution: params.param.lwe_noise_distribution,
        glwe_noise_distribution: params.param.glwe_noise_distribution,
        pbs_base_log: params.param.pbs_base_log,
        pbs_level: params.param.pbs_level,
        ks_base_log: params.param.ks_base_log,
        ks_level: params.param.ks_level,
        pfks_level: DecompositionLevelCount(0),
        pfks_base_log: DecompositionBaseLog(0),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
        cbs_level: DecompositionLevelCount(0),
        cbs_base_log: DecompositionBaseLog(0),
        message_modulus_log: MessageModulusLog(ct_modulus),
        ciphertext_modulus: CiphertextModulus::new_native(),
    };

    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = 1u64 << message_modulus_log.0;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    // This is the 2^nu from the paper
    let extension_factor = Ly23ExtensionFactor(1 << log_extension_factor);
    let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);
    // TODO adapt with parameters
    let shortcut_coeff_count = Ly23ShortcutCoeffCount(1);

    let mut rsc = TestResources::new();

    let f = |x: u64| x.wrapping_rem(msg_modulus);

    let delta: u64 = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;
    const NB_TESTS: usize = 10;

    // To check, if something goes wrong, if format is ok
    let accumulator = generate_programmable_bootstrap_glwe_lut(
        extended_polynomial_size,
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
    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    // TODO update buffer sizes
    buffers.resize(
        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            extension_factor,
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let mut thread_buffers = Vec::with_capacity(extension_factor.0);
    for _ in 0..extension_factor.0 {
        let mut buffer = ComputationBuffers::new();
        buffer.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                extension_factor,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        thread_buffers.push(buffer);
    }

    let mut thread_stacks: Vec<_> = thread_buffers.iter_mut().map(|x| x.stack()).collect();

    let mut keys_gen = |params| generate_keys(params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let (input_lwe_secret_key, output_lwe_secret_key, fbsk) =
        (keys.small_lwe_sk, keys.big_lwe_sk, keys.fbsk);

    while msg != 0u64 {
        msg -= 1;

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
                0u64,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );
            match test {
                "pe_pbs" => fbsk.as_view().bootstrap_ly23_parallelized(
                    out_pbs_ct.as_mut_view(),
                    lwe_ciphertext_in.as_view(),
                    accumulator.as_view(),
                    extension_factor,
                    fft,
                    buffers.stack(),
                    thread_stacks.as_mut_slice(),
                ),
                "spe_pbs" => fbsk.as_view().bootstrap_ly23_parallelized_sorted(
                    out_pbs_ct.as_mut_view(),
                    lwe_ciphertext_in.as_view(),
                    accumulator.as_view(),
                    extension_factor,
                    shortcut_coeff_count,
                    fft,
                    buffers.stack(),
                    thread_stacks.as_mut_slice(),
                ),
                _ => panic!(),
            };

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }
    }
}


fn sepbs_shortint_params_ms(params: ParametersLY23MS) {
    test_sepbs_epbs_pbs(params, "se_pbs")
}


create_parametrized_test!(sepbs_shortint_params_ms{
    LY23_5_40_MS,
    LY23_6_40_MS,
    LY23_7_40_MS,
    LY23_8_40_MS,
    LY23_9_40_MS,
    LY23_5_80_MS,
    LY23_6_80_MS,
    LY23_7_80_MS,
    LY23_8_80_MS,
    LY23_9_80_MS,
    LY23_5_128_MS,
    LY23_6_128_MS,
    LY23_7_128_MS,
    LY23_8_128_MS,
    LY23_9_128_MS,
});
//
// create_parametrized_test!(pbs_shortint_params {
//     PARAM_MESSAGE_1_CARRY_0_PBS_64,
//     PARAM_MESSAGE_1_CARRY_1_PBS_64,
//     PARAM_MESSAGE_1_CARRY_2_PBS_64,
//     PARAM_MESSAGE_2_CARRY_2_PBS_64,
//     PARAM_MESSAGE_2_CARRY_3_PBS_64,
//     PARAM_MESSAGE_3_CARRY_3_PBS_64,
//     PARAM_MESSAGE_3_CARRY_4_PBS_64,
//     PARAM_MESSAGE_4_CARRY_4_PBS_64,
// });
//
//create_parametrized_test!(sepbs_shortint_params {
//     LY23_1,
//     LY23_2,
//     LY23_3,
//     LY23_4,
//     LY23_5,
//     LY23_6,
//     LY23_7,
//     LY23_8,
//});
//
create_parametrized_test!(pepbs_shortint_params {
//     LY23_1_PARALLEL,
     LY23_2_PARALLEL,
     LY23_3_PARALLEL,
     LY23_4_PARALLEL,
     LY23_5_PARALLEL,
     LY23_6_PARALLEL,
     LY23_7_PARALLEL,
//     LY23_8_PARALLEL,
});

// create_parametrized_test!(spepbs_shortint_params {
//     LY23_1_PARALLEL,
//     LY23_2_PARALLEL,
//     LY23_3_PARALLEL,
//     LY23_4_PARALLEL,
//     LY23_5_PARALLEL,
//     LY23_6_PARALLEL,
//     LY23_7_PARALLEL,
//     LY23_8_PARALLEL,
// });

fn multibit_epbs_case(params: MultiBitParametersLY23) {
    let log_extension_factor = params.log_extension_factor;
    let ct_modulus =
        (params.param.message_modulus.0 * params.param.carry_modulus.0).ilog2() as usize;
    let multi_bit_params = params.param;
    let params = MultiBitTestParams {
        input_lwe_dimension: multi_bit_params.lwe_dimension,
        lwe_noise_distribution: multi_bit_params.lwe_noise_distribution,
        decomp_base_log: multi_bit_params.pbs_base_log,
        decomp_level_count: multi_bit_params.pbs_level,
        glwe_dimension: multi_bit_params.glwe_dimension,
        polynomial_size: multi_bit_params.polynomial_size,
        glwe_noise_distribution: multi_bit_params.glwe_noise_distribution,
        message_modulus_log: MessageModulusLog(ct_modulus),
        ciphertext_modulus: multi_bit_params.ciphertext_modulus,
        grouping_factor: multi_bit_params.grouping_factor,
        thread_count: ThreadCount(0),
    };

    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = 1u64 << message_modulus_log.0;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    // This is the 2^nu from the paper
    let extension_factor = Ly23ExtensionFactor(1 << log_extension_factor);
    let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);

    let mut rsc = TestResources::new();

    let f = |x: u64| x.wrapping_rem(msg_modulus);

    let delta: u64 = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;
    const NB_TESTS: usize = 1;

    // To check, if something goes wrong, if format is ok
    let accumulator = generate_programmable_bootstrap_glwe_lut(
        extended_polynomial_size,
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

    let mut keys_gen = |params| multi_bit_gen_keys(params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let (input_lwe_secret_key, output_lwe_secret_key, fbsk) =
        (keys.small_lwe_sk, keys.big_lwe_sk, keys.fbsk);

    while msg != 0u64 {
        msg -= 1;

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
                0u64,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            lwe_multi_bit_extended_programmable_bootstrapping(
                &lwe_ciphertext_in,
                &mut out_pbs_ct,
                &accumulator,
                &fbsk,
                extension_factor,
            );

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }
    }
}

#[test]
fn test_toy_params_multibit_epbs_case() {
    // let params = MultiBitParametersLY23 {
    //     param: crate::shortint::parameters::MultiBitPBSParameters {
    //         lwe_dimension: LweDimension(4),
    //         glwe_dimension: GlweDimension(1),
    //         polynomial_size: PolynomialSize(2048),
    //         lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
    //             0.0,
    //         )),
    //         glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
    //             0.0,
    //         )),
    //         pbs_base_log: DecompositionBaseLog(22),
    //         pbs_level: DecompositionLevelCount(1),
    //         ks_base_log: DecompositionBaseLog(3),
    //         ks_level: DecompositionLevelCount(5),
    //         message_modulus: crate::shortint::parameters::MessageModulus(4),
    //         carry_modulus: crate::shortint::parameters::CarryModulus(4),
    //         max_noise_level: crate::shortint::parameters::MaxNoiseLevel::new(5),
    //         log2_p_fail: 0.0,
    //         ciphertext_modulus: CiphertextModulus::new_native(),
    //         encryption_key_choice: EncryptionKeyChoice::Big,
    //         grouping_factor: LweBskGroupingFactor(2),
    //         deterministic_execution: false,
    //     },
    //     log_extension_factor: 1,
    // };

    let params = MultiBitParametersLY23 {
        param: crate::shortint::parameters::MultiBitPBSParameters {
            lwe_dimension: LweDimension(888),
            glwe_dimension: GlweDimension(1),
            polynomial_size: PolynomialSize(2048),
            lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                1.3998779623487315e-06,
            )),
            glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                2.845267479601915e-15,
            )),
            pbs_base_log: DecompositionBaseLog(21),
            pbs_level: DecompositionLevelCount(1),
            ks_base_log: DecompositionBaseLog(4),
            ks_level: DecompositionLevelCount(4),
            message_modulus: crate::shortint::parameters::MessageModulus(4),
            carry_modulus: crate::shortint::parameters::CarryModulus(4),
            max_noise_level: crate::shortint::parameters::MaxNoiseLevel::new(5),
            log2_p_fail: 0.0,
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Big,
            grouping_factor: LweBskGroupingFactor(2),
            deterministic_execution: false,
        },
        log_extension_factor: 2,
    };

    multibit_epbs_case(params);
}

fn multibit_sepbs_case(params: MultiBitParametersLY23) {
    let log_extension_factor = params.log_extension_factor;
    let ct_modulus =
        (params.param.message_modulus.0 * params.param.carry_modulus.0).ilog2() as usize;
    let multi_bit_params = params.param;
    let params = MultiBitTestParams {
        input_lwe_dimension: multi_bit_params.lwe_dimension,
        lwe_noise_distribution: multi_bit_params.lwe_noise_distribution,
        decomp_base_log: multi_bit_params.pbs_base_log,
        decomp_level_count: multi_bit_params.pbs_level,
        glwe_dimension: multi_bit_params.glwe_dimension,
        polynomial_size: multi_bit_params.polynomial_size,
        glwe_noise_distribution: multi_bit_params.glwe_noise_distribution,
        message_modulus_log: MessageModulusLog(ct_modulus),
        ciphertext_modulus: multi_bit_params.ciphertext_modulus,
        grouping_factor: multi_bit_params.grouping_factor,
        thread_count: ThreadCount(0),
    };

    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = 1u64 << message_modulus_log.0;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    // This is the 2^nu from the paper
    let extension_factor = Ly23ExtensionFactor(1 << log_extension_factor);
    let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);
    // TODO adapt with parameters
    let shortcut_coeff_count = Ly23ShortcutCoeffCount(1);

    let mut rsc = TestResources::new();

    let f = |x: u64| x.wrapping_rem(msg_modulus);

    let delta: u64 = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;
    const NB_TESTS: usize = 10;

    // To check, if something goes wrong, if format is ok
    let accumulator = generate_programmable_bootstrap_glwe_lut(
        extended_polynomial_size,
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

    let mut keys_gen = |params| multi_bit_gen_keys(params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let (input_lwe_secret_key, output_lwe_secret_key, fbsk) =
        (keys.small_lwe_sk, keys.big_lwe_sk, keys.fbsk);

    while msg != 0u64 {
        msg -= 1;

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
                0u64,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            lwe_multi_bit_sorted_extended_programmable_bootstrapping(
                &lwe_ciphertext_in,
                &mut out_pbs_ct,
                &accumulator,
                &fbsk,
                extension_factor,
                shortcut_coeff_count,
            );

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }
    }
}

#[test]
fn test_toy_params_multibit_sepbs_case() {
    // let params = MultiBitParametersLY23 {
    //     param: crate::shortint::parameters::MultiBitPBSParameters {
    //         lwe_dimension: LweDimension(4),
    //         glwe_dimension: GlweDimension(1),
    //         polynomial_size: PolynomialSize(2048),
    //         lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
    //             0.0,
    //         )),
    //         glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
    //             0.0,
    //         )),
    //         pbs_base_log: DecompositionBaseLog(22),
    //         pbs_level: DecompositionLevelCount(1),
    //         ks_base_log: DecompositionBaseLog(3),
    //         ks_level: DecompositionLevelCount(5),
    //         message_modulus: crate::shortint::parameters::MessageModulus(4),
    //         carry_modulus: crate::shortint::parameters::CarryModulus(4),
    //         max_noise_level: crate::shortint::parameters::MaxNoiseLevel::new(5),
    //         log2_p_fail: 0.0,
    //         ciphertext_modulus: CiphertextModulus::new_native(),
    //         encryption_key_choice: EncryptionKeyChoice::Big,
    //         grouping_factor: LweBskGroupingFactor(2),
    //         deterministic_execution: false,
    //     },
    //     log_extension_factor: 1,
    // };

    let params = MultiBitParametersLY23 {
        param: crate::shortint::parameters::MultiBitPBSParameters {
            lwe_dimension: LweDimension(888),
            glwe_dimension: GlweDimension(1),
            polynomial_size: PolynomialSize(2048),
            lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                1.3998779623487315e-06,
            )),
            glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                2.845267479601915e-15,
            )),
            pbs_base_log: DecompositionBaseLog(21),
            pbs_level: DecompositionLevelCount(1),
            ks_base_log: DecompositionBaseLog(4),
            ks_level: DecompositionLevelCount(4),
            message_modulus: crate::shortint::parameters::MessageModulus(4),
            carry_modulus: crate::shortint::parameters::CarryModulus(4),
            max_noise_level: crate::shortint::parameters::MaxNoiseLevel::new(5),
            log2_p_fail: 0.0,
            ciphertext_modulus: CiphertextModulus::new_native(),
            encryption_key_choice: EncryptionKeyChoice::Big,
            grouping_factor: LweBskGroupingFactor(2),
            deterministic_execution: false,
        },
        log_extension_factor: 2,
    };

    multibit_sepbs_case(params);
}

// N' = 2^nu * N
// new_lut_idx = (ai + old_lut_idx) % 2^nu
// (2^nu + (ai % 2N') - 1 - new_lut_idx)/2^nu a l'air de marcher pour x X^ai

#[test]
fn test_monic_mul_split_eq() {
    use rand::Rng;

    let polynomial_size = PolynomialSize(2048);
    let extension_factor = Ly23ExtensionFactor(1 << 2);
    let small_poly_size = PolynomialSize(polynomial_size.0 / extension_factor.0);

    let mut rng = rand::thread_rng();

    for _ in 0..100 {
        let mut polynomial = Polynomial::new(0u64, polynomial_size);
        // polynomial
        //     .iter_mut()
        //     .enumerate()
        //     .for_each(|(idx, val)| *val = (idx + 1) as u64);
        polynomial.iter_mut().for_each(|x| *x = rng.gen());
        let polynomial = polynomial;
        let mut small_polynomials =
            vec![Polynomial::new(0u64, small_poly_size); extension_factor.0];

        fn split_lut(
            lut: &PolynomialOwned<u64>,
            split_luts: &mut [PolynomialOwned<u64>],
            extension_factor: Ly23ExtensionFactor,
        ) {
            for (idx, &coeff) in lut.as_ref().iter().enumerate() {
                let dst_lut = &mut split_luts[idx % extension_factor.0];
                dst_lut.as_mut()[idx / extension_factor.0] = coeff;
            }
        }

        split_lut(&polynomial, &mut small_polynomials, extension_factor);
        let ref_small_polynomials = small_polynomials;

        // let monomial_degree = MonomialDegree(rng.gen());
        for _ in 0..10000 {
            let mut small_polynomials = ref_small_polynomials.clone();

            // let monomial_degree = MonomialDegree(degree);

            let monomial_degree = MonomialDegree(rng.gen::<usize>() % (polynomial_size.0 * 2));

            let mut rotated_polynomial = polynomial.clone();
            polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign(
                &mut rotated_polynomial,
                monomial_degree,
            );
            let mut small_rotated_polynomials =
                vec![Polynomial::new(0u64, small_poly_size); extension_factor.0];

            split_lut(
                &rotated_polynomial,
                &mut small_rotated_polynomials,
                extension_factor,
            );

            // println!("monomial_degree={monomial_degree:?}");

            // println!(
            //     "monomial_degree % ext = {}, monomial_degree % N = {}",
            //     monomial_degree.0 % extension_factor.0,
            //     monomial_degree.0 % polynomial_size.0
            // );

            // Rotate the lookup tables
            small_polynomials.rotate_right(monomial_degree.0 % extension_factor.0);

            for (lut_idx, small_polynomial) in small_polynomials.iter_mut().enumerate() {
                let small_monomial_degree = MonomialDegree(
                    (extension_factor.0 + monomial_degree.0 - 1 - lut_idx) / extension_factor.0,
                );
                polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign(
                    small_polynomial,
                    small_monomial_degree,
                )
            }

            //     println!(
            //         "{small_rotated_polynomials:?}, \n\
            // {small_polynomials:?}"
            //     );

            assert_eq!(small_rotated_polynomials, small_polynomials);
        }
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

fn lwe_encrypt_pbs_ntt64_decrypt_custom_mod(params: ClassicTestParams<u64>) {
    let input_lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = 1u64 << message_modulus_log.0;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.pbs_base_log;
    let decomp_level_count = params.pbs_level;
    let mut rsc = TestResources::new();

    let f = |x: u64| x.wrapping_rem(msg_modulus);

    let delta: u64 = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;
    const NB_TESTS: usize = 10;

    let accumulator = generate_programmable_bootstrap_glwe_lut(
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

    // Create the LweSecretKey
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        input_lwe_dimension,
        &mut rsc.secret_random_generator,
    );
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    let mut bsk = LweBootstrapKey::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        input_lwe_dimension,
        ciphertext_modulus,
    );

    par_generate_lwe_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        &mut bsk,
        glwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_encrypted_content_respects_mod(
        &*bsk,
        ciphertext_modulus
    ));

    use crate::core_crypto::commons::math::ntt::ntt64::Ntt64;

    let mut nbsk = NttLweBootstrapKeyOwned::new(
        0u64,
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
        bsk.ciphertext_modulus(),
    );

    let mut buffers = ComputationBuffers::new();

    let ntt = Ntt64::new(ciphertext_modulus, nbsk.polynomial_size());
    let ntt = ntt.as_view();

    let stack_size = programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized_requirement(
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ntt,
    )
    .unwrap()
    .try_unaligned_bytes_required()
    .unwrap();

    buffers.resize(stack_size);

    par_convert_standard_lwe_bootstrap_key_to_ntt64(&bsk, &mut nbsk);

    drop(bsk);

    while msg != 0u64 {
        msg = msg.wrapping_sub(1u64);
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
                0u64,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized(
                &lwe_ciphertext_in,
                &mut out_pbs_ct,
                &accumulator,
                &nbsk,
                ntt,
                buffers.stack(),
            );

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }

        // In coverage, we break after one while loop iteration, changing message values does
        // not yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parametrized_test!(lwe_encrypt_pbs_ntt64_decrypt_custom_mod {
    TEST_PARAMS_3_BITS_SOLINAS_U64
});

#[test]
fn test_lwe_encrypt_pbs_switch_mod_switch_scalar_decrypt_custom_mod() {
    let params = super::TEST_PARAMS_4_BITS_NATIVE_U64;

    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution_u64 = params.lwe_noise_distribution;
    let lwe_noise_distribution_u32 =
        DynamicDistribution::new_gaussian(lwe_noise_distribution_u64.gaussian_std_dev());
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let output_ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let output_encoding_with_padding = get_encoding_with_padding(output_ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let pbs_base_log = params.pbs_base_log;
    let pbs_level_count = params.pbs_level;

    let input_ciphertext_modulus = CiphertextModulus::<u32>::new_native();
    let input_encoding_with_padding = get_encoding_with_padding(input_ciphertext_modulus);

    let mut rsc = TestResources::new();

    let input_msg_modulus = 1u32 << message_modulus_log.0;
    let output_msg_modulus = 1u64 << message_modulus_log.0;
    let mut msg = input_msg_modulus;
    let input_delta = input_encoding_with_padding / input_msg_modulus;
    let output_delta = output_encoding_with_padding / output_msg_modulus;

    let f = |x| x;

    let accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        output_msg_modulus.cast_into(),
        output_ciphertext_modulus,
        output_delta,
        f,
    );

    assert!(check_encrypted_content_respects_mod(
        &accumulator,
        output_ciphertext_modulus
    ));

    let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key::<u32, _>(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let lwe_sk_as_u64 = LweSecretKey::from_container(
        lwe_sk
            .as_ref()
            .iter()
            .copied()
            .map(|x| x as u64)
            .collect::<Vec<_>>(),
    );

    let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );

    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_sk_as_u64,
        &glwe_sk,
        pbs_base_log,
        pbs_level_count,
        glwe_noise_distribution,
        output_ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_encrypted_content_respects_mod(
        &*bsk,
        output_ciphertext_modulus
    ));

    let mut fbsk = FourierLweBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );

    par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);
    drop(bsk);

    while msg != 0 {
        msg -= 1;
        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * input_delta);

            let ct = allocate_and_encrypt_new_lwe_ciphertext(
                &lwe_sk,
                plaintext,
                lwe_noise_distribution_u32,
                input_ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                input_ciphertext_modulus
            ));

            let mut output_ct = LweCiphertext::new(
                0u64,
                fbsk.output_lwe_dimension().to_lwe_size(),
                output_ciphertext_modulus,
            );

            programmable_bootstrap_lwe_ciphertext(&ct, &mut output_ct, &accumulator, &fbsk);

            assert!(check_encrypted_content_respects_mod(
                &output_ct,
                output_ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&glwe_sk.as_lwe_secret_key(), &output_ct);

            let decoded = round_decode(decrypted.0, output_delta) % output_msg_modulus;

            assert_eq!(msg as u64, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}
#[derive(Clone, Copy)]
struct ParametersLY23 {
    param: ClassicPBSParameters,
    log_extension_factor: usize,
}

#[derive(Clone, Copy)]
struct MultiBitParametersLY23 {
    param: crate::shortint::parameters::MultiBitPBSParameters,
    log_extension_factor: usize,
}

struct ParametersLY23MS{
    param: ClassicPBSParameters,
    log_extension_factor: u64,
    shortcut_coeff: usize
}

const LY23_2_PARALLEL: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_64,
    log_extension_factor: 4,
};

const LY23_3_PARALLEL: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_1_CARRY_2_PARALLEL_PBS_MS_0_EF_4_64,
    log_extension_factor: 4,
};

const LY23_4_PARALLEL: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_MS_0_EF_4_64,
    log_extension_factor: 4,
};

const LY23_5_PARALLEL: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_2_CARRY_3_PARALLEL_PBS_MS_0_EF_4_64,
    log_extension_factor: 4,
};

const LY23_6_PARALLEL: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_3_CARRY_3_PARALLEL_PBS_MS_0_EF_4_64,
    log_extension_factor: 4,
};

const LY23_7_PARALLEL: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_3_CARRY_4_PARALLEL_PBS_MS_0_EF_4_64,
    log_extension_factor: 4,
};


const LY23_5_40_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_5_BEST_PBS_MS_20_EF_1_40,
    log_extension_factor: 1,
    shortcut_coeff: 20,
};
const LY23_6_40_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_6_BEST_PBS_MS_1_EF_3_40,
    log_extension_factor: 3,
    shortcut_coeff: 1,
};
const LY23_7_40_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_7_BEST_PBS_MS_94_EF_3_40,
    log_extension_factor: 3,
    shortcut_coeff: 94,
};
const LY23_8_40_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_8_BEST_PBS_MS_90_EF_4_40,
    log_extension_factor: 4,
    shortcut_coeff: 90,
};
const LY23_9_40_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_9_BEST_PBS_MS_76_EF_5_40,
    log_extension_factor: 5,
    shortcut_coeff: 76,
};
const LY23_5_80_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_5_BEST_PBS_MS_151_EF_2_80,
    log_extension_factor: 2,
    shortcut_coeff: 151,
};
const LY23_6_80_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_6_BEST_PBS_MS_255_EF_3_80,
    log_extension_factor: 3,
    shortcut_coeff: 255,
};
const LY23_7_80_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_7_BEST_PBS_MS_256_EF_4_80,
    log_extension_factor: 4,
    shortcut_coeff: 256,
};
const LY23_8_80_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_8_BEST_PBS_MS_256_EF_5_80,
    log_extension_factor: 5,
    shortcut_coeff: 256,
};
const LY23_9_80_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_9_BEST_PBS_MS_255_EF_6_80,
    log_extension_factor: 6,
    shortcut_coeff: 255,
};
const LY23_5_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_5_BEST_PBS_MS_0_EF_2_128,
    log_extension_factor: 2,
    shortcut_coeff: 0,
};
const LY23_6_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_6_BEST_PBS_MS_150_EF_3_128,
    log_extension_factor: 3,
    shortcut_coeff: 150,
};
const LY23_7_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_7_BEST_PBS_MS_148_EF_4_128,
    log_extension_factor: 4,
    shortcut_coeff: 148,
};
const LY23_8_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_8_BEST_PBS_MS_137_EF_5_128,
    log_extension_factor: 5,
    shortcut_coeff: 137,
};
const LY23_9_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_9_BEST_PBS_MS_96_EF_6_128,
    log_extension_factor: 6,
    shortcut_coeff: 96,
};
