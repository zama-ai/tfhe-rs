use super::*;
use crate::core_crypto::keycache::KeyCacheAccess;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(feature = "__coverage")]
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
        params.glwe_modular_std_dev,
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
        glwe_sk: output_glwe_secret_key,
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
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
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
                lwe_modular_std_dev,
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
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test!(lwe_encrypt_pbs_decrypt_custom_mod);

// DISCLAIMER: all parameters here are not guaranteed to be secure or yield correct computations
pub const TEST_PARAMS_4_BITS_NATIVE_U128: ClassicTestParams<u128> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(4.9982771e-11),
    glwe_modular_std_dev: StandardDev(8.6457178e-32),
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
    lwe_modular_std_dev: StandardDev(4.9982771e-11),
    glwe_modular_std_dev: StandardDev(8.6457178e-32),
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
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
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
                lwe_modular_std_dev,
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
        #[cfg(feature = "__coverage")]
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

fn blind_rotate<Scalar>(params: ClassicTestParams<Scalar>)
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
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;

    let mut rsc = TestResources::new();

    let input_message = msg_modulus.wrapping_sub(Scalar::ONE);

    let f = |x: Scalar| Scalar::TWO * x;

    let delta: Scalar = encoding_with_padding / msg_modulus;

    let mut accumulator = generate_accumulator(
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

    // Apply our encoding
    let plaintext = Plaintext(input_message * delta);

    let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        plaintext,
        lwe_modular_std_dev,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    // Allocate the LweCiphertext to store the result of the PBS
    let mut pbs_multiplication_ct = LweCiphertext::new(
        Scalar::ZERO,
        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    blind_rotate_assign(&lwe_ciphertext_in, &mut accumulator, &fbsk);

    extract_lwe_sample_from_glwe_ciphertext(
        &accumulator,
        &mut pbs_multiplication_ct,
        MonomialDegree(0),
    );

    // Decrypt the PBS multiplication result
    let pbs_multiplication_plaintext =
        decrypt_lwe_ciphertext(&output_lwe_secret_key, &pbs_multiplication_ct);

    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of message modulus (n) and a DecompositionLevelCount of 1
    // indicating we want to round the n+1 MSB, 1 bit of padding plus our n bits of message
    let signed_decomposer = SignedDecomposer::new(
        DecompositionBaseLog(message_modulus_log.0 + 1),
        DecompositionLevelCount(1),
    );

    // Round and remove our encoding
    let pbs_multiplication_result =
        signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

    assert_eq!(pbs_multiplication_result, f(input_message));
}

create_parametrized_test!(blind_rotate);

fn add_external_product<Scalar>(params: ClassicTestParams<Scalar>)
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
    let glwe_size = GlweSize(2);
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.pbs_base_log;
    let decomp_level_count = params.pbs_level;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;

    let mut rsc = TestResources::new();

    let input_message = msg_modulus.wrapping_sub(Scalar::ONE);
    let delta: Scalar = (encoding_with_padding / msg_modulus) * Scalar::TWO;

    let mut keys_gen = |params| generate_keys(params, &mut rsc);

    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let glwe_secret_key = keys.glwe_sk;

    let msg_ggsw = Plaintext(input_message * delta);

    // Create a new GgswCiphertext
    let mut ggsw = GgswCiphertext::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        ciphertext_modulus,
    );

    encrypt_constant_ggsw_ciphertext(
        &glwe_secret_key,
        &mut ggsw,
        msg_ggsw,
        glwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    let ct_plaintext = Plaintext(input_message * delta);

    let ct_plaintexts = PlaintextList::new(ct_plaintext.0, PlaintextCount(polynomial_size.0));

    let mut ct = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut ct,
        &ct_plaintexts,
        glwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();
    let mut buffers = ComputationBuffers::new();

    let buffer_size_req = add_external_product_assign_mem_optimized_requirement::<Scalar>(
        glwe_size,
        polynomial_size,
        fft,
    )
    .unwrap()
    .unaligned_bytes_required();

    let buffer_size_req = buffer_size_req.max(
        convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );

    buffers.resize(buffer_size_req);

    let mut fourier_ggsw = FourierGgswCiphertext::new(
        glwe_size,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
    );

    convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
        &ggsw,
        &mut fourier_ggsw,
        fft,
        buffers.stack(),
    );

    let mut ct_out = ct.clone();

    add_external_product_assign(&mut ct_out, &fourier_ggsw, &ct);

    let mut output_plaintext_list =
        PlaintextList::new(Scalar::ZERO, ct_plaintexts.plaintext_count());

    decrypt_glwe_ciphertext(&glwe_secret_key, &ct_out, &mut output_plaintext_list);

    let signed_decomposer = SignedDecomposer::new(
        DecompositionBaseLog(message_modulus_log.0),
        DecompositionLevelCount(1),
    );

    output_plaintext_list
        .iter_mut()
        .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));

    // As we cloned the input ciphertext for the output, the external product result is added to the
    // originally contained value, hence why we expect ct_plaintext + ct_plaintext * msg_ggsw
    let expected = ct_plaintext.0 + ct_plaintext.0 * msg_ggsw.0;

    assert!(output_plaintext_list.iter().all(|x| *x.0 == expected));
}

// FIXME: test works with native value for ciphertext modulus but fails with custom one
create_parametrized_test!(add_external_product {
    TEST_PARAMS_4_BITS_NATIVE_U64
});

fn cmux<Scalar>(params: ClassicTestParams<Scalar>)
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
    let glwe_size = GlweSize(2);
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.pbs_base_log;
    let decomp_level_count = params.pbs_level;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;

    let mut rsc = TestResources::new();

    let delta: Scalar = (encoding_with_padding / msg_modulus) * Scalar::TWO;

    let mut keys_gen = |params| generate_keys(params, &mut rsc);

    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let glwe_secret_key = keys.glwe_sk;

    // Create the plaintext
    let msg_ggsw_0 = Plaintext(Scalar::ZERO);

    // Create a new GgswCiphertext
    let mut ggsw_0 = GgswCiphertext::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        ciphertext_modulus,
    );

    encrypt_constant_ggsw_ciphertext(
        &glwe_secret_key,
        &mut ggsw_0,
        msg_ggsw_0,
        glwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    // Create the plaintext
    let msg_ggsw_1 = Plaintext(Scalar::ONE);

    // Create a new GgswCiphertext
    let mut ggsw_1 = GgswCiphertext::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        ciphertext_modulus,
    );

    encrypt_constant_ggsw_ciphertext(
        &glwe_secret_key,
        &mut ggsw_1,
        msg_ggsw_1,
        glwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    let ct0_plaintext = Plaintext(Scalar::ONE * delta);
    let ct1_plaintext = Plaintext(msg_modulus.wrapping_sub(Scalar::ONE) * delta);

    let ct0_plaintexts = PlaintextList::new(ct0_plaintext.0, PlaintextCount(polynomial_size.0));
    let ct1_plaintexts = PlaintextList::new(ct1_plaintext.0, PlaintextCount(polynomial_size.0));

    let mut ct0 = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut ct1 = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut ct0,
        &ct0_plaintexts,
        glwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut ct1,
        &ct1_plaintexts,
        glwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();
    let mut buffers = ComputationBuffers::new();

    let buffer_size_req =
        cmux_assign_mem_optimized_requirement::<Scalar>(glwe_size, polynomial_size, fft)
            .unwrap()
            .unaligned_bytes_required();

    let buffer_size_req = buffer_size_req.max(
        convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
            .unwrap()
            .unaligned_bytes_required(),
    );

    buffers.resize(buffer_size_req);

    let mut fourier_ggsw_0 = FourierGgswCiphertext::new(
        glwe_size,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
    );
    let mut fourier_ggsw_1 = FourierGgswCiphertext::new(
        glwe_size,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
    );

    convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
        &ggsw_0,
        &mut fourier_ggsw_0,
        fft,
        buffers.stack(),
    );

    convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
        &ggsw_1,
        &mut fourier_ggsw_1,
        fft,
        buffers.stack(),
    );

    let mut ct0_clone = ct0.clone();
    let mut ct1_clone = ct1.clone();

    cmux_assign(&mut ct0_clone, &mut ct1_clone, &fourier_ggsw_0);

    let mut output_plaintext_list_0 =
        PlaintextList::new(Scalar::ZERO, ct0_plaintexts.plaintext_count());

    decrypt_glwe_ciphertext(&glwe_secret_key, &ct0_clone, &mut output_plaintext_list_0);

    let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

    output_plaintext_list_0
        .iter_mut()
        .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));

    assert!(output_plaintext_list_0
        .iter()
        .all(|x| *x.0 == ct0_plaintext.0));

    cmux_assign_mem_optimized(&mut ct0, &mut ct1, &fourier_ggsw_1, fft, buffers.stack());

    let mut output_plaintext_list_1 =
        PlaintextList::new(Scalar::ZERO, ct1_plaintexts.plaintext_count());

    decrypt_glwe_ciphertext(&glwe_secret_key, &ct0, &mut output_plaintext_list_1);

    output_plaintext_list_1
        .iter_mut()
        .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));

    assert!(output_plaintext_list_1
        .iter()
        .all(|x| *x.0 == ct1_plaintext.0));
}

create_parametrized_test!(cmux);
