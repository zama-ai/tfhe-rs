use crate::integer::key_switching_key::KeySwitchingKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::parameters::IntegerCompactCiphertextListExpansionMode;
use crate::integer::{
    ClientKey, CompactPrivateKey, CompactPublicKey, CrtClientKey, IntegerCiphertext,
    IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey,
};
use crate::shortint::parameters::test_params::{
    TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{
    ClassicPBSParameters, CompactPublicKeyEncryptionParameters, ShortintKeySwitchingParameters,
};

#[test]
fn gen_multi_keys_test_rdxinteger_to_rdxinteger_ci_run_filter() {
    let num_block = 4;

    let client_key_1 = RadixClientKey::new(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        num_block,
    );

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) = KEY_CACHE.get_from_params(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        IntegerKeyKind::Radix,
    );
    let client_key_2 = RadixClientKey::from((client_key_2, num_block));

    assert_eq!(
        client_key_1.parameters().encryption_key_choice(),
        client_key_2.parameters().encryption_key_choice(),
        "This test requires the same encryption key choice"
    );

    // Get casting key
    let ksk_params = ShortintKeySwitchingParameters::new(
        client_key_2.parameters().ks_base_log(),
        client_key_2.parameters().ks_level(),
        client_key_2.parameters().encryption_key_choice(),
    );
    let ksk = KeySwitchingKey::new(
        (&client_key_1, None),
        (&client_key_2, &server_key_2),
        ksk_params,
    );

    // Encrypt a value and cast
    let ct1 = client_key_1.encrypt(228u8);
    let ct2 = ksk.cast(&ct1);

    // High level decryption and test
    let clear: u64 = client_key_2.decrypt(&ct2);
    assert_eq!(clear, 228);
}

#[test]
fn gen_multi_keys_test_crtinteger_to_crtinteger_ci_run_filter() {
    let basis = vec![2, 3, 5, 7, 11];

    let client_key_1 = CrtClientKey::new(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        basis.clone(),
    );

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) = KEY_CACHE.get_from_params(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        IntegerKeyKind::CRT,
    );
    let client_key_2 = CrtClientKey::from((client_key_2, basis));

    assert_eq!(
        client_key_1.parameters().encryption_key_choice(),
        client_key_2.parameters().encryption_key_choice(),
        "This test requires the same encryption key choice"
    );

    // Get casting key
    let ksk_params = ShortintKeySwitchingParameters::new(
        client_key_2.parameters().ks_base_log(),
        client_key_2.parameters().ks_level(),
        client_key_2.parameters().encryption_key_choice(),
    );
    let ksk = KeySwitchingKey::new(
        (&client_key_1, None),
        (&client_key_2, &server_key_2),
        ksk_params,
    );

    // Encrypt a value and cast
    let ct1 = client_key_1.encrypt(228);
    let ct2 = ksk.cast(&ct1);

    // High level decryption and test
    let clear: u64 = client_key_2.decrypt(&ct2);
    assert_eq!(clear, 228);
}

#[test]
#[should_panic(
    expected = "Attempt to build a KeySwitchingKey between integer key pairs with different message modulus and carry"
)]
fn gen_multi_keys_test_crtinteger_to_crtinteger_fail_ci_run_filter() {
    let basis = vec![2, 3, 5, 7, 11];

    let (client_key_1, server_key_1) = KEY_CACHE.get_from_params(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        IntegerKeyKind::CRT,
    );
    let client_key_1 = CrtClientKey::from((client_key_1, basis.clone()));

    let (client_key_2, server_key_2) = KEY_CACHE.get_from_params(
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        IntegerKeyKind::CRT,
    );
    let client_key_2 = CrtClientKey::from((client_key_2, basis));

    assert_eq!(
        client_key_1.parameters().encryption_key_choice(),
        client_key_2.parameters().encryption_key_choice(),
        "This test requires the same encryption key choice"
    );

    // Get casting key
    let ksk_params = ShortintKeySwitchingParameters::new(
        client_key_2.parameters().ks_base_log(),
        client_key_2.parameters().ks_level(),
        client_key_2.parameters().encryption_key_choice(),
    );
    let _ = KeySwitchingKey::new(
        (&client_key_1, Some(&server_key_1)),
        (&client_key_2, &server_key_2),
        ksk_params,
    );
}

#[test]
fn gen_multi_keys_test_integer_to_integer_ci_run_filter() {
    // We generate a set of client keys, using the default parameters:
    let client_key_1 = ClientKey::new(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) = KEY_CACHE.get_from_params(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        IntegerKeyKind::Radix,
    );

    assert_eq!(
        client_key_1.parameters().encryption_key_choice(),
        client_key_2.parameters().encryption_key_choice(),
        "This test requires the same encryption key choice"
    );

    // Get casting key
    let ksk_params = ShortintKeySwitchingParameters::new(
        client_key_2.parameters().ks_base_log(),
        client_key_2.parameters().ks_level(),
        client_key_2.parameters().encryption_key_choice(),
    );
    let ksk = KeySwitchingKey::new(
        (&client_key_1, None),
        (&client_key_2, &server_key_2),
        ksk_params,
    );

    // Encrypt a value and cast
    let ct1 = client_key_1.encrypt_radix(228u8, 4);
    let ct2 = ksk.cast(&ct1);

    // High level decryption and test
    let clear: u8 = client_key_2.decrypt_radix(&ct2);
    assert_eq!(clear, 228);
}

fn test_case_cpk_encrypt_cast_compute(
    param_pke_only: CompactPublicKeyEncryptionParameters,
    param_fhe: ClassicPBSParameters,
    param_ksk: ShortintKeySwitchingParameters,
) {
    let num_block = 4usize;

    assert_eq!(param_pke_only.message_modulus, param_fhe.message_modulus);
    assert_eq!(param_pke_only.carry_modulus, param_fhe.carry_modulus);

    let modulus = param_fhe.message_modulus.0.pow(num_block as u32);

    let compact_private_key = CompactPrivateKey::new(param_pke_only);
    let pk = CompactPublicKey::new(&compact_private_key);

    let cks_fhe = ClientKey::new(param_fhe);
    let sks_fhe = ServerKey::new_radix_server_key(&cks_fhe);

    // We do not need the sks_pke for the input here
    let ksk = KeySwitchingKey::new(
        (&compact_private_key, None),
        (&cks_fhe, &sks_fhe),
        param_ksk,
    );

    use rand::Rng;
    let mut rng = rand::rng();

    let input_msg: u64 = rng.gen_range(0..modulus);

    // Encrypt a value and cast
    let ct1 = pk.encrypt_radix_compact(input_msg, num_block);
    let expander = ct1
        .expand(IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(ksk.as_view()))
        .unwrap();
    let mut ct1_extracted_and_cast = expander.get::<RadixCiphertext>(0).unwrap().unwrap();

    assert!(ct1_extracted_and_cast
        .blocks()
        .iter()
        .all(|x| x.degree.get() == sks_fhe.message_modulus().0 - 1));

    let sanity_pbs: u64 = cks_fhe.decrypt_radix(&ct1_extracted_and_cast);
    assert_eq!(sanity_pbs, input_msg);

    let multiplier = rng.gen_range(0..modulus);

    // Classical AP: DP, KS, PBS
    sks_fhe.scalar_mul_assign_parallelized(&mut ct1_extracted_and_cast, multiplier);

    {
        let acc = sks_fhe.key.generate_lookup_table(|x| x);
        let mut input_fresh = cks_fhe.encrypt_radix(input_msg, num_block);
        for ct in input_fresh.blocks_mut() {
            sks_fhe.key.apply_lookup_table_assign(ct, &acc);
        }
        sks_fhe.scalar_mul_assign_parallelized(&mut input_fresh, multiplier);
        // High level decryption and test
        let clear_fresh = cks_fhe.decrypt_radix::<u64>(&input_fresh) % modulus;
        assert_eq!(clear_fresh, (input_msg * multiplier) % modulus);
    }

    // High level decryption and test
    let clear = cks_fhe.decrypt_radix::<u64>(&ct1_extracted_and_cast) % modulus;
    assert_eq!(clear, (input_msg * multiplier) % modulus);
}

#[test]
fn test_cpk_encrypt_cast_to_small_compute_big_ci_run_filter() {
    test_case_cpk_encrypt_cast_compute(
        TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_cpk_encrypt_cast_to_big_compute_big_ci_run_filter() {
    test_case_cpk_encrypt_cast_compute(
        TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}
