use crate::shortint::parameters::ShortintKeySwitchingParameters;
use crate::shortint::prelude::{PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS};

use crate::integer::key_switching_key::KeySwitchingKey;

#[test]
fn gen_multi_keys_test_rdxinteger_to_rdxinteger() {
    let num_block = 4;

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_1, server_key_1) =
        crate::integer::gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) =
        crate::integer::gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);

    // Get casting key
    let ksk_params = ShortintKeySwitchingParameters::new(
        client_key_2.parameters().ks_base_log(),
        client_key_2.parameters().ks_level(),
    );
    let ksk = KeySwitchingKey::new(
        (&client_key_1, &server_key_1),
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
fn gen_multi_keys_test_crtinteger_to_crtinteger() {
    let basis = vec![2, 3, 5, 7, 11];

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_1, server_key_1) =
        crate::integer::gen_keys_crt(PARAM_MESSAGE_2_CARRY_2_KS_PBS, basis.clone());

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) =
        crate::integer::gen_keys_crt(PARAM_MESSAGE_2_CARRY_2_KS_PBS, basis);

    // Get casting key
    let ksk_params = ShortintKeySwitchingParameters::new(
        client_key_2.parameters().ks_base_log(),
        client_key_2.parameters().ks_level(),
    );
    let ksk = KeySwitchingKey::new(
        (&client_key_1, &server_key_1),
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
#[should_panic]
fn gen_multi_keys_test_crtinteger_to_crtinteger_fail() {
    let basis = vec![2, 3, 5, 7, 11];

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_1, server_key_1) =
        crate::integer::gen_keys_crt(PARAM_MESSAGE_2_CARRY_2_KS_PBS, basis.clone());

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) =
        crate::integer::gen_keys_crt(PARAM_MESSAGE_1_CARRY_1_KS_PBS, basis);

    // Get casting key
    let ksk_params = ShortintKeySwitchingParameters::new(
        client_key_2.parameters().ks_base_log(),
        client_key_2.parameters().ks_level(),
    );
    let _ = KeySwitchingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
        ksk_params,
    );
}

#[test]
fn gen_multi_keys_test_integer_to_integer() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key_1, server_key_1) = crate::integer::gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) = crate::integer::gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // Get casting key
    let ksk_params = ShortintKeySwitchingParameters::new(
        client_key_2.parameters().ks_base_log(),
        client_key_2.parameters().ks_level(),
    );
    let ksk = KeySwitchingKey::new(
        (&client_key_1, &server_key_1),
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
