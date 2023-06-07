use crate::shortint::prelude::{PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_2_CARRY_2};

use crate::integer::casting_key::CastingKey;

#[test]
fn gen_multi_keys_test_rdxinteger_to_rdxinteger() {
    let num_block = 4;

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_1, server_key_1) =
        crate::integer::gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, num_block);

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) =
        crate::integer::gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, num_block);

    // Get casting key
    let ksk = CastingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
    );

    // Encrypt a value and cast
    let ct1 = client_key_1.encrypt(228);
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
        crate::integer::gen_keys_crt(PARAM_MESSAGE_2_CARRY_2, basis.clone());

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) = crate::integer::gen_keys_crt(PARAM_MESSAGE_2_CARRY_2, basis);

    // Get casting key
    let ksk = CastingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
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
        crate::integer::gen_keys_crt(PARAM_MESSAGE_2_CARRY_2, basis.clone());

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) = crate::integer::gen_keys_crt(PARAM_MESSAGE_1_CARRY_1, basis);

    // Get casting key
    let _ = CastingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
    );
}

#[test]
fn gen_multi_keys_test_integer_to_integer() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key_1, server_key_1) = crate::integer::gen_keys(PARAM_MESSAGE_2_CARRY_2);

    // We generate a set of client/server keys, using the default parameters:
    let (client_key_2, server_key_2) = crate::integer::gen_keys(PARAM_MESSAGE_2_CARRY_2);

    // Get casting key
    let ksk = CastingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
    );

    // Encrypt a value and cast
    let ct1 = client_key_1.encrypt_radix(228, 4);
    let ct2 = ksk.cast(&ct1);

    // High level decryption and test
    let clear: u8 = client_key_2.decrypt_radix(&ct2);
    assert_eq!(clear, 228);
}
