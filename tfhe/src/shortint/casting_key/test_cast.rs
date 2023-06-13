use crate::prelude::*;
use crate::{generate_keys, ConfigBuilder, FheUint8};

use crate::shortint::prelude::*;
use crate::shortint::CastingKey;

#[test]
fn gen_multi_keys_test_hlapi() {
    // get low level keys
    let (ck1, sk1): (crate::shortint::ClientKey, crate::shortint::ServerKey) =
        gen_keys(PARAM_MESSAGE_1_CARRY_1);

    // Get high level config and keys
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    let (client_key, server_key) = generate_keys(config);

    // Get casting key
    let ksk = CastingKey::new((&ck1, &sk1), (&client_key, &server_key));

    let hl_api_int: FheUint8 = ksk.cast(vec![
        ck1.encrypt(0),
        ck1.encrypt(1),
        ck1.unchecked_encrypt(2),
        ck1.unchecked_encrypt(3),
    ]);

    // High level decryption and test
    let clear: u8 = hl_api_int.decrypt(&client_key);
    assert_eq!(clear, 228);
}

#[test]
fn gen_multi_keys_test_integer_radix() {
    // get low level keys
    let (ck1, sk1): (crate::shortint::ClientKey, crate::shortint::ServerKey) =
        gen_keys(PARAM_MESSAGE_1_CARRY_1);

    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) =
        crate::integer::gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, num_block);

    // Get casting key
    let ksk = CastingKey::new((&ck1, &sk1), (&client_key, &server_key));

    // Construct a high level object from blocks
    let fhe_int = ksk.cast(vec![
        ck1.encrypt(0),
        ck1.encrypt(1),
        ck1.unchecked_encrypt(2),
        ck1.unchecked_encrypt(3),
    ]);

    // High level decryption and test
    // let clear: u8 = fhe_int.decrypt(&client_key);
    let clear: u64 = client_key.decrypt(&fhe_int);
    assert_eq!(clear, 228);
}

#[test]
fn gen_multi_keys_test_integer_to_integer() {
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
#[should_panic]
fn gen_multi_keys_test_hlapi_fail() {
    // get low level keys
    let (ck1, sk1): (crate::shortint::ClientKey, crate::shortint::ServerKey) =
        gen_keys(PARAM_MESSAGE_1_CARRY_1);

    // Get high level config and keys
    let config = ConfigBuilder::all_disabled().enable_default_bool().build();
    let (client_key, server_key) = generate_keys(config);

    // Get casting key
    let _ksk = CastingKey::new((&ck1, &sk1), (&client_key, &server_key));
}

#[test]
fn gen_multi_keys_test_fresh() {
    let ((ck1, _sk1), (ck2, sk2), ksk) =
        gen_multi_keys(PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_2_CARRY_2);

    assert_eq!(ksk.cast_rshift, 2);

    // Message 0 Carry 0
    let cipher = ck1.encrypt(0);
    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    assert_eq!(clear, 0);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(carry, 0);

    // Message 1 Carry 0
    let cipher = ck1.encrypt(1);
    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    assert_eq!(clear, 1);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(carry, 0);

    // Message 0 Carry 1
    let cipher = ck1.unchecked_encrypt(2);
    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    assert_eq!(clear, 2);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(carry, 0);

    // Message 1 Carry 1
    let cipher = ck1.unchecked_encrypt(3);
    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    assert_eq!(clear, 3);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(carry, 0);
}

// #[test]
// fn gen_multi_keys_test_fresh_2() {
//     let ((ck1, _sk1), (ck2, sk2), ksk) =
//         gen_multi_keys(PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_3_CARRY_3);

//     assert_eq!(ksk.cast_rshift, 4);

//     // Message 0 Carry 0
//     let cipher = ck1.encrypt(0);
//     let output_of_cast = ksk.cast(&cipher);
//     let clear = ck2.decrypt(&output_of_cast);
//     let ct_carry = sk2.carry_extract(&output_of_cast);
//     let carry = ck2.decrypt(&ct_carry);
//     assert_eq!(clear, 0);
//     assert_eq!(carry, 0);

//     // Message 1 Carry 0
//     let cipher = ck1.encrypt(1);
//     let output_of_cast = ksk.cast(&cipher);
//     let clear = ck2.decrypt(&output_of_cast);
//     let ct_carry = sk2.carry_extract(&output_of_cast);
//     let carry = ck2.decrypt(&ct_carry);
//     assert_eq!(clear, 1);
//     assert_eq!(carry, 0);

//     // Message 0 Carry 1
//     let cipher = ck1.unchecked_encrypt(2);
//     let output_of_cast = ksk.cast(&cipher);
//     let clear = ck2.decrypt(&output_of_cast);
//     let ct_carry = sk2.carry_extract(&output_of_cast);
//     let carry = ck2.decrypt(&ct_carry);
//     assert_eq!(clear, 2);
//     assert_eq!(carry, 0);

//     // Message 1 Carry 1
//     let cipher = ck1.unchecked_encrypt(3);
//     let output_of_cast = ksk.cast(&cipher);
//     let clear = ck2.decrypt(&output_of_cast);
//     let ct_carry = sk2.carry_extract(&output_of_cast);
//     let carry = ck2.decrypt(&ct_carry);
//     assert_eq!(clear, 3);
//     assert_eq!(carry, 0);
// }

#[test]
fn gen_multi_keys_test_add_with_overflow() {
    let ((ck1, sk1), (ck2, sk2), ksk) =
        gen_multi_keys(PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_2_CARRY_2);

    // volontary overflow
    let c1 = ck1.encrypt(1);
    let c2 = ck1.encrypt(1);

    let c3 = sk1.unchecked_scalar_mul(&c1, 2);
    let c4 = sk1.unchecked_add(&c3, &c2);

    let output_of_cast = ksk.cast(&c4);
    let clear = ck2.decrypt(&output_of_cast);
    assert_eq!(clear, 3);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(carry, 0);
}

// #[test]
// fn gen_multi_keys_test_no_shift() {
//     let ((_ck1, _sk1), (_ck2, _sk2), ksk) =
//         gen_multi_keys(PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_1_CARRY_1);
//     assert_eq!(ksk.cast_rshift, 0);
// }

// #[test]
// fn gen_multi_keys_test_truncate() {
//     let ((ck1, sk1), (ck2, sk2), ksk) =
//         gen_multi_keys(PARAM_MESSAGE_2_CARRY_2, PARAM_MESSAGE_1_CARRY_1);
//     assert_eq!(ksk.cast_rshift, -2);

//     // Message 0 Carry 0
//     let cipher = ck1.unchecked_encrypt(0);
//     let output_of_cast = ksk.cast(&cipher);
//     let clear = ck2.decrypt(&output_of_cast);
//     assert_eq!(clear, 0);
//     let ct_carry = sk2.carry_extract(&output_of_cast);
//     let carry = ck2.decrypt(&ct_carry);
//     assert_eq!(carry, 0);

//     // Message 1 Carry 0
//     let cipher = ck1.unchecked_encrypt(1);
//     let output_of_cast = ksk.cast(&cipher);
//     let clear = ck2.decrypt(&output_of_cast);
//     assert_eq!(clear, 1);
//     let ct_carry = sk2.carry_extract(&output_of_cast);
//     let carry = ck2.decrypt(&ct_carry);
//     assert_eq!(carry, 0);

//     // Message 0 Carry 1
//     let cipher = ck1.unchecked_encrypt(2);
//     let output_of_cast = ksk.cast(&cipher);
//     let clear = ck2.decrypt(&output_of_cast);
//     assert_eq!(clear, 0);
//     let ct_carry = sk2.carry_extract(&output_of_cast);
//     let carry = ck2.decrypt(&ct_carry);
//     assert_eq!(carry, 1);

//     // Message 1 Carry 1
//     let cipher = ck1.unchecked_encrypt(3);
//     let output_of_cast = ksk.cast(&cipher);
//     let clear = ck2.decrypt(&output_of_cast);
//     assert_eq!(clear, 1);
//     let ct_carry = sk2.carry_extract(&output_of_cast);
//     let carry = ck2.decrypt(&ct_carry);
//     assert_eq!(carry, 1);

//     // Actual truncation
//     let cipher = ck1.unchecked_encrypt(12);
//     let clear = ck1.decrypt(&cipher);
//     let ct_carry = sk1.carry_extract(&cipher);
//     let carry = ck1.decrypt(&ct_carry);
//     assert_eq!((clear, carry), (0, 3));

//     let output_of_cast = ksk.cast(&cipher);
//     let clear = ck2.decrypt(&output_of_cast);
//     assert_eq!(clear, 0);
//     let ct_carry = sk2.carry_extract(&output_of_cast);
//     let carry = ck2.decrypt(&ct_carry);
//     assert_eq!(carry, 0);
// }
