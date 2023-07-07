use crate::shortint::parameters::ShortintKeySwitchingParameters;
use crate::shortint::prelude::*;

#[test]
fn gen_multi_keys_test_fresh() {
    let (ck1, sk1) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    let (ck2, sk2) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let ksk = KeySwitchingKey::new(
        (&ck1, &sk1),
        (&ck2, &sk2),
        PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
    );

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

#[test]
fn gen_multi_keys_test_fresh_2() {
    let (ck1, sk1) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    let (ck2, sk2) = gen_keys(PARAM_MESSAGE_3_CARRY_3_KS_PBS);

    let ksk_params = ShortintKeySwitchingParameters::new(
        ck2.parameters.ks_base_log(),
        ck2.parameters.ks_level(),
    );
    let ksk = KeySwitchingKey::new((&ck1, &sk1), (&ck2, &sk2), ksk_params);

    assert_eq!(ksk.cast_rshift, 4);

    // Message 0 Carry 0
    let cipher = ck1.encrypt(0);
    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(clear, 0);
    assert_eq!(carry, 0);

    // Message 1 Carry 0
    let cipher = ck1.encrypt(1);
    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(clear, 1);
    assert_eq!(carry, 0);

    // Message 0 Carry 1
    let cipher = ck1.unchecked_encrypt(2);
    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(clear, 2);
    assert_eq!(carry, 0);

    // Message 1 Carry 1
    let cipher = ck1.unchecked_encrypt(3);
    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(clear, 3);
    assert_eq!(carry, 0);
}

#[test]
fn gen_multi_keys_test_add_with_overflow() {
    let (ck1, sk1) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    let (ck2, sk2) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let ksk = KeySwitchingKey::new(
        (&ck1, &sk1),
        (&ck2, &sk2),
        PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
    );

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

#[test]
fn gen_multi_keys_test_no_shift() {
    let (ck1, sk1) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    let (ck2, sk2) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);

    let ksk_params = ShortintKeySwitchingParameters::new(
        ck2.parameters.ks_base_log(),
        ck2.parameters.ks_level(),
    );
    let ksk = KeySwitchingKey::new((&ck1, &sk1), (&ck2, &sk2), ksk_params);
    assert_eq!(ksk.cast_rshift, 0);
}

#[test]
fn gen_multi_keys_test_truncate() {
    let (ck1, sk1) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    let (ck2, sk2) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);

    let ksk_params = ShortintKeySwitchingParameters::new(
        ck2.parameters.ks_base_log(),
        ck2.parameters.ks_level(),
    );
    let ksk = KeySwitchingKey::new((&ck1, &sk1), (&ck2, &sk2), ksk_params);
    assert_eq!(ksk.cast_rshift, -2);

    // Message 0 Carry 0
    let cipher = ck1.unchecked_encrypt(0);
    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    assert_eq!(clear, 0);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(carry, 0);

    // Message 1 Carry 0
    let cipher = ck1.unchecked_encrypt(1);
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
    assert_eq!(clear, 0);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(carry, 1);

    // Message 1 Carry 1
    let cipher = ck1.unchecked_encrypt(3);
    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    assert_eq!(clear, 1);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(carry, 1);

    // Actual truncation
    let cipher = ck1.unchecked_encrypt(12);
    let clear = ck1.decrypt(&cipher);
    let ct_carry = sk1.carry_extract(&cipher);
    let carry = ck1.decrypt(&ct_carry);
    assert_eq!((clear, carry), (0, 3));

    let output_of_cast = ksk.cast(&cipher);
    let clear = ck2.decrypt(&output_of_cast);
    assert_eq!(clear, 0);
    let ct_carry = sk2.carry_extract(&output_of_cast);
    let carry = ck2.decrypt(&ct_carry);
    assert_eq!(carry, 0);
}
