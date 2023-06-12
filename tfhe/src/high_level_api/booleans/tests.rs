// Without this, clippy will conplain about equal expressions to `ffalse & ffalse`
// However since we overloaded these operators, we want to test them to see
// if they are correct
#![allow(clippy::eq_op)]
#![allow(clippy::bool_assert_comparison)]
use std::ops::{BitAnd, BitOr, BitXor, Not};

use crate::high_level_api::prelude::*;
use crate::high_level_api::{
    generate_keys, set_server_key, CastingKey, ClientKey, CompressedFheBool, ConfigBuilder,
    FheBool, FheBoolParameters,
};
use crate::CompressedPublicKey;

fn setup_static_default() -> ClientKey {
    let config = ConfigBuilder::all_disabled().enable_default_bool().build();

    let (my_keys, server_keys) = generate_keys(config);

    set_server_key(server_keys);
    my_keys
}

fn setup_static_tfhe() -> ClientKey {
    let config = ConfigBuilder::all_disabled()
        .enable_custom_bool(FheBoolParameters::tfhe_lib())
        .build();

    let (my_keys, server_keys) = generate_keys(config);

    set_server_key(server_keys);
    my_keys
}

#[test]
fn test_xor_truth_table_static_default() {
    let keys = setup_static_default();

    let ttrue = FheBool::encrypt(true, &keys);
    let ffalse = FheBool::encrypt(false, &keys);

    xor_truth_table(&ttrue, &ffalse, &keys);
}

#[test]
fn test_and_truth_table_static_default() {
    let keys = setup_static_default();

    let ttrue = FheBool::encrypt(true, &keys);
    let ffalse = FheBool::encrypt(false, &keys);

    and_truth_table(&ttrue, &ffalse, &keys);
}

#[test]
fn test_or_truth_table_static_default() {
    let keys = setup_static_default();

    let ttrue = FheBool::encrypt(true, &keys);
    let ffalse = FheBool::encrypt(false, &keys);

    or_truth_table(&ttrue, &ffalse, &keys);
}

#[test]
fn test_not_truth_table_static_default() {
    let keys = setup_static_default();

    let ttrue = FheBool::encrypt(true, &keys);
    let ffalse = FheBool::encrypt(false, &keys);

    not_truth_table(&ttrue, &ffalse, &keys);
}

#[test]
fn test_xor_truth_table_static_tfhe() {
    let keys = setup_static_tfhe();

    let ttrue = FheBool::encrypt(true, &keys);
    let ffalse = FheBool::encrypt(false, &keys);

    xor_truth_table(&ttrue, &ffalse, &keys);
}

#[test]
fn test_and_truth_table_static_tfhe() {
    let keys = setup_static_tfhe();

    let ttrue = FheBool::encrypt(true, &keys);
    let ffalse = FheBool::encrypt(false, &keys);

    and_truth_table(&ttrue, &ffalse, &keys);
}

#[test]
fn test_or_truth_table_static_tfhe() {
    let keys = setup_static_tfhe();

    let ttrue = FheBool::encrypt(true, &keys);
    let ffalse = FheBool::encrypt(false, &keys);

    or_truth_table(&ttrue, &ffalse, &keys);
}

#[test]
fn test_not_truth_table_static_tfhe() {
    let keys = setup_static_tfhe();

    let ttrue = FheBool::encrypt(true, &keys);
    let ffalse = FheBool::encrypt(false, &keys);

    not_truth_table(&ttrue, &ffalse, &keys);
}

fn xor_truth_table<'a, BoolType>(ttrue: &'a BoolType, ffalse: &'a BoolType, key: &ClientKey)
where
    &'a BoolType: BitXor<&'a BoolType, Output = BoolType>,
    BoolType: FheDecrypt<bool>,
{
    let r = ffalse ^ ffalse;
    assert_eq!(r.decrypt(key), false);

    let r = ffalse ^ ttrue;
    assert_eq!(r.decrypt(key), true);

    let r = ttrue ^ ffalse;
    assert_eq!(r.decrypt(key), true);

    let r = ttrue ^ ttrue;
    assert_eq!(r.decrypt(key), false);
}

fn and_truth_table<'a, BoolType>(ttrue: &'a BoolType, ffalse: &'a BoolType, key: &ClientKey)
where
    &'a BoolType: BitAnd<&'a BoolType, Output = BoolType>,
    BoolType: FheDecrypt<bool>,
{
    let r = ffalse & ffalse;
    assert_eq!(r.decrypt(key), false);

    let r = ffalse & ttrue;
    assert_eq!(r.decrypt(key), false);

    let r = ttrue & ffalse;
    assert_eq!(r.decrypt(key), false);

    let r = ttrue & ttrue;
    assert_eq!(r.decrypt(key), true);
}

fn or_truth_table<'a, BoolType>(ttrue: &'a BoolType, ffalse: &'a BoolType, key: &ClientKey)
where
    &'a BoolType: BitOr<&'a BoolType, Output = BoolType>,
    BoolType: FheDecrypt<bool>,
{
    let r = ffalse | ffalse;
    assert_eq!(r.decrypt(key), false);

    let r = ffalse | ttrue;
    assert_eq!(r.decrypt(key), true);

    let r = ttrue | ffalse;
    assert_eq!(r.decrypt(key), true);

    let r = ttrue | ttrue;
    assert_eq!(r.decrypt(key), true);
}

fn not_truth_table<'a, BoolType>(ttrue: &'a BoolType, ffalse: &'a BoolType, key: &ClientKey)
where
    &'a BoolType: Not<Output = BoolType>,
    BoolType: FheDecrypt<bool>,
{
    let r = !ffalse;
    assert_eq!(r.decrypt(key), true);

    let r = !ttrue;
    assert_eq!(r.decrypt(key), false);
}

#[test]
fn test_compressed_bool() {
    let keys = setup_static_default();

    let cttrue = CompressedFheBool::encrypt(true, &keys);
    let cffalse = CompressedFheBool::encrypt(false, &keys);

    let a = FheBool::from(cttrue);
    let b = FheBool::from(cffalse);

    assert_eq!(a.decrypt(&keys), true);
    assert_eq!(b.decrypt(&keys), false);
}

#[test]
fn test_trivial_bool() {
    let keys = setup_static_default();

    let a = FheBool::encrypt_trivial(true);
    let b = FheBool::encrypt_trivial(false);

    assert_eq!(a.decrypt(&keys), true);
    assert_eq!(b.decrypt(&keys), false);
}

#[test]
fn test_compressed_public_key_encrypt() {
    let config = ConfigBuilder::all_disabled().enable_default_bool().build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompressedPublicKey::new(&client_key);

    let a = FheBool::try_encrypt(true, &public_key).unwrap();
    let clear: bool = a.decrypt(&client_key);
    assert_eq!(clear, true);
}

#[test]
fn test_decompressed_public_key_encrypt() {
    let config = ConfigBuilder::all_disabled().enable_default_bool().build();
    let (client_key, _) = generate_keys(config);

    let compressed_public_key = CompressedPublicKey::new(&client_key);
    let public_key = compressed_public_key.decompress();

    let a = FheBool::try_encrypt(true, &public_key).unwrap();
    let clear: bool = a.decrypt(&client_key);
    assert_eq!(clear, true);
}

#[test]
fn test_boolean_casting_key() {
    let config = ConfigBuilder::all_disabled().enable_default_bool().build();
    let (client_key_1, server_key_1) = generate_keys(config.clone());
    let (client_key_2, server_key_2) = generate_keys(config);

    let ksk = CastingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
    );

    let mut ct_true = FheBool::encrypt(true, &client_key_1);
    ct_true = ct_true.cast(&ksk);
    let clear = ct_true.decrypt(&client_key_2);
    assert_eq!(clear, true);

    let mut ct_false = FheBool::encrypt(false, &client_key_1);
    ct_false = ct_false.cast(&ksk);
    let clear = ct_false.decrypt(&client_key_2);
    assert_eq!(clear, false);
}
