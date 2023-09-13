#![cfg(any(feature = "integer", feature = "shortint"))]

//! For now, in this test file, we don't want to check results
//! but rather check that short int, int, dyn short int, dyn int
//! all overload the same operators.
//!
//! For each operator overloaded operator we want to support $ variants:
//!
//! lhs + rhs
//! lhs + &rhs
//! &lhs + rhs
//! &lhs + &rhs
use crate::prelude::*;
use crate::{generate_keys, set_server_key, ClientKey, ConfigBuilder};
use std::fmt::Debug;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Rem, Shl, Shr, Sub};

macro_rules! define_operation_test {
    ($name:ident => ($trait:ident, $symbol:tt)) => {
        fn $name<T>(lhs: T, rhs: T)
        where
            T: Clone + $trait<T, Output = T>,
            T: for<'a> $trait<&'a T, Output = T>,
            for<'a> &'a T: $trait<T, Output = T> + $trait<&'a T, Output = T>,
        {
            let _ = &lhs $symbol &rhs;

            let _ = &lhs $symbol rhs.clone();

            let _ = lhs.clone() $symbol &rhs;

            let _ = lhs $symbol rhs;
        }
    };
}

/// We keep this to improve tests later
#[allow(dead_code)]
fn static_supports_all_add_ways<T, FheT>(lhs_clear: T, rhs_clear: T, client_key: &ClientKey)
where
    T: Add<T, Output = T> + Copy + Debug + PartialEq,
    FheT: FheTryEncrypt<T, ClientKey> + FheDecrypt<T>,
    FheT: Clone + Add<FheT, Output = FheT>,
    FheT: for<'a> Add<&'a FheT, Output = FheT>,
    for<'a> &'a FheT: Add<FheT, Output = FheT> + Add<&'a FheT, Output = FheT>,
{
    let lhs = FheT::try_encrypt(lhs_clear, client_key).unwrap();
    let rhs = FheT::try_encrypt(lhs_clear, client_key).unwrap();

    let expected = lhs_clear + rhs_clear;

    let r = &lhs + &rhs;
    let dec_r = r.decrypt(client_key);
    assert_eq!(dec_r, expected);

    let r = &lhs + rhs.clone();
    let dec_r = r.decrypt(client_key);
    assert_eq!(dec_r, expected);

    let r = lhs.clone() + &rhs;
    let dec_r = r.decrypt(client_key);
    assert_eq!(dec_r, expected);

    let r = lhs + rhs;
    let dec_r = r.decrypt(client_key);
    assert_eq!(dec_r, expected);
}

define_operation_test!(supports_all_add_ways => (Add, +));
define_operation_test!(supports_all_sub_ways => (Sub, -));
define_operation_test!(supports_all_mul_ways => (Mul, *));
define_operation_test!(supports_all_div_ways => (Div, /));
define_operation_test!(supports_all_bitand_ways => (BitAnd, &));
define_operation_test!(supports_all_bitor_ways => (BitOr, |));
define_operation_test!(supports_all_bitxor_ways => (BitXor, ^));

fn supports_scalar_add_with_u8<T>(lhs: T, rhs: u8)
where
    T: Clone + Add<u8, Output = T>,
    for<'a> &'a T: Add<u8, Output = T>,
    u8: Add<T, Output = T>,
    u8: for<'a> Add<&'a T, Output = T>,
{
    let _ = &lhs + rhs;
    let _ = lhs.clone() + rhs;

    let _ = rhs + &lhs;
    let _ = rhs + lhs;
}

fn supports_scalar_div_with_u8<T>(lhs: T, rhs: u8)
where
    T: Clone + Div<u8, Output = T>,
    for<'a> &'a T: Div<u8, Output = T>,
    u8: Div<T, Output = T>,
    u8: for<'a> Div<&'a T, Output = T>,
{
    let _ = &lhs / rhs;
    let _ = lhs.clone() / rhs;

    let _ = rhs / &lhs;
    let _ = rhs / lhs;
}

fn supports_scalar_shl_with_u8<T>(lhs: T, rhs: u8)
where
    T: Clone + Shl<u8, Output = T>,
    for<'a> &'a T: Shl<u8, Output = T>,
    u8: Shl<T, Output = T>,
    u8: for<'a> Shl<&'a T, Output = T>,
{
    let _ = &lhs << rhs;
    let _ = lhs.clone() << rhs;

    let _ = rhs << &lhs;
    let _ = rhs << lhs;
}

fn supports_scalar_shr_with_u8<T>(lhs: T, rhs: u8)
where
    T: Clone + Shr<u8, Output = T>,
    for<'a> &'a T: Shr<u8, Output = T>,
    u8: Shr<T, Output = T>,
    u8: for<'a> Shr<&'a T, Output = T>,
{
    let _ = &lhs >> rhs;
    let _ = lhs.clone() >> rhs;

    let _ = rhs >> &lhs;
    let _ = rhs >> lhs;
}

fn supports_scalar_mod_with_u8<T>(lhs: T, rhs: u8)
where
    T: Clone + Rem<u8, Output = T>,
    for<'a> &'a T: Rem<u8, Output = T>,
    u8: Rem<T, Output = T>,
    u8: for<'a> Rem<&'a T, Output = T>,
{
    let _ = &lhs % rhs;
    let _ = lhs.clone() % rhs;

    let _ = rhs % &lhs;
    let _ = rhs % lhs;
}

fn supports_scalar_mul_with_u8<T>(lhs: T, rhs: u8)
where
    T: Clone + Mul<u8, Output = T>,
    for<'a> &'a T: Mul<u8, Output = T>,
    u8: Mul<T, Output = T>,
    u8: for<'a> Mul<&'a T, Output = T>,
{
    let _ = &lhs * rhs;
    let _ = lhs.clone() * rhs;

    let _ = rhs * &lhs;
    let _ = rhs * lhs;
}

#[cfg(feature = "shortint")]
#[test]
fn test_static_shortint_supports_ops() {
    use crate::FheUint2;

    let config = ConfigBuilder::all_disabled().enable_default_uint2().build();
    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let lhs = FheUint2::try_encrypt(0, &client_key).unwrap();
    let rhs = FheUint2::try_encrypt(1, &client_key).unwrap();

    supports_all_add_ways(lhs.clone(), rhs.clone());
    supports_all_mul_ways(lhs.clone(), rhs.clone());
    supports_all_sub_ways(lhs.clone(), rhs.clone());
    supports_all_div_ways(lhs.clone(), rhs.clone());
    supports_all_bitand_ways(lhs.clone(), rhs.clone());
    supports_all_bitor_ways(lhs.clone(), rhs.clone());
    supports_all_bitxor_ways(lhs.clone(), rhs);
    supports_scalar_mul_with_u8(lhs.clone(), 1);
    supports_scalar_add_with_u8(lhs.clone(), 1);
    supports_scalar_div_with_u8(lhs.clone(), 1);
    supports_scalar_mod_with_u8(lhs.clone(), 1);
    supports_scalar_shl_with_u8(lhs.clone(), 1);
    supports_scalar_shr_with_u8(lhs, 1);
}

#[cfg(feature = "integer")]
#[test]
fn test_static_supports_ops() {
    use crate::FheUint8;

    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let lhs = FheUint8::encrypt(0u8, &client_key);
    let rhs = FheUint8::encrypt(1u8, &client_key);

    supports_all_add_ways(lhs.clone(), rhs.clone());
    supports_all_mul_ways(lhs.clone(), rhs.clone());
    supports_all_sub_ways(lhs, rhs);
}
