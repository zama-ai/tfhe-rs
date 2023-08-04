use crate::c_api::high_level_api::keys::{ClientKey, CompactPublicKey, PublicKey};
use crate::high_level_api::prelude::*;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::c_api::high_level_api::u128::U128;
use crate::c_api::high_level_api::u256::U256;
use crate::c_api::utils::*;
use std::os::raw::c_int;

/// Implement C functions for all the operations supported by a integer type,
/// which should also be accessible from C API
macro_rules! impl_operations_for_integer_type {
    (
        name: $name:ident,
        clear_scalar_type: $clear_scalar_type:ty
    ) => {
        impl_binary_fn_on_type!($name =>
            add,
            sub,
            mul,
            bitand,
            bitor,
            bitxor,
            shl,
            shr,
            eq,
            ne,
            ge,
            gt,
            le,
            lt,
            min,
            max,
            div,
            rem,
        );
        impl_binary_assign_fn_on_type!($name =>
            add_assign,
            sub_assign,
            mul_assign,
            bitand_assign,
            bitor_assign,
            bitxor_assign,
            shl_assign,
            shr_assign,
            div_assign,
            rem_assign,
        );
        impl_scalar_binary_fn_on_type!($name, $clear_scalar_type =>
            add,
            sub,
            mul,
            bitand,
            bitor,
            bitxor,
            shl,
            shr,
            eq,
            ne,
            ge,
            gt,
            le,
            lt,
            min,
            max,
            rotate_right,
            rotate_left,
            div,
            rem,
        );
        impl_scalar_binary_assign_fn_on_type!($name, $clear_scalar_type =>
            add_assign,
            sub_assign,
            mul_assign,
            bitand_assign,
            bitor_assign,
            bitxor_assign,
            shl_assign,
            shr_assign,
            rotate_right_assign,
            rotate_left_assign,
            div_assign,
            rem_assign,
        );

        impl_unary_fn_on_type!($name => neg, not);

        // Implement div_rem.
        // We can't use the macro above as div_rem returns a tuple.
        //
        // (Having div_rem is important for the cases where you need both
        // the quotient and remainder as you may save time by using the div_rem
        // instead of div and rem separately
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$name:snake _scalar_div_rem>](
                lhs: *const $name,
                rhs: $clear_scalar_type,
                q_result: *mut *mut $name,
                r_result: *mut *mut $name,
            ) -> c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                    let rhs = <$clear_scalar_type as $crate::c_api::high_level_api::utils::ToRustScalarType
                        >::to_rust_scalar_type(rhs);

                    let (q, r) = (&lhs.0).div_rem(rhs);

                    *q_result = Box::into_raw(Box::new($name(q)));
                    *r_result = Box::into_raw(Box::new($name(r)));
                })
            }
        }

        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$name:snake _div_rem>](
                lhs: *const $name,
                rhs: *const $name,
                q_result: *mut *mut $name,
                r_result: *mut *mut $name,
            ) -> c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let lhs = $crate::c_api::utils::get_ref_checked(lhs).unwrap();
                    let rhs = $crate::c_api::utils::get_ref_checked(rhs).unwrap();

                    let (q, r) = (&lhs.0).div_rem(&rhs.0);

                    *q_result = Box::into_raw(Box::new($name(q)));
                    *r_result = Box::into_raw(Box::new($name(r)));
                })
            }
        }

        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$name:snake _if_then_else>](
                condition_ct: *const $name,
                then_ct: *const $name,
                else_ct: *const $name,
                result: *mut *mut $name,
            ) -> c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let condition_ct = &$crate::c_api::utils::get_ref_checked(condition_ct).unwrap().0;
                    let then_ct = &$crate::c_api::utils::get_ref_checked(then_ct).unwrap().0;
                    let else_ct = &$crate::c_api::utils::get_ref_checked(else_ct).unwrap().0;

                    let r = condition_ct.if_then_else(then_ct, else_ct);

                    *result = Box::into_raw(Box::new($name(r)));
                })
            }
        }
    };
}

/// Creates a type that will act as an opaque wrapper
/// aroung a tfhe integer.
///
/// It also implements binary operations for this wrapper type
macro_rules! create_integer_wrapper_type {
    (
        name: $name:ident,
        clear_scalar_type: $clear_scalar_type:ty
    ) => {
        pub struct $name($crate::high_level_api::$name);

        impl_destroy_on_type!($name);

        impl_operations_for_integer_type!(name: $name, clear_scalar_type: $clear_scalar_type);

        impl_serialize_deserialize_on_type!($name);

        impl_clone_on_type!($name);

        // The compressed version of the ciphertext type
        ::paste::paste! {
            pub struct [<Compressed $name>]($crate::high_level_api::[<Compressed $name>]);

            impl_destroy_on_type!([<Compressed $name>]);

            impl_clone_on_type!([<Compressed $name>]);

            impl_serialize_deserialize_on_type!([<Compressed $name>]);

            #[no_mangle]
            pub unsafe extern "C" fn [<compressed_ $name:snake _decompress>](
                sself: *const [<Compressed $name>],
                result: *mut *mut $name,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let compressed = $crate::c_api::utils::get_ref_checked(sself).unwrap();

                    let decompressed_inner = compressed.0.clone().into();
                    *result = Box::into_raw(Box::new($name(decompressed_inner)));
                })
            }
        }

        // The compact list version of the ciphertext type
        ::paste::paste! {
            pub struct [<Compact $name List>]($crate::high_level_api::[<Compact $name List>]);

            impl_destroy_on_type!([<Compact $name List>]);

            impl_clone_on_type!([<Compact $name List>]);

            impl_serialize_deserialize_on_type!([<Compact $name List>]);

            #[no_mangle]
            pub unsafe extern "C" fn [<compact_ $name:snake _list_len>](
                sself: *const [<Compact $name List>],
                result: *mut usize,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    let list = $crate::c_api::utils::get_ref_checked(sself).unwrap();

                    *result = list.0.len();
                })
            }

            #[no_mangle]
            pub unsafe extern "C" fn [<compact_ $name:snake _list_expand>](
                sself: *const [<Compact $name List>],
                output: *mut *mut $name,
                output_len: usize
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    check_ptr_is_non_null_and_aligned(output).unwrap();
                    let list = $crate::c_api::utils::get_ref_checked(sself).unwrap();
                    let expanded = list.0.expand();

                    let num_to_take = output_len.max(list.0.len());
                    let iter = expanded.into_iter().take(num_to_take).enumerate();
                    for (i, fhe_uint) in iter {
                        let ptr = output.wrapping_add(i);
                        *ptr = Box::into_raw(Box::new($name(fhe_uint)));
                    }
                })
            }
        }
    };
}

create_integer_wrapper_type!(name: FheUint8, clear_scalar_type: u8);
create_integer_wrapper_type!(name: FheUint10, clear_scalar_type: u16);
create_integer_wrapper_type!(name: FheUint12, clear_scalar_type: u16);
create_integer_wrapper_type!(name: FheUint14, clear_scalar_type: u16);
create_integer_wrapper_type!(name: FheUint16, clear_scalar_type: u16);
create_integer_wrapper_type!(name: FheUint32, clear_scalar_type: u32);
create_integer_wrapper_type!(name: FheUint64, clear_scalar_type: u64);
create_integer_wrapper_type!(name: FheUint128, clear_scalar_type: U128);
create_integer_wrapper_type!(name: FheUint256, clear_scalar_type: U256);

impl_decrypt_on_type!(FheUint8, u8);
impl_try_encrypt_trivial_on_type!(FheUint8{crate::high_level_api::FheUint8}, u8);
impl_try_encrypt_with_client_key_on_type!(FheUint8{crate::high_level_api::FheUint8}, u8);
impl_try_encrypt_with_public_key_on_type!(FheUint8{crate::high_level_api::FheUint8}, u8);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint8{crate::high_level_api::FheUint8}, u8);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint8{crate::high_level_api::CompressedFheUint8}, u8);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint8List{crate::high_level_api::CompactFheUint8List}, u8);

impl_decrypt_on_type!(FheUint10, u16);
impl_try_encrypt_trivial_on_type!(FheUint10{crate::high_level_api::FheUint10}, u16);
impl_try_encrypt_with_client_key_on_type!(FheUint10{crate::high_level_api::FheUint10}, u16);
impl_try_encrypt_with_public_key_on_type!(FheUint10{crate::high_level_api::FheUint10}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint10{crate::high_level_api::FheUint10}, u16);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint10{crate::high_level_api::CompressedFheUint10}, u16);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint10List{crate::high_level_api::CompactFheUint10List}, u16);

impl_decrypt_on_type!(FheUint12, u16);
impl_try_encrypt_trivial_on_type!(FheUint12{crate::high_level_api::FheUint12}, u16);
impl_try_encrypt_with_client_key_on_type!(FheUint12{crate::high_level_api::FheUint12}, u16);
impl_try_encrypt_with_public_key_on_type!(FheUint12{crate::high_level_api::FheUint12}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint12{crate::high_level_api::FheUint12}, u16);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint12{crate::high_level_api::CompressedFheUint12}, u16);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint12List{crate::high_level_api::CompactFheUint12List}, u16);

impl_decrypt_on_type!(FheUint14, u16);
impl_try_encrypt_trivial_on_type!(FheUint14{crate::high_level_api::FheUint14}, u16);
impl_try_encrypt_with_client_key_on_type!(FheUint14{crate::high_level_api::FheUint14}, u16);
impl_try_encrypt_with_public_key_on_type!(FheUint14{crate::high_level_api::FheUint14}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint14{crate::high_level_api::FheUint14}, u16);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint14{crate::high_level_api::CompressedFheUint14}, u16);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint14List{crate::high_level_api::CompactFheUint14List}, u16);

impl_decrypt_on_type!(FheUint16, u16);
impl_try_encrypt_trivial_on_type!(FheUint16{crate::high_level_api::FheUint16}, u16);
impl_try_encrypt_with_client_key_on_type!(FheUint16{crate::high_level_api::FheUint16}, u16);
impl_try_encrypt_with_public_key_on_type!(FheUint16{crate::high_level_api::FheUint16}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint16{crate::high_level_api::FheUint16}, u16);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint16{crate::high_level_api::CompressedFheUint16}, u16);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint16List{crate::high_level_api::CompactFheUint16List}, u16);

impl_decrypt_on_type!(FheUint32, u32);
impl_try_encrypt_trivial_on_type!(FheUint32{crate::high_level_api::FheUint32}, u32);
impl_try_encrypt_with_client_key_on_type!(FheUint32{crate::high_level_api::FheUint32}, u32);
impl_try_encrypt_with_public_key_on_type!(FheUint32{crate::high_level_api::FheUint32}, u32);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint32{crate::high_level_api::FheUint32}, u32);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint32{crate::high_level_api::CompressedFheUint32}, u32);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint32List{crate::high_level_api::CompactFheUint32List}, u32);

impl_decrypt_on_type!(FheUint64, u64);
impl_try_encrypt_trivial_on_type!(FheUint64{crate::high_level_api::FheUint64}, u64);
impl_try_encrypt_with_client_key_on_type!(FheUint64{crate::high_level_api::FheUint64}, u64);
impl_try_encrypt_with_public_key_on_type!(FheUint64{crate::high_level_api::FheUint64}, u64);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint64{crate::high_level_api::FheUint64}, u64);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint64{crate::high_level_api::CompressedFheUint64}, u64);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint64List{crate::high_level_api::CompactFheUint64List}, u64);

#[no_mangle]
pub unsafe extern "C" fn fhe_uint128_try_encrypt_trivial_u128(
    value: U128,
    result: *mut *mut FheUint128,
) -> c_int {
    catch_panic(|| {
        let value = u128::from(value);

        let inner = <crate::high_level_api::FheUint128>::try_encrypt_trivial(value).unwrap();

        *result = Box::into_raw(Box::new(FheUint128(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn fhe_uint128_try_encrypt_with_client_key_u128(
    value: U128,
    client_key: *const ClientKey,
    result: *mut *mut FheUint128,
) -> c_int {
    catch_panic(|| {
        let client_key = get_ref_checked(client_key).unwrap();

        let value = u128::from(value);

        let inner = <crate::high_level_api::FheUint128>::try_encrypt(value, &client_key.0).unwrap();

        *result = Box::into_raw(Box::new(FheUint128(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compressed_fhe_uint128_try_encrypt_with_client_key_u128(
    value: U128,
    client_key: *const ClientKey,
    result: *mut *mut CompressedFheUint128,
) -> c_int {
    catch_panic(|| {
        let client_key = get_ref_checked(client_key).unwrap();

        let value = u128::from(value);

        let inner =
            <crate::high_level_api::CompressedFheUint128>::try_encrypt(value, &client_key.0)
                .unwrap();

        *result = Box::into_raw(Box::new(CompressedFheUint128(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn fhe_uint128_try_encrypt_with_public_key_u128(
    value: U128,
    public_key: *const PublicKey,
    result: *mut *mut FheUint128,
) -> c_int {
    catch_panic(|| {
        let public_key = get_ref_checked(public_key).unwrap();

        let value = u128::from(value);

        let inner = <crate::high_level_api::FheUint128>::try_encrypt(value, &public_key.0).unwrap();

        *result = Box::into_raw(Box::new(FheUint128(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn fhe_uint128_try_encrypt_with_compact_public_key_u128(
    value: U128,
    public_key: *const CompactPublicKey,
    result: *mut *mut FheUint128,
) -> c_int {
    catch_panic(|| {
        let public_key = get_ref_checked(public_key).unwrap();

        let value = u128::from(value);

        let inner = <crate::high_level_api::FheUint128>::try_encrypt(value, &public_key.0).unwrap();

        *result = Box::into_raw(Box::new(FheUint128(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compact_fhe_uint256_list_try_encrypt_with_compact_public_key_u128(
    input: *const U128,
    input_len: usize,
    public_key: *const CompactPublicKey,
    result: *mut *mut CompactFheUint256List,
) -> c_int {
    catch_panic(|| {
        let public_key = get_ref_checked(public_key).unwrap();

        let slc = ::std::slice::from_raw_parts(input, input_len);
        let values = slc.iter().copied().map(u128::from).collect::<Vec<_>>();
        let inner =
            <crate::high_level_api::CompactFheUint256List>::try_encrypt(&values, &public_key.0)
                .unwrap();

        *result = Box::into_raw(Box::new(CompactFheUint256List(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn fhe_uint128_decrypt(
    encrypted_value: *const FheUint128,
    client_key: *const ClientKey,
    result: *mut U128,
) -> c_int {
    catch_panic(|| {
        let client_key = get_ref_checked(client_key).unwrap();
        let encrypted_value = get_ref_checked(encrypted_value).unwrap();

        let inner: u128 = encrypted_value.0.decrypt(&client_key.0);

        *result = U128::from(inner);
    })
}

#[no_mangle]
pub unsafe extern "C" fn fhe_uint256_try_encrypt_trivial_u256(
    value: U256,
    result: *mut *mut FheUint256,
) -> c_int {
    catch_panic(|| {
        let value = crate::integer::U256::from(value);
        let inner = <crate::high_level_api::FheUint256>::try_encrypt_trivial(value).unwrap();

        *result = Box::into_raw(Box::new(FheUint256(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn fhe_uint256_try_encrypt_with_client_key_u256(
    value: U256,
    client_key: *const ClientKey,
    result: *mut *mut FheUint256,
) -> c_int {
    catch_panic(|| {
        let client_key = get_ref_checked(client_key).unwrap();

        let value = crate::integer::U256::from(value);
        let inner = <crate::high_level_api::FheUint256>::try_encrypt(value, &client_key.0).unwrap();

        *result = Box::into_raw(Box::new(FheUint256(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compressed_fhe_uint256_try_encrypt_with_client_key_u256(
    value: U256,
    client_key: *const ClientKey,
    result: *mut *mut CompressedFheUint256,
) -> c_int {
    catch_panic(|| {
        let client_key = get_ref_checked(client_key).unwrap();

        let value = crate::integer::U256::from(value);
        let inner =
            <crate::high_level_api::CompressedFheUint256>::try_encrypt(value, &client_key.0)
                .unwrap();

        *result = Box::into_raw(Box::new(CompressedFheUint256(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn fhe_uint256_try_encrypt_with_public_key_u256(
    value: U256,
    public_key: *const PublicKey,
    result: *mut *mut FheUint256,
) -> c_int {
    catch_panic(|| {
        let public_key = get_ref_checked(public_key).unwrap();

        let value = crate::integer::U256::from(value);
        let inner = <crate::high_level_api::FheUint256>::try_encrypt(value, &public_key.0).unwrap();

        *result = Box::into_raw(Box::new(FheUint256(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn fhe_uint256_try_encrypt_with_compact_public_key_u256(
    value: U256,
    public_key: *const CompactPublicKey,
    result: *mut *mut FheUint256,
) -> c_int {
    catch_panic(|| {
        let public_key = get_ref_checked(public_key).unwrap();

        let value = crate::integer::U256::from(value);
        let inner = <crate::high_level_api::FheUint256>::try_encrypt(value, &public_key.0).unwrap();

        *result = Box::into_raw(Box::new(FheUint256(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compact_fhe_uint256_list_try_encrypt_with_compact_public_key_u256(
    input: *const U256,
    input_len: usize,
    public_key: *const CompactPublicKey,
    result: *mut *mut CompactFheUint256List,
) -> c_int {
    catch_panic(|| {
        let public_key = get_ref_checked(public_key).unwrap();

        let slc = ::std::slice::from_raw_parts(input, input_len);
        let values = slc
            .iter()
            .copied()
            .map(crate::integer::U256::from)
            .collect::<Vec<_>>();
        let inner =
            <crate::high_level_api::CompactFheUint256List>::try_encrypt(&values, &public_key.0)
                .unwrap();

        *result = Box::into_raw(Box::new(CompactFheUint256List(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn fhe_uint256_decrypt(
    encrypted_value: *const FheUint256,
    client_key: *const ClientKey,
    result: *mut U256,
) -> c_int {
    catch_panic(|| {
        let client_key = get_ref_checked(client_key).unwrap();
        let encrypted_value = get_ref_checked(encrypted_value).unwrap();

        let inner: crate::integer::U256 = encrypted_value.0.decrypt(&client_key.0);
        *result = U256::from(inner);
    })
}

macro_rules! define_casting_operation(
    ($from:ty => $($to:ty),*) => {
        $(
            ::paste::paste!{
                #[no_mangle]
                pub unsafe extern "C" fn [<$from:snake _cast_into_ $to:snake>](
                    sself: *const $from,
                    result: *mut *mut $to,
                    ) -> ::std::os::raw::c_int {
                    $crate::c_api::utils::catch_panic(|| {
                        let from = $crate::c_api::utils::get_ref_checked(sself).unwrap();

                        let inner_to  = from.0.clone().cast_into();
                        *result = Box::into_raw(Box::new($to(inner_to)));
                    })
                }
            }
        )*
    }
);

define_casting_operation!(FheUint8 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256);
define_casting_operation!(FheUint10 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256);
define_casting_operation!(FheUint12 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256);
define_casting_operation!(FheUint14 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256);
define_casting_operation!(FheUint16 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256);
define_casting_operation!(FheUint32 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256);
define_casting_operation!(FheUint64 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256);
define_casting_operation!(FheUint128 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256);
define_casting_operation!(FheUint256 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256);
