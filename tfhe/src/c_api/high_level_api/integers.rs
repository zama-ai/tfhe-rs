use crate::c_api::high_level_api::keys::CompactPublicKey;
use crate::high_level_api::prelude::*;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::c_api::high_level_api::booleans::FheBool;
use crate::c_api::high_level_api::i128::I128;
use crate::c_api::high_level_api::i256::I256;
use crate::c_api::high_level_api::u128::U128;
use crate::c_api::high_level_api::u256::U256;
use crate::c_api::utils::*;
use std::os::raw::c_int;

/// Implement C functions for all the operations supported by a integer type,
/// which should also be accessible from C API
///
/// We require the shift amount to be an unsigned type,
/// so to be able to use that macro for signed integers (which have a signed clear type)
/// we also accept an additional clear_shift_type
macro_rules! impl_operations_for_integer_type {
    (
        name: $name:ident,
        fhe_unsigned_type: $fhe_unsigned_type:ty,
        clear_scalar_type: $clear_scalar_type:ty,
        clear_shift_type: $clear_shift_type:ty
        $(,)?
    ) => {
        impl_binary_fn_on_type!($name =>
            add,
            sub,
            mul,
            bitand,
            bitor,
            bitxor,
            min,
            max,
            div,
            rem,
        );

        // Handle comparisons separately as they return FheBool
        impl_comparison_fn_on_type!(
            lhs_type: $name,
            rhs_type: $name,
            comparison_fn_names: eq, ne, ge, gt, le, lt,
        );

        // Handle comparisons separately as they return FheBool
        impl_scalar_comparison_fn_on_type!(
            lhs_type: $name,
            clear_type: $clear_scalar_type,
            comparison_fn_names: eq, ne, ge, gt, le, lt,
        );

        // handle shift separately as they require
        // rhs to be an unsigned type
        impl_binary_fn_on_type!(
            lhs_type: $name,
            rhs_type: $fhe_unsigned_type,
            binary_fn_names: shl, shr, rotate_right, rotate_left,
        );

        impl_binary_assign_fn_on_type!($name =>
            add_assign,
            sub_assign,
            mul_assign,
            bitand_assign,
            bitor_assign,
            bitxor_assign,
            div_assign,
            rem_assign,
        );

        // handle shift separately as they require
        // rhs to be an unsigned type
        impl_binary_assign_fn_on_type!(
            lhs_type: $name,
            rhs_type: $fhe_unsigned_type,
            binary_fn_names: shl_assign, shr_assign, rotate_right_assign, rotate_left_assign,
        );

        impl_scalar_binary_fn_on_type!($name, $clear_scalar_type =>
            add,
            sub,
            mul,
            bitand,
            bitor,
            bitxor,
            min,
            max,
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
            div_assign,
            rem_assign,
        );

        // handle shift separately as they require
        // rhs to be an unsigned type
        impl_scalar_binary_fn_on_type!($name, $clear_shift_type =>
            shl,
            shr,
            rotate_right,
            rotate_left,
        );
        impl_scalar_binary_assign_fn_on_type!($name, $clear_shift_type =>
            shl_assign,
            shr_assign,
            rotate_right_assign,
            rotate_left_assign,
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
                    let rhs = <$clear_scalar_type as $crate::c_api::high_level_api::utils::CApiIntegerType
                        >::to_rust(rhs);

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

        // Even though if_then_else/cmux is a method of FheBool, it still takes as
        // integers inputs, so its easier to keep the definition here
        ::paste::paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<$name:snake _if_then_else>](
                condition_ct: *const FheBool,
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

             // map cmux to if_then_else
             pub unsafe extern "C" fn [<$name:snake _cmux>](
                condition_ct: *const FheBool,
                then_ct: *const $name,
                else_ct: *const $name,
                result: *mut *mut $name,
            ) -> c_int {
                [<$name:snake _if_then_else>](condition_ct, then_ct, else_ct, result)
            }
        }
    };
}

/// Creates a type that will act as an opaque wrapper
/// around a tfhe integer.
///
/// It also implements binary operations for this wrapper type
macro_rules! create_integer_wrapper_type {

    (
        name: $name:ident,
        fhe_unsigned_type: $fhe_unsigned_type:ty,
        clear_scalar_type: $clear_scalar_type:ty,
        clear_shift_type: $clear_shift_type:ty
        $(,)?
    ) => {
        pub struct $name($crate::high_level_api::$name);

        impl_destroy_on_type!($name);

        impl_operations_for_integer_type!(
            name: $name,
            fhe_unsigned_type: $fhe_unsigned_type,
            clear_scalar_type: $clear_scalar_type,
            clear_shift_type: $clear_shift_type,
        );

        impl_serialize_deserialize_on_type!($name);

        impl_clone_on_type!($name);

        impl_safe_serialize_on_type!($name);

        impl_safe_deserialize_conformant_integer!($name, crate::high_level_api::safe_deserialize_conformant_integer);


        // The compressed version of the ciphertext type
        ::paste::paste! {
            pub struct [<Compressed $name>]($crate::high_level_api::[<Compressed $name>]);

            impl_destroy_on_type!([<Compressed $name>]);

            impl_clone_on_type!([<Compressed $name>]);

            impl_serialize_deserialize_on_type!([<Compressed $name>]);

            impl_safe_serialize_on_type!([<Compressed $name>]);

            impl_safe_deserialize_conformant_integer!([<Compressed $name>], crate::high_level_api::safe_deserialize_conformant_compressed_integer);


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


        // The compact version of the ciphertext type
        ::paste::paste! {
            pub struct [<Compact $name>]($crate::high_level_api::[<Compact $name>]);

            impl_destroy_on_type!([<Compact $name>]);

            impl_clone_on_type!([<Compact $name>]);

            impl_serialize_deserialize_on_type!([<Compact $name>]);

            impl_safe_serialize_on_type!([<Compact $name>]);

            impl_safe_deserialize_conformant_integer!([<Compact $name>], crate::high_level_api::safe_deserialize_conformant_compact_integer);

            #[no_mangle]
            pub unsafe extern "C" fn [<compact_ $name:snake _expand>](
                sself: *const [<Compact $name>],
                output: *mut *mut $name,
            ) -> ::std::os::raw::c_int {
                $crate::c_api::utils::catch_panic(|| {
                    check_ptr_is_non_null_and_aligned(output).unwrap();
                    let list = $crate::c_api::utils::get_ref_checked(sself).unwrap();
                    let expanded = list.0.expand();

                    *output = Box::into_raw(Box::new($name(expanded)));
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

    // This entry point is meant for unsigned types
    (
        name: $name:ident,
        clear_scalar_type: $clear_scalar_type:ty
    ) => {
        create_integer_wrapper_type!(
            name: $name,
            fhe_unsigned_type: $name,
            clear_scalar_type: $clear_scalar_type,
            clear_shift_type: $clear_scalar_type,
        );
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
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheUint8{crate::high_level_api::CompactFheUint8}, u8);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint8{crate::high_level_api::CompressedFheUint8}, u8);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint8List{crate::high_level_api::CompactFheUint8List}, u8);

impl_decrypt_on_type!(FheUint10, u16);
impl_try_encrypt_trivial_on_type!(FheUint10{crate::high_level_api::FheUint10}, u16);
impl_try_encrypt_with_client_key_on_type!(FheUint10{crate::high_level_api::FheUint10}, u16);
impl_try_encrypt_with_public_key_on_type!(FheUint10{crate::high_level_api::FheUint10}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint10{crate::high_level_api::FheUint10}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheUint10{crate::high_level_api::CompactFheUint10}, u16);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint10{crate::high_level_api::CompressedFheUint10}, u16);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint10List{crate::high_level_api::CompactFheUint10List}, u16);

impl_decrypt_on_type!(FheUint12, u16);
impl_try_encrypt_trivial_on_type!(FheUint12{crate::high_level_api::FheUint12}, u16);
impl_try_encrypt_with_client_key_on_type!(FheUint12{crate::high_level_api::FheUint12}, u16);
impl_try_encrypt_with_public_key_on_type!(FheUint12{crate::high_level_api::FheUint12}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint12{crate::high_level_api::FheUint12}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheUint12{crate::high_level_api::CompactFheUint12}, u16);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint12{crate::high_level_api::CompressedFheUint12}, u16);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint12List{crate::high_level_api::CompactFheUint12List}, u16);

impl_decrypt_on_type!(FheUint14, u16);
impl_try_encrypt_trivial_on_type!(FheUint14{crate::high_level_api::FheUint14}, u16);
impl_try_encrypt_with_client_key_on_type!(FheUint14{crate::high_level_api::FheUint14}, u16);
impl_try_encrypt_with_public_key_on_type!(FheUint14{crate::high_level_api::FheUint14}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint14{crate::high_level_api::FheUint14}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheUint14{crate::high_level_api::CompactFheUint14}, u16);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint14{crate::high_level_api::CompressedFheUint14}, u16);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint14List{crate::high_level_api::CompactFheUint14List}, u16);

impl_decrypt_on_type!(FheUint16, u16);
impl_try_encrypt_trivial_on_type!(FheUint16{crate::high_level_api::FheUint16}, u16);
impl_try_encrypt_with_client_key_on_type!(FheUint16{crate::high_level_api::FheUint16}, u16);
impl_try_encrypt_with_public_key_on_type!(FheUint16{crate::high_level_api::FheUint16}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint16{crate::high_level_api::FheUint16}, u16);
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheUint16{crate::high_level_api::CompactFheUint16}, u16);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint16{crate::high_level_api::CompressedFheUint16}, u16);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint16List{crate::high_level_api::CompactFheUint16List}, u16);

impl_decrypt_on_type!(FheUint32, u32);
impl_try_encrypt_trivial_on_type!(FheUint32{crate::high_level_api::FheUint32}, u32);
impl_try_encrypt_with_client_key_on_type!(FheUint32{crate::high_level_api::FheUint32}, u32);
impl_try_encrypt_with_public_key_on_type!(FheUint32{crate::high_level_api::FheUint32}, u32);
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheUint32{crate::high_level_api::CompactFheUint32}, u32);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint32{crate::high_level_api::FheUint32}, u32);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint32{crate::high_level_api::CompressedFheUint32}, u32);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint32List{crate::high_level_api::CompactFheUint32List}, u32);

impl_decrypt_on_type!(FheUint64, u64);
impl_try_encrypt_trivial_on_type!(FheUint64{crate::high_level_api::FheUint64}, u64);
impl_try_encrypt_with_client_key_on_type!(FheUint64{crate::high_level_api::FheUint64}, u64);
impl_try_encrypt_with_public_key_on_type!(FheUint64{crate::high_level_api::FheUint64}, u64);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint64{crate::high_level_api::FheUint64}, u64);
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheUint64{crate::high_level_api::CompactFheUint64}, u64);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint64{crate::high_level_api::CompressedFheUint64}, u64);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheUint64List{crate::high_level_api::CompactFheUint64List}, u64);

impl_decrypt_on_type!(FheUint128, U128);
impl_try_encrypt_trivial_on_type!(FheUint128{crate::high_level_api::FheUint128}, U128);
impl_try_encrypt_with_client_key_on_type!(FheUint128{crate::high_level_api::FheUint128}, U128);
impl_try_encrypt_with_public_key_on_type!(FheUint128{crate::high_level_api::FheUint128}, U128);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint128{crate::high_level_api::FheUint128}, U128);
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheUint128{crate::high_level_api::CompactFheUint128}, U128);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint128{crate::high_level_api::CompressedFheUint128}, U128);

impl_decrypt_on_type!(FheUint256, U256);
impl_try_encrypt_trivial_on_type!(FheUint256{crate::high_level_api::FheUint256}, U256);
impl_try_encrypt_with_client_key_on_type!(FheUint256{crate::high_level_api::FheUint256}, U256);
impl_try_encrypt_with_public_key_on_type!(FheUint256{crate::high_level_api::FheUint256}, U256);
impl_try_encrypt_with_compact_public_key_on_type!(FheUint256{crate::high_level_api::FheUint256}, U256);
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheUint256{crate::high_level_api::CompactFheUint256}, U256);
impl_try_encrypt_with_client_key_on_type!(CompressedFheUint256{crate::high_level_api::CompressedFheUint256}, U256);

create_integer_wrapper_type!(
    name: FheInt8,
    fhe_unsigned_type: FheUint8,
    clear_scalar_type: i8,
    clear_shift_type: u8,
);
create_integer_wrapper_type!(
    name: FheInt16,
    fhe_unsigned_type: FheUint16,
    clear_scalar_type: i16,
    clear_shift_type: u16,
);
create_integer_wrapper_type!(
    name: FheInt32,
    fhe_unsigned_type: FheUint32,
    clear_scalar_type: i32,
    clear_shift_type: u32,
);
create_integer_wrapper_type!(
    name: FheInt64,
    fhe_unsigned_type: FheUint64,
    clear_scalar_type: i64,
    clear_shift_type: u64,
);
create_integer_wrapper_type!(
    name: FheInt128,
    fhe_unsigned_type: FheUint128,
    clear_scalar_type: I128,
    clear_shift_type: U128,
);
create_integer_wrapper_type!(
    name: FheInt256,
    fhe_unsigned_type: FheUint256,
    clear_scalar_type: I256,
    clear_shift_type: U256,
);

impl_decrypt_on_type!(FheInt8, i8);
impl_try_encrypt_trivial_on_type!(FheInt8{crate::high_level_api::FheInt8}, i8);
impl_try_encrypt_with_client_key_on_type!(FheInt8{crate::high_level_api::FheInt8}, i8);
impl_try_encrypt_with_public_key_on_type!(FheInt8{crate::high_level_api::FheInt8}, i8);
impl_try_encrypt_with_compact_public_key_on_type!(FheInt8{crate::high_level_api::FheInt8}, i8);
impl_try_encrypt_with_client_key_on_type!(CompressedFheInt8{crate::high_level_api::CompressedFheInt8}, i8);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheInt8List{crate::high_level_api::CompactFheInt8List}, i8);

impl_decrypt_on_type!(FheInt16, i16);
impl_try_encrypt_trivial_on_type!(FheInt16{crate::high_level_api::FheInt16}, i16);
impl_try_encrypt_with_client_key_on_type!(FheInt16{crate::high_level_api::FheInt16}, i16);
impl_try_encrypt_with_public_key_on_type!(FheInt16{crate::high_level_api::FheInt16}, i16);
impl_try_encrypt_with_compact_public_key_on_type!(FheInt16{crate::high_level_api::FheInt16}, i16);
impl_try_encrypt_with_client_key_on_type!(CompressedFheInt16{crate::high_level_api::CompressedFheInt16}, i16);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheInt16List{crate::high_level_api::CompactFheInt16List}, i16);

impl_decrypt_on_type!(FheInt32, i32);
impl_try_encrypt_trivial_on_type!(FheInt32{crate::high_level_api::FheInt32}, i32);
impl_try_encrypt_with_client_key_on_type!(FheInt32{crate::high_level_api::FheInt32}, i32);
impl_try_encrypt_with_public_key_on_type!(FheInt32{crate::high_level_api::FheInt32}, i32);
impl_try_encrypt_with_compact_public_key_on_type!(FheInt32{crate::high_level_api::FheInt32}, i32);
impl_try_encrypt_with_client_key_on_type!(CompressedFheInt32{crate::high_level_api::CompressedFheInt32}, i32);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheInt32List{crate::high_level_api::CompactFheInt32List}, i32);

impl_decrypt_on_type!(FheInt64, i64);
impl_try_encrypt_trivial_on_type!(FheInt64{crate::high_level_api::FheInt64}, i64);
impl_try_encrypt_with_client_key_on_type!(FheInt64{crate::high_level_api::FheInt64}, i64);
impl_try_encrypt_with_public_key_on_type!(FheInt64{crate::high_level_api::FheInt64}, i64);
impl_try_encrypt_with_compact_public_key_on_type!(FheInt64{crate::high_level_api::FheInt64}, i64);
impl_try_encrypt_with_client_key_on_type!(CompressedFheInt64{crate::high_level_api::CompressedFheInt64}, i64);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheInt64List{crate::high_level_api::CompactFheInt64List}, i64);

impl_decrypt_on_type!(FheInt128, I128);
impl_try_encrypt_trivial_on_type!(FheInt128{crate::high_level_api::FheInt128}, I128);
impl_try_encrypt_with_client_key_on_type!(FheInt128{crate::high_level_api::FheInt128}, I128);
impl_try_encrypt_with_public_key_on_type!(FheInt128{crate::high_level_api::FheInt128}, I128);
impl_try_encrypt_with_compact_public_key_on_type!(FheInt128{crate::high_level_api::FheInt128}, I128);
impl_try_encrypt_with_client_key_on_type!(CompressedFheInt128{crate::high_level_api::CompressedFheInt128}, I128);

impl_decrypt_on_type!(FheInt256, I256);
impl_try_encrypt_trivial_on_type!(FheInt256{crate::high_level_api::FheInt256}, I256);
impl_try_encrypt_with_client_key_on_type!(FheInt256{crate::high_level_api::FheInt256}, I256);
impl_try_encrypt_with_public_key_on_type!(FheInt256{crate::high_level_api::FheInt256}, I256);
impl_try_encrypt_with_compact_public_key_on_type!(FheInt256{crate::high_level_api::FheInt256}, I256);
impl_try_encrypt_with_client_key_on_type!(CompressedFheInt256{crate::high_level_api::CompressedFheInt256}, I256);

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
pub unsafe extern "C" fn compact_fhe_int128_list_try_encrypt_with_compact_public_key_i128(
    input: *const I128,
    input_len: usize,
    public_key: *const CompactPublicKey,
    result: *mut *mut CompactFheInt128List,
) -> c_int {
    catch_panic(|| {
        let public_key = get_ref_checked(public_key).unwrap();

        let slc = ::std::slice::from_raw_parts(input, input_len);
        let values = slc.iter().copied().map(i128::from).collect::<Vec<_>>();
        let inner =
            <crate::high_level_api::CompactFheInt128List>::try_encrypt(&values, &public_key.0)
                .unwrap();

        *result = Box::into_raw(Box::new(CompactFheInt128List(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compact_fhe_int256_list_try_encrypt_with_compact_public_key_i256(
    input: *const I256,
    input_len: usize,
    public_key: *const CompactPublicKey,
    result: *mut *mut CompactFheInt256List,
) -> c_int {
    catch_panic(|| {
        let public_key = get_ref_checked(public_key).unwrap();

        let slc = ::std::slice::from_raw_parts(input, input_len);
        let values = slc
            .iter()
            .copied()
            .map(crate::integer::I256::from)
            .collect::<Vec<_>>();
        let inner =
            <crate::high_level_api::CompactFheInt256List>::try_encrypt(&values, &public_key.0)
                .unwrap();

        *result = Box::into_raw(Box::new(CompactFheInt256List(inner)));
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

define_casting_operation!(FheUint8 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheUint10 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheUint12 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheUint14 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheUint16 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheUint32 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheUint64 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheUint128 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheUint256 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);

define_casting_operation!(FheInt8 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheInt16 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheInt32 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheInt64 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheInt128 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
define_casting_operation!(FheInt256 => FheUint8, FheUint10, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
    FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256);
