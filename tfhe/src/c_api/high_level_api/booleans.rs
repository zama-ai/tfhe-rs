use crate::high_level_api::prelude::*;

use crate::c_api::utils::check_ptr_is_non_null_and_aligned;
use std::ops::{BitAnd, BitOr, BitXor, Not};

pub struct FheBool(pub(in crate::c_api) crate::high_level_api::FheBool);

impl_destroy_on_type!(FheBool);
impl_clone_on_type!(FheBool);

impl_binary_fn_on_type!(FheBool => bitand, bitor, bitxor);
impl_unary_fn_on_type!(FheBool => not);

impl_decrypt_on_type!(FheBool, bool);
impl_try_decrypt_trivial_on_type!(FheBool, bool);
impl_try_encrypt_trivial_on_type!(FheBool{crate::high_level_api::FheBool}, bool);
impl_try_encrypt_with_client_key_on_type!(FheBool{crate::high_level_api::FheBool}, bool);
impl_try_encrypt_with_public_key_on_type!(FheBool{crate::high_level_api::FheBool}, bool);
impl_try_encrypt_with_compact_public_key_on_type!(FheBool{crate::high_level_api::FheBool}, bool);

pub struct CompressedFheBool(crate::high_level_api::CompressedFheBool);

impl_destroy_on_type!(CompressedFheBool);
impl_clone_on_type!(CompressedFheBool);
impl_serialize_deserialize_on_type!(CompressedFheBool);

#[no_mangle]
pub unsafe extern "C" fn compressed_fhe_bool_decompress(
    sself: *const CompressedFheBool,
    result: *mut *mut FheBool,
) -> std::os::raw::c_int {
    crate::c_api::utils::catch_panic(|| {
        let compressed = crate::c_api::utils::get_ref_checked(sself).unwrap();

        let decompressed_inner = compressed.0.clone().decompress();
        *result = Box::into_raw(Box::new(FheBool(decompressed_inner)));
    })
}

pub struct CompactFheBool(crate::high_level_api::CompactFheBool);

impl_destroy_on_type!(CompactFheBool);
impl_clone_on_type!(CompactFheBool);
impl_serialize_deserialize_on_type!(CompactFheBool);
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheBool{crate::high_level_api::CompactFheBool}, bool);

#[no_mangle]
pub unsafe extern "C" fn compact_fhe_bool_expand(
    sself: *const CompactFheBool,
    result: *mut *mut FheBool,
) -> std::os::raw::c_int {
    crate::c_api::utils::catch_panic(|| {
        let compact = crate::c_api::utils::get_ref_checked(sself).unwrap();

        let expanded = compact.0.clone().expand();
        *result = Box::into_raw(Box::new(FheBool(expanded)));
    })
}

pub struct CompactFheBoolList(crate::high_level_api::CompactFheBoolList);

impl_destroy_on_type!(CompactFheBoolList);
impl_clone_on_type!(CompactFheBoolList);
impl_serialize_deserialize_on_type!(CompactFheBoolList);

#[no_mangle]
pub unsafe extern "C" fn compact_fhe_bool_list_len(
    sself: *const CompactFheBoolList,
    result: *mut usize,
) -> ::std::os::raw::c_int {
    crate::c_api::utils::catch_panic(|| {
        let list = crate::c_api::utils::get_ref_checked(sself).unwrap();

        *result = list.0.len();
    })
}

#[no_mangle]
pub unsafe extern "C" fn compact_fhe_bool_list_expand(
    sself: *const CompactFheBoolList,
    output: *mut *mut FheBool,
    output_len: usize,
) -> std::os::raw::c_int {
    crate::c_api::utils::catch_panic(|| {
        check_ptr_is_non_null_and_aligned(output).unwrap();
        let list = crate::c_api::utils::get_ref_checked(sself).unwrap();
        let expanded = list.0.expand();

        let num_to_take = output_len.max(list.0.len());
        let iter = expanded.into_iter().take(num_to_take).enumerate();
        for (i, fhe_uint) in iter {
            let ptr = output.wrapping_add(i);
            *ptr = Box::into_raw(Box::new(FheBool(fhe_uint)));
        }
    })
}
