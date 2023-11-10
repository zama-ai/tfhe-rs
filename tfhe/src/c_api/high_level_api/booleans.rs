use crate::high_level_api::prelude::*;

use std::ops::{BitAnd, BitOr, BitXor, Not};

pub struct FheBool(pub(in crate::c_api) crate::high_level_api::FheBool);

impl_destroy_on_type!(FheBool);
impl_clone_on_type!(FheBool);

impl_binary_fn_on_type!(FheBool => bitand, bitor, bitxor);
impl_unary_fn_on_type!(FheBool => not);

impl_decrypt_on_type!(FheBool, bool);
impl_try_encrypt_trivial_on_type!(FheBool{crate::high_level_api::FheBool}, bool);
impl_try_encrypt_with_client_key_on_type!(FheBool{crate::high_level_api::FheBool}, bool);
impl_try_encrypt_with_public_key_on_type!(FheBool{crate::high_level_api::FheBool}, bool);

pub struct CompressedFheBool(crate::high_level_api::CompressedFheBool);

impl_destroy_on_type!(CompressedFheBool);
impl_clone_on_type!(CompressedFheBool);
impl_serialize_deserialize_on_type!(CompressedFheBool);

#[no_mangle]
pub unsafe extern "C" fn compressed_fhe_bool_decompress(
    sself: *const CompressedFheBool,
    result: *mut *mut FheBool,
) -> ::std::os::raw::c_int {
    crate::c_api::utils::catch_panic(|| {
        let compressed = crate::c_api::utils::get_ref_checked(sself).unwrap();

        let decompressed_inner = compressed.0.clone().into();
        *result = Box::into_raw(Box::new(FheBool(decompressed_inner)));
    })
}
