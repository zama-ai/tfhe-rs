use super::utils::*;
use crate::high_level_api::prelude::*;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

pub struct FheBool(pub(in crate::c_api) crate::high_level_api::FheBool);

impl_destroy_on_type!(FheBool);
impl_clone_on_type!(FheBool);
impl_serialize_deserialize_on_type!(FheBool);
impl_safe_serialize_on_type!(FheBool);
impl_safe_deserialize_conformant_on_type!(FheBool, FheBoolConformanceParams);

impl_binary_fn_on_type!(FheBool => bitand, bitor, bitxor);
impl_binary_assign_fn_on_type!(FheBool => bitand_assign,  bitor_assign, bitxor_assign);
impl_unary_fn_on_type!(FheBool => not);
impl_comparison_fn_on_type!(
    lhs_type: FheBool,
    rhs_type: FheBool,
    comparison_fn_names: eq, ne,
);
impl_scalar_binary_fn_on_type!(FheBool, bool =>
    bitand,
    bitor,
    bitxor,
);
impl_scalar_binary_assign_fn_on_type!(FheBool, bool =>
    bitand_assign,
    bitor_assign,
    bitxor_assign,
);
impl_scalar_comparison_fn_on_type!(
    lhs_type: FheBool,
    clear_type: bool,
    comparison_fn_names: eq, ne
);

impl_decrypt_on_type!(FheBool, bool);
impl_try_decrypt_trivial_on_type!(FheBool, bool);
impl_try_encrypt_trivial_on_type!(FheBool{crate::high_level_api::FheBool}, bool);
impl_try_encrypt_with_client_key_on_type!(FheBool{crate::high_level_api::FheBool}, bool);
impl_try_encrypt_with_public_key_on_type!(FheBool{crate::high_level_api::FheBool}, bool);

pub struct CompressedFheBool(crate::high_level_api::CompressedFheBool);

impl_destroy_on_type!(CompressedFheBool);
impl_clone_on_type!(CompressedFheBool);
impl_serialize_deserialize_on_type!(CompressedFheBool);
impl_safe_serialize_on_type!(CompressedFheBool);
impl_safe_deserialize_conformant_on_type!(CompressedFheBool, FheBoolConformanceParams);
impl_try_encrypt_with_client_key_on_type!(CompressedFheBool{crate::high_level_api::CompressedFheBool}, bool);

#[no_mangle]
pub unsafe extern "C" fn compressed_fhe_bool_decompress(
    sself: *const CompressedFheBool,
    result: *mut *mut FheBool,
) -> std::os::raw::c_int {
    crate::c_api::utils::catch_panic(|| {
        let compressed = crate::c_api::utils::get_ref_checked(sself).unwrap();

        let decompressed_inner = compressed.0.decompress();
        *result = Box::into_raw(Box::new(FheBool(decompressed_inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn fhe_bool_compress(
    sself: *const FheBool,
    result: *mut *mut CompressedFheBool,
) -> std::os::raw::c_int {
    crate::c_api::utils::catch_panic(|| {
        let ct = crate::c_api::utils::get_ref_checked(sself).unwrap();

        let compressed_inner = ct.0.compress();
        *result = Box::into_raw(Box::new(CompressedFheBool(compressed_inner)));
    })
}
