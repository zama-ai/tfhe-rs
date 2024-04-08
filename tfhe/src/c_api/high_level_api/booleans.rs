use super::utils::*;
use crate::c_api::utils::check_ptr_is_non_null_and_aligned;
use crate::high_level_api::prelude::*;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

pub struct FheBool(pub(in crate::c_api) crate::high_level_api::FheBool);

impl_destroy_on_type!(FheBool);
impl_clone_on_type!(FheBool);
impl_serialize_deserialize_on_type!(FheBool);
impl_safe_serialize_on_type!(FheBool);
impl_safe_deserialize_conformant_integer!(FheBool, FheBoolConformanceParams);

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
impl_try_encrypt_with_compact_public_key_on_type!(FheBool{crate::high_level_api::FheBool}, bool);

pub struct CompressedFheBool(crate::high_level_api::CompressedFheBool);

impl_destroy_on_type!(CompressedFheBool);
impl_clone_on_type!(CompressedFheBool);
impl_serialize_deserialize_on_type!(CompressedFheBool);
impl_safe_serialize_on_type!(CompressedFheBool);
impl_safe_deserialize_conformant_integer!(CompressedFheBool, FheBoolConformanceParams);
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

pub struct CompactFheBool(crate::high_level_api::CompactFheBool);

impl_destroy_on_type!(CompactFheBool);
impl_clone_on_type!(CompactFheBool);
impl_serialize_deserialize_on_type!(CompactFheBool);
impl_safe_serialize_on_type!(CompactFheBool);
impl_safe_deserialize_conformant_integer!(CompactFheBool, FheBoolConformanceParams);
impl_try_encrypt_with_compact_public_key_on_type!(CompactFheBool{crate::high_level_api::CompactFheBool}, bool);

#[no_mangle]
pub unsafe extern "C" fn compact_fhe_bool_expand(
    sself: *const CompactFheBool,
    result: *mut *mut FheBool,
) -> std::os::raw::c_int {
    crate::c_api::utils::catch_panic(|| {
        let compact = crate::c_api::utils::get_ref_checked(sself).unwrap();

        let expanded = compact.0.expand();
        *result = Box::into_raw(Box::new(FheBool(expanded)));
    })
}

pub struct CompactFheBoolList(crate::high_level_api::CompactFheBoolList);

impl_destroy_on_type!(CompactFheBoolList);
impl_clone_on_type!(CompactFheBoolList);
impl_serialize_deserialize_on_type!(CompactFheBoolList);
impl_safe_serialize_on_type!(CompactFheBoolList);
impl_safe_deserialize_conformant_integer_list!(CompactFheBoolList);
impl_try_encrypt_list_with_compact_public_key_on_type!(CompactFheBoolList{crate::high_level_api::CompactFheBoolList}, bool);

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

#[cfg(feature = "zk-pok-experimental")]
mod zk {
    use crate::c_api::high_level_api::utils::{
        impl_clone_on_type, impl_destroy_on_type, impl_safe_serialize_on_type,
        impl_serialize_deserialize_on_type,
    };
    use std::ffi::c_int;

    pub struct ProvenCompactFheBool(crate::high_level_api::ProvenCompactFheBool);

    impl_destroy_on_type!(ProvenCompactFheBool);
    impl_clone_on_type!(ProvenCompactFheBool);
    impl_serialize_deserialize_on_type!(ProvenCompactFheBool);
    impl_safe_serialize_on_type!(ProvenCompactFheBool);

    #[no_mangle]
    pub unsafe extern "C" fn proven_compact_fhe_bool_try_encrypt(
        message: bool,
        public_params: &crate::c_api::high_level_api::zk::CompactPkePublicParams,
        pk: &crate::c_api::high_level_api::keys::CompactPublicKey,
        compute_load: crate::c_api::high_level_api::zk::ZkComputeLoad,
        out_result: *mut *mut ProvenCompactFheBool,
    ) -> c_int {
        crate::c_api::utils::catch_panic(|| {
            let result = crate::high_level_api::ProvenCompactFheBool::try_encrypt(
                message,
                &public_params.0,
                &pk.0,
                compute_load.into(),
            )
            .unwrap();

            *out_result = Box::into_raw(Box::new(ProvenCompactFheBool(result)));
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn proven_compact_fhe_bool_verify_and_expand(
        ct: *const ProvenCompactFheBool,
        public_params: &crate::c_api::high_level_api::zk::CompactPkePublicParams,
        pk: &crate::c_api::high_level_api::keys::CompactPublicKey,
        out_result: *mut *mut super::FheBool,
    ) -> c_int {
        crate::c_api::utils::catch_panic(|| {
            let ct = crate::c_api::utils::get_ref_checked(ct).unwrap();

            let result =
                ct.0.clone()
                    .verify_and_expand(&public_params.0, &pk.0)
                    .unwrap();

            *out_result = Box::into_raw(Box::new(super::FheBool(result)));
        })
    }

    pub struct ProvenCompactFheBoolList(crate::high_level_api::ProvenCompactFheBoolList);

    impl_destroy_on_type!(ProvenCompactFheBoolList);
    impl_clone_on_type!(ProvenCompactFheBoolList);
    impl_serialize_deserialize_on_type!(ProvenCompactFheBoolList);
    impl_safe_serialize_on_type!(ProvenCompactFheBoolList);

    #[no_mangle]
    pub unsafe extern "C" fn proven_compact_fhe_bool_list_try_encrypt(
        input: *const bool,
        input_len: usize,
        public_params: &crate::c_api::high_level_api::zk::CompactPkePublicParams,
        pk: &crate::c_api::high_level_api::keys::CompactPublicKey,
        compute_load: crate::c_api::high_level_api::zk::ZkComputeLoad,
        out_result: *mut *mut ProvenCompactFheBoolList,
    ) -> ::std::os::raw::c_int {
        crate::c_api::utils::catch_panic(|| {
            let messages = std::slice::from_raw_parts(input, input_len);

            let result = crate::high_level_api::ProvenCompactFheBoolList::try_encrypt(
                messages,
                &public_params.0,
                &pk.0,
                compute_load.into(),
            )
            .unwrap();

            *out_result = Box::into_raw(Box::new(ProvenCompactFheBoolList(result)));
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn proven_compact_fhe_bool_list_len(
        sself: *const ProvenCompactFheBoolList,
        result: *mut usize,
    ) -> ::std::os::raw::c_int {
        crate::c_api::utils::catch_panic(|| {
            let list = crate::c_api::utils::get_ref_checked(sself).unwrap();

            *result = list.0.len();
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn proven_compact_fhe_bool_list_verify_and_expand(
        list: &ProvenCompactFheBoolList,
        public_params: &crate::c_api::high_level_api::zk::CompactPkePublicParams,
        pk: &crate::c_api::high_level_api::keys::CompactPublicKey,
        output: *mut *mut super::FheBool,
        output_len: usize,
    ) -> ::std::os::raw::c_int {
        crate::c_api::utils::catch_panic(|| {
            let expanded = list.0.verify_and_expand(&public_params.0, &pk.0).unwrap();

            let num_to_take = output_len.max(list.0.len());
            let iter = expanded.into_iter().take(num_to_take).enumerate();
            for (i, fhe_uint) in iter {
                let ptr = output.wrapping_add(i);
                *ptr = Box::into_raw(Box::new(super::FheBool(fhe_uint)));
            }
        })
    }
}
