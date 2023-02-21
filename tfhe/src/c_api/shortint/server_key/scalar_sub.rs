use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::{ShortintCiphertext, ShortintCiphertextInner, ShortintServerKey};

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_sub(
    server_key: *const ShortintServerKey,
    ct_left: *mut ShortintCiphertext,
    scalar_right: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_mut_checked(ct_left).unwrap();

        let res = dispatch_binary_server_key_call!(
            server_key,
            smart_scalar_sub,
            &mut ct_left,
            scalar_right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_scalar_sub(
    server_key: *const ShortintServerKey,
    ct_left: *const ShortintCiphertext,
    scalar_right: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();

        let res = dispatch_binary_server_key_call!(
            server_key,
            unchecked_scalar_sub,
            &ct_left,
            scalar_right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_sub_assign(
    server_key: *const ShortintServerKey,
    ct_left_and_result: *mut ShortintCiphertext,
    scalar_right: u8,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left_and_result = get_mut_checked(ct_left_and_result).unwrap();

        dispatch_binary_assign_server_key_call!(
            server_key,
            smart_scalar_sub_assign,
            &mut ct_left_and_result,
            scalar_right
        );
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_scalar_sub_assign(
    server_key: *const ShortintServerKey,
    ct_left_and_result: *mut ShortintCiphertext,
    scalar_right: u8,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left_and_result = get_mut_checked(ct_left_and_result).unwrap();

        dispatch_binary_assign_server_key_call!(
            server_key,
            unchecked_scalar_sub_assign,
            &mut ct_left_and_result,
            scalar_right
        );
    })
}
