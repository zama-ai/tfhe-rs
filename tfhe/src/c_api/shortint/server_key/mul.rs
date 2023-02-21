use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::{ShortintCiphertext, ShortintCiphertextInner, ShortintServerKey};

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_mul(
    server_key: *const ShortintServerKey,
    ct_left: *mut ShortintCiphertext,
    ct_right: *mut ShortintCiphertext,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_mut_checked(ct_left).unwrap();
        let ct_right = get_mut_checked(ct_right).unwrap();

        let res = dispatch_binary_server_key_call!(
            server_key,
            smart_mul_lsb,
            &mut ct_left,
            &mut ct_right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_mul(
    server_key: *const ShortintServerKey,
    ct_left: *const ShortintCiphertext,
    ct_right: *const ShortintCiphertext,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();
        let ct_right = get_ref_checked(ct_right).unwrap();

        let res =
            dispatch_binary_server_key_call!(server_key, unchecked_mul_lsb, &ct_left, &ct_right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_mul_assign(
    server_key: *const ShortintServerKey,
    ct_left_and_result: *mut ShortintCiphertext,
    ct_right: *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left_and_result = get_mut_checked(ct_left_and_result).unwrap();
        let ct_right = get_mut_checked(ct_right).unwrap();

        dispatch_binary_assign_server_key_call!(
            server_key,
            smart_mul_lsb_assign,
            &mut ct_left_and_result,
            &mut ct_right
        );
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_mul_assign(
    server_key: *const ShortintServerKey,
    ct_left_and_result: *mut ShortintCiphertext,
    ct_right: *const ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left_and_result = get_mut_checked(ct_left_and_result).unwrap();
        let ct_right = get_ref_checked(ct_right).unwrap();

        dispatch_binary_assign_server_key_call!(
            server_key,
            unchecked_mul_lsb_assign,
            &mut ct_left_and_result,
            &ct_right
        );
    })
}
