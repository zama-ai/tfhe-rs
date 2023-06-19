use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::{ShortintCiphertext, ShortintServerKey};

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

        let res = server_key.0.smart_mul_lsb(&mut ct_left.0, &mut ct_right.0);

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

        let res = server_key.0.unchecked_mul_lsb(&ct_left.0, &ct_right.0);

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

        server_key
            .0
            .smart_mul_lsb_assign(&mut ct_left_and_result.0, &mut ct_right.0);
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

        server_key
            .0
            .unchecked_mul_lsb_assign(&mut ct_left_and_result.0, &ct_right.0);
    })
}
