use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::{ShortintCiphertext, ShortintServerKey};

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_div(
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

        let res = server_key.0.smart_div(&mut ct_left.0, &mut ct_right.0);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_div(
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

        let res = server_key.0.unchecked_div(&ct_left.0, &ct_right.0);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_div_assign(
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
            .smart_div_assign(&mut ct_left_and_result.0, &mut ct_right.0);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_div_assign(
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
            .unchecked_div_assign(&mut ct_left_and_result.0, &ct_right.0);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_scalar_div(
    server_key: *const ShortintServerKey,
    ct_left: *const ShortintCiphertext,
    right: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();

        let res = server_key.0.unchecked_scalar_div(&ct_left.0, right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_scalar_div_assign(
    server_key: *const ShortintServerKey,
    ct_left_and_result: *mut ShortintCiphertext,
    right: u8,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left_and_result = get_mut_checked(ct_left_and_result).unwrap();

        server_key
            .0
            .unchecked_scalar_div_assign(&mut ct_left_and_result.0, right);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_scalar_mod(
    server_key: *const ShortintServerKey,
    ct_left: *const ShortintCiphertext,
    right: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();

        let res = server_key.0.unchecked_scalar_mod(&ct_left.0, right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_scalar_mod_assign(
    server_key: *const ShortintServerKey,
    ct_left_and_result: *mut ShortintCiphertext,
    right: u8,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left_and_result = get_mut_checked(ct_left_and_result).unwrap();

        server_key
            .0
            .unchecked_scalar_mod_assign(&mut ct_left_and_result.0, right);
    })
}
