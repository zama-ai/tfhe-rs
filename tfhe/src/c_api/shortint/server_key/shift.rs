use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::{ShortintCiphertext, ShortintServerKey};

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_left_shift(
    server_key: *const ShortintServerKey,
    ct: *mut ShortintCiphertext,
    shift: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct = get_mut_checked(ct).unwrap();

        let res = server_key.0.smart_scalar_left_shift(&mut ct.0, shift);
        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_scalar_left_shift(
    server_key: *const ShortintServerKey,
    ct: *const ShortintCiphertext,
    shift: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct = get_ref_checked(ct).unwrap();

        let res = server_key.0.unchecked_scalar_left_shift(&ct.0, shift);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_right_shift(
    server_key: *const ShortintServerKey,
    ct: *mut ShortintCiphertext,
    shift: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    shortint_server_key_unchecked_scalar_right_shift(server_key, ct, shift, result)
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_scalar_right_shift(
    server_key: *const ShortintServerKey,
    ct: *const ShortintCiphertext,
    shift: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct = get_ref_checked(ct).unwrap();

        let res = server_key.0.unchecked_scalar_right_shift(&ct.0, shift);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_left_shift_assign(
    server_key: *const ShortintServerKey,
    ct: *mut ShortintCiphertext,
    shift: u8,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let ct = get_mut_checked(ct).unwrap();

        server_key
            .0
            .smart_scalar_left_shift_assign(&mut ct.0, shift);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_scalar_left_shift_assign(
    server_key: *const ShortintServerKey,
    ct: *mut ShortintCiphertext,
    shift: u8,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let ct = get_mut_checked(ct).unwrap();

        server_key
            .0
            .unchecked_scalar_left_shift_assign(&mut ct.0, shift);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_right_shift_assign(
    server_key: *const ShortintServerKey,
    ct: *mut ShortintCiphertext,
    shift: u8,
) -> c_int {
    shortint_server_key_unchecked_scalar_right_shift_assign(server_key, ct, shift)
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_scalar_right_shift_assign(
    server_key: *const ShortintServerKey,
    ct: *mut ShortintCiphertext,
    shift: u8,
) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();
        let ct = get_mut_checked(ct).unwrap();

        server_key
            .0
            .unchecked_scalar_right_shift_assign(&mut ct.0, shift);
    })
}
