use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::{ShortintCiphertext, ShortintCiphertextInner, ShortintServerKey};

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_greater(
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
            smart_greater,
            &mut ct_left,
            &mut ct_right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_greater(
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
            dispatch_binary_server_key_call!(server_key, unchecked_greater, &ct_left, &ct_right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_greater_or_equal(
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
            smart_greater_or_equal,
            &mut ct_left,
            &mut ct_right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_greater_or_equal(
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

        let res = dispatch_binary_server_key_call!(
            server_key,
            unchecked_greater_or_equal,
            &ct_left,
            &ct_right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_less(
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

        let res =
            dispatch_binary_server_key_call!(server_key, smart_less, &mut ct_left, &mut ct_right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_less(
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

        let res = dispatch_binary_server_key_call!(server_key, unchecked_less, &ct_left, &ct_right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_less_or_equal(
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
            smart_less_or_equal,
            &mut ct_left,
            &mut ct_right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_less_or_equal(
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

        let res = dispatch_binary_server_key_call!(
            server_key,
            unchecked_less_or_equal,
            &ct_left,
            &ct_right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_equal(
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

        let res =
            dispatch_binary_server_key_call!(server_key, smart_equal, &mut ct_left, &mut ct_right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_equal(
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
            dispatch_binary_server_key_call!(server_key, unchecked_equal, &ct_left, &ct_right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_not_equal(
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
            smart_not_equal,
            &mut ct_left,
            &mut ct_right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_unchecked_not_equal(
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
            dispatch_binary_server_key_call!(server_key, unchecked_not_equal, &ct_left, &ct_right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_greater(
    server_key: *const ShortintServerKey,
    ct_left: *const ShortintCiphertext,
    right: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();

        let res =
            dispatch_binary_server_key_call!(server_key, smart_scalar_greater, &ct_left, right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_greater_or_equal(
    server_key: *const ShortintServerKey,
    ct_left: *const ShortintCiphertext,
    right: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();

        let res = dispatch_binary_server_key_call!(
            server_key,
            smart_scalar_greater_or_equal,
            &ct_left,
            right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_less(
    server_key: *const ShortintServerKey,
    ct_left: *const ShortintCiphertext,
    right: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();

        let res = dispatch_binary_server_key_call!(server_key, smart_scalar_less, &ct_left, right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_less_or_equal(
    server_key: *const ShortintServerKey,
    ct_left: *const ShortintCiphertext,
    right: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();

        let res = dispatch_binary_server_key_call!(
            server_key,
            smart_scalar_less_or_equal,
            &ct_left,
            right
        );

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_equal(
    server_key: *const ShortintServerKey,
    ct_left: *const ShortintCiphertext,
    right: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();

        let res = dispatch_binary_server_key_call!(server_key, smart_scalar_equal, &ct_left, right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_smart_scalar_not_equal(
    server_key: *const ShortintServerKey,
    ct_left: *const ShortintCiphertext,
    right: u8,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();

        let res =
            dispatch_binary_server_key_call!(server_key, smart_scalar_not_equal, &ct_left, right);

        let heap_allocated_ct_result = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ct_result);
    })
}
