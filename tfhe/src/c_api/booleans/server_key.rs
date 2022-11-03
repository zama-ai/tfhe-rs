use crate::c_api::buffer::*;
use crate::c_api::utils::*;
use std::os::raw::c_int;

use crate::boolean;
use crate::boolean::server_key::BinaryBooleanGates;

use super::BooleanCiphertext;

pub struct BooleanServerKey(pub(in crate::c_api) boolean::server_key::ServerKey);

#[no_mangle]
pub unsafe extern "C" fn booleans_gen_server_key(
    client_key: *const super::BooleanClientKey,
    result_server_key: *mut *mut BooleanServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result_server_key = std::ptr::null_mut();

        let client_key = get_ref_checked(client_key).unwrap();

        let server_key = boolean::server_key::ServerKey::new(&client_key.0);

        let heap_allocated_server_key = Box::new(BooleanServerKey(server_key));

        *result_server_key = Box::into_raw(heap_allocated_server_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_server_key_and(
    server_key: *const BooleanServerKey,
    ct_left: *const BooleanCiphertext,
    ct_right: *const BooleanCiphertext,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();
        let ct_right = get_ref_checked(ct_right).unwrap();

        let heap_allocated_result =
            Box::new(BooleanCiphertext(server_key.0.and(&ct_left.0, &ct_right.0)));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_server_key_nand(
    server_key: *const BooleanServerKey,
    ct_left: *const BooleanCiphertext,
    ct_right: *const BooleanCiphertext,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();
        let ct_right = get_ref_checked(ct_right).unwrap();

        let heap_allocated_result = Box::new(BooleanCiphertext(
            server_key.0.nand(&ct_left.0, &ct_right.0),
        ));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_server_key_nor(
    server_key: *const BooleanServerKey,
    ct_left: *const BooleanCiphertext,
    ct_right: *const BooleanCiphertext,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();
        let ct_right = get_ref_checked(ct_right).unwrap();

        let heap_allocated_result =
            Box::new(BooleanCiphertext(server_key.0.nor(&ct_left.0, &ct_right.0)));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_server_key_or(
    server_key: *const BooleanServerKey,
    ct_left: *const BooleanCiphertext,
    ct_right: *const BooleanCiphertext,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();
        let ct_right = get_ref_checked(ct_right).unwrap();

        let heap_allocated_result =
            Box::new(BooleanCiphertext(server_key.0.or(&ct_left.0, &ct_right.0)));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_server_key_xor(
    server_key: *const BooleanServerKey,
    ct_left: *const BooleanCiphertext,
    ct_right: *const BooleanCiphertext,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();
        let ct_right = get_ref_checked(ct_right).unwrap();

        let heap_allocated_result =
            Box::new(BooleanCiphertext(server_key.0.xor(&ct_left.0, &ct_right.0)));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_server_key_xnor(
    server_key: *const BooleanServerKey,
    ct_left: *const BooleanCiphertext,
    ct_right: *const BooleanCiphertext,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_left = get_ref_checked(ct_left).unwrap();
        let ct_right = get_ref_checked(ct_right).unwrap();

        let heap_allocated_result = Box::new(BooleanCiphertext(
            server_key.0.xnor(&ct_left.0, &ct_right.0),
        ));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_server_key_not(
    server_key: *const BooleanServerKey,
    ct_input: *const BooleanCiphertext,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_input = get_ref_checked(ct_input).unwrap();

        let heap_allocated_result = Box::new(BooleanCiphertext(server_key.0.not(&ct_input.0)));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_server_key_mux(
    server_key: *const BooleanServerKey,
    ct_condition: *const BooleanCiphertext,
    ct_then: *const BooleanCiphertext,
    ct_else: *const BooleanCiphertext,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key = get_ref_checked(server_key).unwrap();
        let ct_condition = get_ref_checked(ct_condition).unwrap();
        let ct_then = get_ref_checked(ct_then).unwrap();
        let ct_else = get_ref_checked(ct_else).unwrap();

        let heap_allocated_result = Box::new(BooleanCiphertext(server_key.0.mux(
            &ct_condition.0,
            &ct_then.0,
            &ct_else.0,
        )));

        *result = Box::into_raw(heap_allocated_result);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_serialize_server_key(
    server_key: *const BooleanServerKey,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();

        let buffer: Buffer = bincode::serialize(&server_key.0).unwrap().into();

        *result = buffer;
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_deserialize_server_key(
    buffer_view: BufferView,
    result: *mut *mut BooleanServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key: boolean::server_key::ServerKey =
            bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_server_key = Box::new(BooleanServerKey(server_key));

        *result = Box::into_raw(heap_allocated_server_key);
    })
}
