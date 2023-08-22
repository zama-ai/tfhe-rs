use crate::c_api::buffer::*;
use crate::c_api::utils::*;
use std::os::raw::c_int;

use crate::boolean;

use super::{BooleanCiphertext, BooleanClientKey};

pub struct BooleanPublicKey(pub(in crate::c_api) boolean::public_key::PublicKey);

#[no_mangle]
pub unsafe extern "C" fn boolean_gen_public_key(
    client_key: *const BooleanClientKey,
    result: *mut *mut BooleanPublicKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let client_key = get_ref_checked(client_key).unwrap();

        let heap_allocated_public_key = Box::new(BooleanPublicKey(
            boolean::public_key::PublicKey::new(&client_key.0),
        ));

        *result = Box::into_raw(heap_allocated_public_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn boolean_public_key_encrypt(
    public_key: *const BooleanPublicKey,
    value_to_encrypt: bool,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let public_key = get_ref_checked(public_key).unwrap();

        let heap_allocated_ciphertext =
            Box::new(BooleanCiphertext(public_key.0.encrypt(value_to_encrypt)));

        *result = Box::into_raw(heap_allocated_ciphertext);
    })
}

#[no_mangle]
pub unsafe extern "C" fn boolean_serialize_public_key(
    public_key: *const BooleanPublicKey,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let public_key = get_ref_checked(public_key).unwrap();

        let buffer: Buffer = bincode::serialize(&public_key.0).unwrap().into();

        *result = buffer;
    })
}

#[no_mangle]
pub unsafe extern "C" fn boolean_deserialize_public_key(
    buffer_view: BufferView,
    result: *mut *mut BooleanPublicKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let public_key: boolean::public_key::PublicKey =
            bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_public_key = Box::new(BooleanPublicKey(public_key));

        *result = Box::into_raw(heap_allocated_public_key);
    })
}
