use crate::c_api::buffer::*;
use crate::c_api::utils::*;
use bincode;
use std::os::raw::c_int;

use crate::shortint;

use super::{ShortintCiphertext, ShortintClientKey};

pub struct ShortintPublicKey(pub(in crate::c_api) shortint::public_key::PublicKey);

#[no_mangle]
pub unsafe extern "C" fn shortints_gen_public_key(
    client_key: *const ShortintClientKey,
    result: *mut *mut ShortintPublicKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let client_key = get_ref_checked(client_key).unwrap();

        let heap_allocated_public_key = Box::new(ShortintPublicKey(
            shortint::public_key::PublicKey::new(&client_key.0),
        ));

        *result = Box::into_raw(heap_allocated_public_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortints_public_key_encrypt(
    public_key: *const ShortintPublicKey,
    value_to_encrypt: u64,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let public_key = get_ref_checked(public_key).unwrap();

        let heap_allocated_ciphertext =
            Box::new(ShortintCiphertext(public_key.0.encrypt(value_to_encrypt)));

        *result = Box::into_raw(heap_allocated_ciphertext);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortints_serialize_public_key(
    public_key: *const ShortintPublicKey,
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
pub unsafe extern "C" fn shortints_deserialize_public_key(
    buffer_view: BufferView,
    result: *mut *mut ShortintPublicKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let public_key: shortint::public_key::PublicKey =
            bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_public_key = Box::new(ShortintPublicKey(public_key));

        *result = Box::into_raw(heap_allocated_public_key);
    })
}
