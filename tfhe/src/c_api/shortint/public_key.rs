use crate::c_api::buffer::*;
use crate::c_api::utils::*;
use std::os::raw::c_int;

use crate::shortint;

use super::{ShortintCiphertext, ShortintClientKey};

pub struct ShortintPublicKey(pub(in crate::c_api) shortint::PublicKey);

pub struct ShortintCompressedPublicKey(pub(in crate::c_api) shortint::CompressedPublicKey);

#[no_mangle]
pub unsafe extern "C" fn shortint_gen_public_key(
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
pub unsafe extern "C" fn shortint_public_key_encrypt(
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
pub unsafe extern "C" fn shortint_serialize_public_key(
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
pub unsafe extern "C" fn shortint_deserialize_public_key(
    buffer_view: BufferView,
    result: *mut *mut ShortintPublicKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let public_key = bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_public_key = Box::new(ShortintPublicKey(public_key));

        *result = Box::into_raw(heap_allocated_public_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_gen_compressed_public_key(
    client_key: *const ShortintClientKey,
    result: *mut *mut ShortintCompressedPublicKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let client_key = get_ref_checked(client_key).unwrap();

        let heap_allocated_compressed_public_key = Box::new(ShortintCompressedPublicKey(
            shortint::public_key::CompressedPublicKey::new(&client_key.0),
        ));

        *result = Box::into_raw(heap_allocated_compressed_public_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_compressed_public_key_encrypt(
    compressed_public_key: *const ShortintCompressedPublicKey,
    value_to_encrypt: u64,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let compressed_public_key = get_ref_checked(compressed_public_key).unwrap();

        let heap_allocated_ciphertext = Box::new(ShortintCiphertext(
            compressed_public_key.0.encrypt(value_to_encrypt),
        ));

        *result = Box::into_raw(heap_allocated_ciphertext);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_serialize_compressed_public_key(
    compressed_public_key: *const ShortintCompressedPublicKey,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let compressed_public_key = get_ref_checked(compressed_public_key).unwrap();

        let buffer: Buffer = bincode::serialize(&compressed_public_key.0).unwrap().into();

        *result = buffer;
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_deserialize_compressed_public_key(
    buffer_view: BufferView,
    result: *mut *mut ShortintCompressedPublicKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let compressed_public_key = bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_public_key =
            Box::new(ShortintCompressedPublicKey(compressed_public_key));

        *result = Box::into_raw(heap_allocated_public_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_decompress_public_key(
    compressed_public_key: *const ShortintCompressedPublicKey,
    result: *mut *mut ShortintPublicKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let compressed_public_key = get_ref_checked(compressed_public_key).unwrap();

        let heap_allocated_public_key =
            Box::new(ShortintPublicKey(compressed_public_key.0.clone().into()));

        *result = Box::into_raw(heap_allocated_public_key);
    })
}
