use crate::c_api::buffer::*;
use crate::c_api::utils::*;
use std::os::raw::c_int;

use crate::shortint;

use super::{ShortintCiphertext, ShortintCompressedCiphertext};
pub struct ShortintClientKey(pub(in crate::c_api) shortint::client_key::ClientKey);

#[no_mangle]
pub unsafe extern "C" fn shortint_gen_client_key(
    shortint_parameters: super::parameters::ShortintPBSParameters,
    result_client_key: *mut *mut ShortintClientKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_client_key).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result_client_key = std::ptr::null_mut();

        let shortint_parameters: crate::shortint::parameters::ClassicPBSParameters =
            shortint_parameters.try_into().unwrap();

        let client_key = shortint::client_key::ClientKey::new(shortint_parameters);

        let heap_allocated_client_key = Box::new(ShortintClientKey(client_key));

        *result_client_key = Box::into_raw(heap_allocated_client_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_client_key_encrypt(
    client_key: *const ShortintClientKey,
    value_to_encrypt: u64,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let client_key = get_ref_checked(client_key).unwrap();

        let heap_allocated_ciphertext =
            Box::new(ShortintCiphertext(client_key.0.encrypt(value_to_encrypt)));

        *result = Box::into_raw(heap_allocated_ciphertext);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_client_key_encrypt_compressed(
    client_key: *const ShortintClientKey,
    value_to_encrypt: u64,
    result: *mut *mut ShortintCompressedCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let client_key = get_ref_checked(client_key).unwrap();

        let heap_allocated_ciphertext = Box::new(ShortintCompressedCiphertext(
            client_key.0.encrypt_compressed(value_to_encrypt),
        ));

        *result = Box::into_raw(heap_allocated_ciphertext);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_client_key_decrypt(
    client_key: *const ShortintClientKey,
    ciphertext_to_decrypt: *const ShortintCiphertext,
    result: *mut u64,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let client_key = get_ref_checked(client_key).unwrap();
        let ciphertext_to_decrypt = get_ref_checked(ciphertext_to_decrypt).unwrap();
        let inner_ct = &ciphertext_to_decrypt.0;

        *result = client_key.0.decrypt(inner_ct);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_serialize_client_key(
    client_key: *const ShortintClientKey,
    result: *mut Buffer,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let client_key = get_ref_checked(client_key).unwrap();

        let buffer: Buffer = bincode::serialize(&client_key.0).unwrap().into();

        *result = buffer;
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_deserialize_client_key(
    buffer_view: BufferView,
    result: *mut *mut ShortintClientKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let client_key: shortint::client_key::ClientKey =
            bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_client_key = Box::new(ShortintClientKey(client_key));

        *result = Box::into_raw(heap_allocated_client_key);
    })
}
