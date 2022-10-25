use crate::c_api::buffer::*;
use crate::c_api::utils::*;
use bincode;
use std::os::raw::c_int;

use crate::boolean;

use super::BooleanCiphertext;
pub struct BooleanClientKey(pub(in crate::c_api) boolean::client_key::ClientKey);

#[no_mangle]
pub unsafe extern "C" fn booleans_client_key_encrypt(
    client_key: *const BooleanClientKey,
    value_to_encrypt: bool,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let client_key = get_ref_checked(client_key).unwrap();

        let heap_allocated_ciphertext =
            Box::new(BooleanCiphertext(client_key.0.encrypt(value_to_encrypt)));

        *result = Box::into_raw(heap_allocated_ciphertext);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_client_key_decrypt(
    client_key: *const BooleanClientKey,
    ciphertext_to_decrypt: *const BooleanCiphertext,
    result: *mut bool,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let client_key = get_ref_checked(client_key).unwrap();
        let ciphertext_to_decrypt = get_ref_checked(ciphertext_to_decrypt).unwrap();

        *result = client_key.0.decrypt(&ciphertext_to_decrypt.0);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_serialize_client_key(
    client_key: *const BooleanClientKey,
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
pub unsafe extern "C" fn booleans_deserialize_client_key(
    buffer_view: BufferView,
    result: *mut *mut BooleanClientKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let client_key: boolean::client_key::ClientKey =
            bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_client_key = Box::new(BooleanClientKey(client_key));

        *result = Box::into_raw(heap_allocated_client_key);
    })
}
