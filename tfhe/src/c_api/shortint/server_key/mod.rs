use crate::c_api::buffer::*;
use crate::c_api::utils::*;
use std::os::raw::c_int;

use crate::shortint;

use super::ShortintCiphertext;

pub mod add;
pub mod bitwise_op;
pub mod comp_op;
pub mod div_mod;
pub mod mul;
pub mod neg;
pub mod pbs;
pub mod scalar_add;
pub mod scalar_mul;
pub mod scalar_sub;
pub mod shift;
pub mod sub;

pub struct ShortintServerKey(pub(in crate::c_api) shortint::server_key::ServerKey);
pub struct ShortintCompressedServerKey(
    pub(in crate::c_api) shortint::server_key::CompressedServerKey,
);

#[no_mangle]
pub unsafe extern "C" fn shortint_gen_server_key(
    client_key: *const super::ShortintClientKey,
    result_server_key: *mut *mut ShortintServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result_server_key = std::ptr::null_mut();

        let client_key = get_ref_checked(client_key).unwrap();

        let server_key = shortint::server_key::ServerKey::new(&client_key.0);

        let heap_allocated_server_key = Box::new(ShortintServerKey(server_key));

        *result_server_key = Box::into_raw(heap_allocated_server_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_server_key_create_trivial(
    server_key: *const ShortintServerKey,
    value_to_trivially_encrypt: u64,
    result: *mut *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        let server_key = get_ref_checked(server_key).unwrap();

        let res = server_key.0.create_trivial(value_to_trivially_encrypt);

        let heap_allocated_ciphertext = Box::new(ShortintCiphertext(res));

        *result = Box::into_raw(heap_allocated_ciphertext);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_serialize_server_key(
    server_key: *const ShortintServerKey,
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
pub unsafe extern "C" fn shortint_deserialize_server_key(
    buffer_view: BufferView,
    result: *mut *mut ShortintServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let server_key: shortint::server_key::ServerKey =
            bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_server_key = Box::new(ShortintServerKey(server_key));

        *result = Box::into_raw(heap_allocated_server_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_gen_compressed_server_key(
    client_key: *const super::ShortintClientKey,
    result_server_key: *mut *mut ShortintCompressedServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result_server_key = std::ptr::null_mut();

        let client_key = get_ref_checked(client_key).unwrap();

        let server_key = shortint::server_key::CompressedServerKey::new(&client_key.0);

        let heap_allocated_server_key = Box::new(ShortintCompressedServerKey(server_key));

        *result_server_key = Box::into_raw(heap_allocated_server_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_serialize_compressed_server_key(
    server_key: *const ShortintCompressedServerKey,
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
pub unsafe extern "C" fn shortint_deserialize_compressed_server_key(
    buffer_view: BufferView,
    result: *mut *mut ShortintCompressedServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        // *result = std::ptr::null_mut();

        let server_key: shortint::server_key::CompressedServerKey =
            bincode::deserialize(buffer_view.into()).unwrap();

        let heap_allocated_server_key = Box::new(ShortintCompressedServerKey(server_key));

        *result = Box::into_raw(heap_allocated_server_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_decompress_server_key(
    compressed_server_key: *const ShortintCompressedServerKey,
    result: *mut *mut ShortintServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result = std::ptr::null_mut();

        let compressed_server_key = get_ref_checked(compressed_server_key).unwrap();

        let heap_allocated_public_key = Box::new(ShortintServerKey(
            shortint::server_key::ServerKey::from(compressed_server_key.0.clone()),
        ));

        *result = Box::into_raw(heap_allocated_public_key);
    })
}
