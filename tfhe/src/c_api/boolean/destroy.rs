use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::{
    BooleanCiphertext, BooleanClientKey, BooleanCompressedCiphertext, BooleanCompressedServerKey,
    BooleanPublicKey, BooleanServerKey,
};

#[no_mangle]
pub unsafe extern "C" fn boolean_destroy_client_key(client_key: *mut BooleanClientKey) -> c_int {
    if client_key.is_null() {
        return 0;
    }

    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(client_key).unwrap();

        drop(Box::from_raw(client_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn boolean_destroy_server_key(server_key: *mut BooleanServerKey) -> c_int {
    if server_key.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(server_key).unwrap();

        drop(Box::from_raw(server_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn boolean_destroy_compressed_server_key(
    server_key: *mut BooleanCompressedServerKey,
) -> c_int {
    if server_key.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(server_key).unwrap();

        drop(Box::from_raw(server_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn boolean_destroy_public_key(public_key: *mut BooleanPublicKey) -> c_int {
    if public_key.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(public_key).unwrap();

        drop(Box::from_raw(public_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn boolean_destroy_ciphertext(
    boolean_ciphertext: *mut BooleanCiphertext,
) -> c_int {
    if boolean_ciphertext.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(boolean_ciphertext).unwrap();

        drop(Box::from_raw(boolean_ciphertext));
    })
}

#[no_mangle]
pub unsafe extern "C" fn boolean_destroy_compressed_ciphertext(
    boolean_ciphertext: *mut BooleanCompressedCiphertext,
) -> c_int {
    if boolean_ciphertext.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(boolean_ciphertext).unwrap();

        drop(Box::from_raw(boolean_ciphertext));
    })
}
