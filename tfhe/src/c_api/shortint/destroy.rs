use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::{
    ShortintBivariatePBSLookupTable, ShortintCiphertext, ShortintClientKey,
    ShortintCompressedCiphertext, ShortintCompressedPublicKey, ShortintCompressedServerKey,
    ShortintPBSLookupTable, ShortintPublicKey, ShortintServerKey,
};

#[no_mangle]
pub unsafe extern "C" fn shortint_destroy_client_key(client_key: *mut ShortintClientKey) -> c_int {
    if client_key.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(client_key).unwrap();

        drop(Box::from_raw(client_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_destroy_server_key(server_key: *mut ShortintServerKey) -> c_int {
    if server_key.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(server_key).unwrap();

        drop(Box::from_raw(server_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_destroy_compressed_server_key(
    server_key: *mut ShortintCompressedServerKey,
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
pub unsafe extern "C" fn shortint_destroy_public_key(public_key: *mut ShortintPublicKey) -> c_int {
    if public_key.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(public_key).unwrap();

        drop(Box::from_raw(public_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_destroy_compressed_public_key(
    compressed_public_key: *mut ShortintCompressedPublicKey,
) -> c_int {
    if compressed_public_key.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(compressed_public_key).unwrap();

        drop(Box::from_raw(compressed_public_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_destroy_ciphertext(
    shortint_ciphertext: *mut ShortintCiphertext,
) -> c_int {
    if shortint_ciphertext.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(shortint_ciphertext).unwrap();

        drop(Box::from_raw(shortint_ciphertext));
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_destroy_compressed_ciphertext(
    shortint_ciphertext: *mut ShortintCompressedCiphertext,
) -> c_int {
    if shortint_ciphertext.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(shortint_ciphertext).unwrap();

        drop(Box::from_raw(shortint_ciphertext));
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_destroy_pbs_lookup_table(
    pbs_lookup_table: *mut ShortintPBSLookupTable,
) -> c_int {
    if pbs_lookup_table.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(pbs_lookup_table).unwrap();

        drop(Box::from_raw(pbs_lookup_table));
    })
}

#[no_mangle]
pub unsafe extern "C" fn shortint_destroy_bivariate_pbs_lookup_table(
    pbs_lookup_table: *mut ShortintBivariatePBSLookupTable,
) -> c_int {
    if pbs_lookup_table.is_null() {
        return 0;
    }
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(pbs_lookup_table).unwrap();

        drop(Box::from_raw(pbs_lookup_table));
    })
}
