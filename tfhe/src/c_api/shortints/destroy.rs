use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::parameters::ShortintParameters;
use super::{ShortintCiphertext, ShortintClientKey, ShortintServerKey};

#[no_mangle]
pub unsafe extern "C" fn destroy_shortint_client_key(client_key: *mut ShortintClientKey) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(client_key).unwrap();

        drop(Box::from_raw(client_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn destroy_shortint_server_key(server_key: *mut ShortintServerKey) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(server_key).unwrap();

        drop(Box::from_raw(server_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn destroy_shortint_parameters(
    shortint_parameters: *mut ShortintParameters,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(shortint_parameters).unwrap();

        drop(Box::from_raw(shortint_parameters));
    })
}

#[no_mangle]
pub unsafe extern "C" fn destroy_shortint_ciphertext(
    shortint_ciphertext: *mut ShortintCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(shortint_ciphertext).unwrap();

        drop(Box::from_raw(shortint_ciphertext));
    })
}
