use crate::c_api::utils::*;
use std::os::raw::c_int;

use super::parameters::BooleanParameters;
use super::{BooleanCiphertext, BooleanClientKey, BooleanServerKey};

#[no_mangle]
pub unsafe extern "C" fn destroy_boolean_client_key(client_key: *mut BooleanClientKey) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(client_key).unwrap();

        drop(Box::from_raw(client_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn destroy_boolean_server_key(server_key: *mut BooleanServerKey) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(server_key).unwrap();

        drop(Box::from_raw(server_key));
    })
}

#[no_mangle]
pub unsafe extern "C" fn destroy_boolean_parameters(
    boolean_parameters: *mut BooleanParameters,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(boolean_parameters).unwrap();

        drop(Box::from_raw(boolean_parameters));
    })
}

#[no_mangle]
pub unsafe extern "C" fn destroy_boolean_ciphertext(
    boolean_ciphertext: *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(boolean_ciphertext).unwrap();

        drop(Box::from_raw(boolean_ciphertext));
    })
}
