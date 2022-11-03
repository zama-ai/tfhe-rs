pub mod ciphertext;
pub mod client_key;
pub mod destroy;
pub mod parameters;
pub mod public_key;
pub mod server_key;

use crate::c_api::utils::*;
use std::os::raw::c_int;

use crate::boolean;

pub use ciphertext::BooleanCiphertext;
pub use client_key::BooleanClientKey;
pub use public_key::BooleanPublicKey;
pub use server_key::BooleanServerKey;

#[no_mangle]
pub unsafe extern "C" fn booleans_gen_keys_with_default_parameters(
    result_client_key: *mut *mut BooleanClientKey,
    result_server_key: *mut *mut BooleanServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_client_key).unwrap();
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result_client_key = std::ptr::null_mut();
        *result_server_key = std::ptr::null_mut();

        let (client_key, server_key) = boolean::gen_keys();
        let heap_allocated_client_key = Box::new(BooleanClientKey(client_key));
        let heap_allocated_server_key = Box::new(BooleanServerKey(server_key));

        *result_client_key = Box::into_raw(heap_allocated_client_key);
        *result_server_key = Box::into_raw(heap_allocated_server_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_gen_keys_with_parameters(
    boolean_parameters: *const parameters::BooleanParameters,
    result_client_key: *mut *mut BooleanClientKey,
    result_server_key: *mut *mut BooleanServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_client_key).unwrap();
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result_client_key = std::ptr::null_mut();
        *result_server_key = std::ptr::null_mut();

        let boolean_parameters = get_ref_checked(boolean_parameters).unwrap();

        let client_key = boolean::client_key::ClientKey::new(&boolean_parameters.0);
        let server_key = boolean::server_key::ServerKey::new(&client_key);

        let heap_allocated_client_key = Box::new(BooleanClientKey(client_key));
        let heap_allocated_server_key = Box::new(BooleanServerKey(server_key));

        *result_client_key = Box::into_raw(heap_allocated_client_key);
        *result_server_key = Box::into_raw(heap_allocated_server_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_gen_keys_with_predefined_parameters_set(
    boolean_parameters_set: c_int,
    result_client_key: *mut *mut BooleanClientKey,
    result_server_key: *mut *mut BooleanServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_client_key).unwrap();
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result_client_key = std::ptr::null_mut();
        *result_server_key = std::ptr::null_mut();

        let boolean_parameters_set_as_enum =
            parameters::BooleanParametersSet::try_from(boolean_parameters_set).unwrap();

        let boolean_parameters =
            parameters::BooleanParameters::from(boolean_parameters_set_as_enum);

        let client_key = boolean::client_key::ClientKey::new(&boolean_parameters.0);
        let server_key = boolean::server_key::ServerKey::new(&client_key);

        let heap_allocated_client_key = Box::new(BooleanClientKey(client_key));
        let heap_allocated_server_key = Box::new(BooleanServerKey(server_key));

        *result_client_key = Box::into_raw(heap_allocated_client_key);
        *result_server_key = Box::into_raw(heap_allocated_server_key);
    })
}

#[no_mangle]
pub unsafe extern "C" fn booleans_trivial_encrypt(
    message: bool,
    result: *mut *mut BooleanCiphertext,
) -> c_int {
    catch_panic(|| {
        use boolean::engine::WithThreadLocalEngine;

        check_ptr_is_non_null_and_aligned(result).unwrap();

        let heap_allocated_result = Box::new(BooleanCiphertext(
            boolean::engine::CpuBooleanEngine::with_thread_local_mut(|engine| {
                engine.trivial_encrypt(message)
            }),
        ));

        *result = Box::into_raw(heap_allocated_result);
    })
}
