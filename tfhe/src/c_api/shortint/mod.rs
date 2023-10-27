pub mod ciphertext;
pub mod client_key;
pub mod destroy;
pub mod parameters;
pub mod public_key;
pub mod server_key;

use crate::c_api::utils::*;
use std::os::raw::c_int;

use crate::shortint;

pub use ciphertext::{ShortintCiphertext, ShortintCompressedCiphertext};
pub use client_key::ShortintClientKey;
pub use public_key::{ShortintCompressedPublicKey, ShortintPublicKey};
pub use server_key::pbs::{ShortintBivariatePBSLookupTable, ShortintPBSLookupTable};
pub use server_key::{ShortintCompressedServerKey, ShortintServerKey};

#[no_mangle]
pub unsafe extern "C" fn shortint_gen_keys_with_parameters(
    shortint_parameters: parameters::ShortintPBSParameters,
    result_client_key: *mut *mut ShortintClientKey,
    result_server_key: *mut *mut ShortintServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_client_key).unwrap();
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();

        // First fill the result with a null ptr so that if we fail and the return code is not
        // checked, then any access to the result pointer will segfault (mimics malloc on failure)
        *result_client_key = std::ptr::null_mut();
        *result_server_key = std::ptr::null_mut();

        let shortint_parameters: crate::shortint::parameters::ClassicPBSParameters =
            shortint_parameters.try_into().unwrap();

        let client_key = shortint::client_key::ClientKey::new(shortint_parameters);
        let server_key = shortint::server_key::ServerKey::new(&client_key);

        let heap_allocated_client_key = Box::new(ShortintClientKey(client_key));
        let heap_allocated_server_key = Box::new(ShortintServerKey(server_key));

        *result_client_key = Box::into_raw(heap_allocated_client_key);
        *result_server_key = Box::into_raw(heap_allocated_server_key);
    })
}
