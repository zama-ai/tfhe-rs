use crate::c_api::buffer::*;
use crate::c_api::utils::*;
use std::os::raw::c_int;

use crate::shortint;

use super::ShortintCiphertext;

pub struct ShortintServerKey(pub(in crate::c_api) shortint::server_key::ServerKey);

#[no_mangle]
pub unsafe extern "C" fn shortints_serialize_server_key(
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
pub unsafe extern "C" fn shortints_deserialize_server_key(
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
