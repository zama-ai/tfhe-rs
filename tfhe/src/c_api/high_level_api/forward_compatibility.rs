use super::keys::ClientKey;
use crate::c_api::buffer::BufferView;
use crate::c_api::utils::*;
use crate::forward_compatibility::ConvertInto;
use tfhe_c_api_dynamic_buffer::DynamicBuffer;

use std::ffi::c_int;

// TODO: automate this as much as possible
// This was a proof of concept and it works

#[no_mangle]
pub unsafe extern "C" fn client_key_update_serialization_from_0_4_to_0_5(
    buffer_view: BufferView,
    result: *mut DynamicBuffer,
) -> c_int {
    catch_panic(|| {
        let object = bincode::deserialize(buffer_view.into()).unwrap();
        let cks = ClientKey(object);

        let next_cks: next_tfhe::ClientKey = cks.0.convert_into();
        let serialized = bincode::serialize(&next_cks).unwrap();

        *result = serialized.into();
    })
}
