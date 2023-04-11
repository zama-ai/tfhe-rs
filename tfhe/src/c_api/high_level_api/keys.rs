use crate::c_api::utils::*;
use std::os::raw::c_int;

pub struct ClientKey(pub(crate) crate::high_level_api::ClientKey);
pub struct PublicKey(pub(crate) crate::high_level_api::PublicKey);
pub struct ServerKey(pub(crate) crate::high_level_api::ServerKey);

impl_destroy_on_type!(ClientKey);
impl_destroy_on_type!(PublicKey);
impl_destroy_on_type!(ServerKey);

impl_serialize_deserialize_on_type!(ClientKey);
impl_serialize_deserialize_on_type!(PublicKey);
impl_serialize_deserialize_on_type!(ServerKey);

#[no_mangle]
pub unsafe extern "C" fn generate_keys(
    config: *mut super::config::Config,
    result_client_key: *mut *mut ClientKey,
    result_server_key: *mut *mut ServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_client_key).unwrap();
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();

        *result_client_key = std::ptr::null_mut();
        *result_server_key = std::ptr::null_mut();

        let config = Box::from_raw(config);

        let (cks, sks) = crate::high_level_api::generate_keys(config.0);

        *result_client_key = Box::into_raw(Box::new(ClientKey(cks)));
        *result_server_key = Box::into_raw(Box::new(ServerKey(sks)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn set_server_key(server_key: *const ServerKey) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();

        let cloned = server_key.0.clone();
        crate::high_level_api::set_server_key(cloned);
    })
}

/// result can be null
#[no_mangle]
pub unsafe extern "C" fn unset_server_key(result: *mut *mut ServerKey) -> c_int {
    catch_panic(|| {
        let previous_key = crate::high_level_api::unset_server_key();

        if !result.is_null() {
            *result = Box::into_raw(Box::new(ServerKey(previous_key)))
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn public_key_new(
    client_key: *const ClientKey,
    result_public_key: *mut *mut PublicKey,
) -> c_int {
    catch_panic(|| {
        let client_key = get_ref_checked(client_key).unwrap();
        let inner = crate::high_level_api::PublicKey::new(&client_key.0);

        *result_public_key = Box::into_raw(Box::new(PublicKey(inner)));
    })
}
