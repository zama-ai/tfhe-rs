use super::utils::*;
use crate::c_api::utils::*;
use std::os::raw::c_int;

pub struct ClientKey(pub(crate) crate::high_level_api::ClientKey);
pub struct PublicKey(pub(crate) crate::high_level_api::PublicKey);
pub struct CompactPublicKey(pub(crate) crate::high_level_api::CompactPublicKey);
pub struct CompressedCompactPublicKey(pub(crate) crate::high_level_api::CompressedCompactPublicKey);
pub struct ServerKey(pub(crate) crate::high_level_api::ServerKey);
/// Compressed version of the ServerKey
///
/// Allows to save storage space and transfer time.
/// Also, the CompressedServerKey is the key format that allows to select
/// the target hardware of the actual ServerKey when decompressing it.
pub struct CompressedServerKey(pub(crate) crate::high_level_api::CompressedServerKey);

/// ServerKey that lives on a Cuda GPU
#[cfg(feature = "gpu")]
pub struct CudaServerKey(pub(crate) crate::high_level_api::CudaServerKey);

impl_destroy_on_type!(ClientKey);
impl_destroy_on_type!(PublicKey);
impl_destroy_on_type!(CompactPublicKey);
impl_destroy_on_type!(CompressedCompactPublicKey);
impl_destroy_on_type!(ServerKey);
impl_destroy_on_type!(CompressedServerKey);
#[cfg(feature = "gpu")]
impl_destroy_on_type!(CudaServerKey);

impl_serialize_deserialize_on_type!(ClientKey);
impl_serialize_deserialize_on_type!(PublicKey);
impl_serialize_deserialize_on_type!(CompactPublicKey);
impl_serialize_deserialize_on_type!(CompressedCompactPublicKey);
impl_serialize_deserialize_on_type!(ServerKey);
impl_serialize_deserialize_on_type!(CompressedServerKey);

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

/// Sets the cuda server key.
///
/// Once a cuda server key is set in a thread, all computations done in
/// that thread will actually happend on the Cuda GPU.
///
/// Does not take ownership of the key
#[cfg(feature = "gpu")]
#[no_mangle]
pub unsafe extern "C" fn set_cuda_server_key(server_key: *const CudaServerKey) -> c_int {
    catch_panic(|| {
        let server_key = get_ref_checked(server_key).unwrap();

        let cloned = server_key.0.clone();
        crate::high_level_api::set_server_key(cloned);
    })
}

#[no_mangle]
pub unsafe extern "C" fn unset_server_key() -> c_int {
    catch_panic(|| {
        crate::high_level_api::unset_server_key();
    })
}

/// Creates a new compressed server key
#[no_mangle]
pub unsafe extern "C" fn compressed_server_key_new(
    client_key: *const ClientKey,
    result_server_key: *mut *mut CompressedServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();
        *result_server_key = std::ptr::null_mut();

        let cks = get_ref_checked(client_key).unwrap();

        let sks = crate::high_level_api::CompressedServerKey::new(&cks.0);

        *result_server_key = Box::into_raw(Box::new(CompressedServerKey(sks)));
    })
}

/// Decompresses the CompressedServerKey to a ServerKey that lives on CPU
#[no_mangle]
pub unsafe extern "C" fn compressed_server_key_decompress(
    compressed_server_key: *const CompressedServerKey,
    result_server_key: *mut *mut ServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();
        *result_server_key = std::ptr::null_mut();

        let c_sks = get_ref_checked(compressed_server_key).unwrap();

        let sks = c_sks.0.decompress();

        *result_server_key = Box::into_raw(Box::new(ServerKey(sks)));
    })
}

/// Decompresses the CompressedServerKey to a CudaServerKey that lives on GPU
#[cfg(feature = "gpu")]
#[no_mangle]
pub unsafe extern "C" fn compressed_server_key_decompress_to_gpu(
    compressed_server_key: *const CompressedServerKey,
    result_server_key: *mut *mut CudaServerKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_server_key).unwrap();
        *result_server_key = std::ptr::null_mut();

        let c_sks = get_ref_checked(compressed_server_key).unwrap();

        let sks = c_sks.0.decompress_to_gpu();

        *result_server_key = Box::into_raw(Box::new(CudaServerKey(sks)));
    })
}

/// Generates a client key with the given config
///
/// This function takes ownership of the config,
/// thus the given config pointer should not be used/freed after.
#[no_mangle]
pub unsafe extern "C" fn client_key_generate(
    config: *mut super::config::Config,
    result_client_key: *mut *mut ClientKey,
) -> c_int {
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result_client_key).unwrap();

        *result_client_key = std::ptr::null_mut();

        let config = Box::from_raw(config);

        let cks = crate::high_level_api::ClientKey::generate(config.0);

        *result_client_key = Box::into_raw(Box::new(ClientKey(cks)));
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

#[no_mangle]
pub unsafe extern "C" fn compact_public_key_new(
    client_key: *const ClientKey,
    result_public_key: *mut *mut CompactPublicKey,
) -> c_int {
    catch_panic(|| {
        let client_key = get_ref_checked(client_key).unwrap();
        let inner = crate::high_level_api::CompactPublicKey::new(&client_key.0);

        *result_public_key = Box::into_raw(Box::new(CompactPublicKey(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compressed_compact_public_key_new(
    client_key: *const ClientKey,
    result_public_key: *mut *mut CompressedCompactPublicKey,
) -> c_int {
    catch_panic(|| {
        let client_key = get_ref_checked(client_key).unwrap();
        let inner = crate::high_level_api::CompressedCompactPublicKey::new(&client_key.0);

        *result_public_key = Box::into_raw(Box::new(CompressedCompactPublicKey(inner)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compressed_compact_public_key_decompress(
    public_key: *const CompressedCompactPublicKey,
    result_public_key: *mut *mut CompactPublicKey,
) -> c_int {
    catch_panic(|| {
        let public_key = get_ref_checked(public_key).unwrap();

        *result_public_key = Box::into_raw(Box::new(CompactPublicKey(public_key.0.decompress())));
    })
}
