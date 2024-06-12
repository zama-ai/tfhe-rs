use super::utils::*;
use crate::c_api::high_level_api::config::Config;
use crate::c_api::utils::get_ref_checked;
use crate::zk::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use std::ffi::c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ZkComputeLoad {
    ZkComputeLoadProof,
    ZkComputeLoadVerify,
}

impl From<ZkComputeLoad> for crate::zk::ZkComputeLoad {
    fn from(value: ZkComputeLoad) -> Self {
        match value {
            ZkComputeLoad::ZkComputeLoadProof => Self::Proof,
            ZkComputeLoad::ZkComputeLoadVerify => Self::Verify,
        }
    }
}

pub struct CompactPkePublicParams(pub(crate) crate::core_crypto::entities::CompactPkePublicParams);
impl_destroy_on_type!(CompactPkePublicParams);

/// Serializes the public params
///
/// If compress is true, the data will be compressed (less serialized bytes), however, this makes
/// the serialization process slower.
///
/// Also, the value to `compress` should match the value given to `is_compressed`
/// when deserializing.
#[no_mangle]
pub unsafe extern "C" fn compact_pke_public_params_serialize(
    sself: *const CompactPkePublicParams,
    compress: bool,
    result: *mut crate::c_api::buffer::DynamicBuffer,
) -> ::std::os::raw::c_int {
    crate::c_api::utils::catch_panic(|| {
        crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

        let wrapper = crate::c_api::utils::get_ref_checked(sself).unwrap();

        let compress = if compress {
            Compress::Yes
        } else {
            Compress::No
        };
        let mut buffer = vec![];
        wrapper
            .0
            .serialize_with_mode(&mut buffer, compress)
            .unwrap();

        *result = buffer.into();
    })
}

/// Deserializes the public params
///
/// If the data comes from compressed public params, then `is_compressed` must be true.
#[no_mangle]
pub unsafe extern "C" fn compact_pke_public_params_deserialize(
    buffer_view: crate::c_api::buffer::DynamicBufferView,
    is_compressed: bool,
    validate: bool,
    result: *mut *mut CompactPkePublicParams,
) -> ::std::os::raw::c_int {
    crate::c_api::utils::catch_panic(|| {
        crate::c_api::utils::check_ptr_is_non_null_and_aligned(result).unwrap();

        *result = std::ptr::null_mut();

        let deserialized = crate::zk::CompactPkePublicParams::deserialize_with_mode(
            buffer_view.as_slice(),
            if is_compressed {
                Compress::Yes
            } else {
                Compress::No
            },
            if validate {
                Validate::Yes
            } else {
                Validate::No
            },
        )
        .unwrap();

        let heap_allocated_object = Box::new(CompactPkePublicParams(deserialized));

        *result = Box::into_raw(heap_allocated_object);
    })
}

pub struct CompactPkeCrs(pub(crate) crate::core_crypto::entities::CompactPkeCrs);

impl_destroy_on_type!(CompactPkeCrs);

#[no_mangle]
pub unsafe extern "C" fn compact_pke_crs_from_config(
    config: *const Config,
    max_num_bits: usize,
    out_result: *mut *mut CompactPkeCrs,
) -> c_int {
    crate::c_api::utils::catch_panic(|| {
        let config = get_ref_checked(config).unwrap();

        let crs = crate::core_crypto::entities::CompactPkeCrs::from_config(config.0, max_num_bits)
            .unwrap();

        *out_result = Box::into_raw(Box::new(CompactPkeCrs(crs)));
    })
}

#[no_mangle]
pub unsafe extern "C" fn compact_pke_crs_public_params(
    crs: *const CompactPkeCrs,
    out_public_params: *mut *mut CompactPkePublicParams,
) -> c_int {
    crate::c_api::utils::catch_panic(|| {
        let crs = get_ref_checked(crs).unwrap();

        *out_public_params = Box::into_raw(Box::new(CompactPkePublicParams(
            crs.0.public_params().clone(),
        )));
    })
}
