use super::utils::*;
use crate::c_api::high_level_api::config::Config;
use crate::c_api::utils::get_ref_checked;
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
impl_serialize_deserialize_on_type!(CompactPkePublicParams);

pub struct CompactPkeCrs(pub(crate) crate::core_crypto::entities::CompactPkeCrs);

impl_destroy_on_type!(CompactPkeCrs);
impl_serialize_deserialize_on_type!(CompactPkeCrs);

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
