use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::commons::math::random::*;
use crate::core_crypto::prelude::{FloatingPoint, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum TUniformVersions<T: UnsignedInteger> {
    V0(TUniform<T>),
}

#[derive(VersionsDispatch)]
pub enum GaussianVersions<T: FloatingPoint> {
    V0(Gaussian<T>),
}

#[derive(VersionsDispatch)]
pub enum DynamicDistributionVersions<T: UnsignedInteger> {
    V0(DynamicDistribution<T>),
}
