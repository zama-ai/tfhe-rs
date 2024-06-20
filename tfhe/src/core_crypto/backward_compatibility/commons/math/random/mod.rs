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

#[derive(Serialize)]
pub enum CompressionSeedVersioned<'vers> {
    V0(&'vers CompressionSeed),
}

impl<'vers> From<&'vers CompressionSeed> for CompressionSeedVersioned<'vers> {
    fn from(value: &'vers CompressionSeed) -> Self {
        Self::V0(value)
    }
}

#[derive(Serialize, Deserialize)]
pub enum CompressionSeedVersionedOwned {
    V0(CompressionSeed),
}

impl From<CompressionSeed> for CompressionSeedVersionedOwned {
    fn from(value: CompressionSeed) -> Self {
        Self::V0(value)
    }
}

impl From<CompressionSeedVersionedOwned> for CompressionSeed {
    fn from(value: CompressionSeedVersionedOwned) -> Self {
        match value {
            CompressionSeedVersionedOwned::V0(v0) => v0,
        }
    }
}
