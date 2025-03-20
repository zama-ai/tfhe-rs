use crate::integer::noise_squashing::{
    CompressedNoiseSquashingKey, NoiseSquashingKey, NoiseSquashingPrivateKey,
};
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum NoiseSquashingKeyVersions {
    V0(NoiseSquashingKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedNoiseSquashingKeyVersions {
    V0(CompressedNoiseSquashingKey),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingPrivateKeyVersions {
    V0(NoiseSquashingPrivateKey),
}
