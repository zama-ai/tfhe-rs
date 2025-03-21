use crate::shortint::noise_squashing::{
    CompressedNoiseSquashingKey, NoiseSquashingKey, NoiseSquashingPrivateKey,
};
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum NoiseSquashingPrivateKeyVersions {
    V0(NoiseSquashingPrivateKey),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingKeyVersions {
    V0(NoiseSquashingKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedNoiseSquashingKeyVersions {
    V0(CompressedNoiseSquashingKey),
}
