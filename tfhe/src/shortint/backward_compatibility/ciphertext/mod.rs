use crate::shortint::ciphertext::*;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum MaxNoiseLevelVersions {
    V0(MaxNoiseLevel),
}

#[derive(VersionsDispatch)]
pub enum NoiseLevelVersions {
    V0(NoiseLevel),
}

#[derive(VersionsDispatch)]
pub enum MaxDegreeVersions {
    V0(MaxDegree),
}

#[derive(VersionsDispatch)]
pub enum DegreeVersions {
    V0(Degree),
}

#[derive(VersionsDispatch)]
pub enum CiphertextVersions {
    V0(Ciphertext),
}
