use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::NoiseLevel;
use crate::shortint::Ciphertext;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum DegreeVersions {
    V0(Degree),
}

#[derive(VersionsDispatch)]
pub enum NoiseLevelVersions {
    V0(NoiseLevel),
}

#[derive(VersionsDispatch)]
pub enum CiphertextVersions {
    V0(Ciphertext),
}
