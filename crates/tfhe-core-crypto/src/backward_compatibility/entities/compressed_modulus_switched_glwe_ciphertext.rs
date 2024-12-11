use tfhe_versionable::VersionsDispatch;

use crate::prelude::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::prelude::UnsignedInteger;

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedGlweCiphertextVersions<Scalar: UnsignedInteger> {
    V0(CompressedModulusSwitchedGlweCiphertext<Scalar>),
}
