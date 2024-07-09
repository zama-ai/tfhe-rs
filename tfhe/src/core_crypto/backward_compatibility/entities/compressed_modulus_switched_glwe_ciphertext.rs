use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::core_crypto::prelude::UnsignedInteger;

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedGlweCiphertextVersions<Scalar: UnsignedInteger> {
    V0(CompressedModulusSwitchedGlweCiphertext<Scalar>),
}
