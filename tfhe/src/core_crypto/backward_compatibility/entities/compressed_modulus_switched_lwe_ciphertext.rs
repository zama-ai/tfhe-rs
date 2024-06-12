use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::compressed_modulus_switched_lwe_ciphertext::CompressedModulusSwitchedLweCiphertext;
use crate::core_crypto::prelude::UnsignedInteger;

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedLweCiphertextVersions<Scalar: UnsignedInteger> {
    V0(CompressedModulusSwitchedLweCiphertext<Scalar>),
}
