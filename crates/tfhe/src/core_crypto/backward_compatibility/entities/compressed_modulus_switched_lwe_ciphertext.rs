use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::compressed_modulus_switched_lwe_ciphertext::CompressedModulusSwitchedLweCiphertext;
use crate::core_crypto::prelude::packed_integers::PackedIntegers;
use crate::core_crypto::prelude::{
    CiphertextModulus, CiphertextModulusLog, LweDimension, UnsignedInteger,
};

#[derive(Version)]
pub struct CompressedModulusSwitchedLweCiphertextV0<Scalar: UnsignedInteger> {
    packed_coeffs: Vec<Scalar>,
    lwe_dimension: LweDimension,
    log_modulus: CiphertextModulusLog,
    uncompressed_ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger> Upgrade<CompressedModulusSwitchedLweCiphertext<Scalar>>
    for CompressedModulusSwitchedLweCiphertextV0<Scalar>
{
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedModulusSwitchedLweCiphertext<Scalar>, Self::Error> {
        let packed_integers = PackedIntegers {
            packed_coeffs: self.packed_coeffs,
            log_modulus: self.log_modulus,
            initial_len: self.lwe_dimension.to_lwe_size().0,
        };

        Ok(CompressedModulusSwitchedLweCiphertext {
            packed_integers,
            lwe_dimension: self.lwe_dimension,
            uncompressed_ciphertext_modulus: self.uncompressed_ciphertext_modulus,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedLweCiphertextVersions<Scalar: UnsignedInteger> {
    V0(CompressedModulusSwitchedLweCiphertextV0<Scalar>),
    V1(CompressedModulusSwitchedLweCiphertext<Scalar>),
}
