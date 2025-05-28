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

impl<Scalar: UnsignedInteger> Upgrade<CompressedModulusSwitchedLweCiphertextV1<Scalar>>
    for CompressedModulusSwitchedLweCiphertextV0<Scalar>
{
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedModulusSwitchedLweCiphertextV1<Scalar>, Self::Error> {
        let packed_integers = PackedIntegers::from_raw_parts(
            self.packed_coeffs,
            self.log_modulus,
            self.lwe_dimension.to_lwe_size().0,
        );

        Ok(CompressedModulusSwitchedLweCiphertextV1 {
            packed_integers,
            lwe_dimension: self.lwe_dimension,
            uncompressed_ciphertext_modulus: self.uncompressed_ciphertext_modulus,
        })
    }
}

#[derive(Version)]
pub struct CompressedModulusSwitchedLweCiphertextV1<Scalar: UnsignedInteger> {
    packed_integers: PackedIntegers<Scalar>,
    lwe_dimension: LweDimension,
    uncompressed_ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger> Upgrade<CompressedModulusSwitchedLweCiphertext<Scalar>>
    for CompressedModulusSwitchedLweCiphertextV1<Scalar>
{
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedModulusSwitchedLweCiphertext<Scalar>, Self::Error> {
        let Self {
            packed_integers,
            lwe_dimension,
            uncompressed_ciphertext_modulus: _,
        } = self;

        Ok(CompressedModulusSwitchedLweCiphertext::from_raw_parts(
            packed_integers,
            lwe_dimension,
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedLweCiphertextVersions<Scalar: UnsignedInteger> {
    V0(CompressedModulusSwitchedLweCiphertextV0<Scalar>),
    V1(CompressedModulusSwitchedLweCiphertextV1<Scalar>),
    V2(CompressedModulusSwitchedLweCiphertext<Scalar>),
}
