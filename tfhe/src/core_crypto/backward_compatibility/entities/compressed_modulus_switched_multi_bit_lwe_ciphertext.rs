use std::convert::Infallible;

use packed_integers::PackedIntegers;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::*;

#[derive(Version)]
pub struct CompressedModulusSwitchedMultiBitLweCiphertextV0<
    Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>,
> {
    body: usize,
    packed_mask: PackedIntegers<usize>,
    packed_diffs: Option<PackedIntegers<usize>>,
    lwe_dimension: LweDimension,
    uncompressed_ciphertext_modulus: CiphertextModulus<Scalar>,
    grouping_factor: LweBskGroupingFactor,
}

impl<Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>>
    Upgrade<CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>>
    for CompressedModulusSwitchedMultiBitLweCiphertextV0<Scalar>
{
    type Error = Infallible;

    fn upgrade(
        self,
    ) -> Result<CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>, Self::Error> {
        // In the previous version a last coefficient for the body was stored along the mask
        // elements. This was a duplicate, so we remove it.

        let mask_without_body = PackedIntegers::from_raw_parts(
            self.packed_mask.packed_coeffs()[..self.lwe_dimension.0].to_vec(),
            self.packed_mask.log_modulus(),
            self.packed_mask.initial_len(),
        );
        Ok(
            CompressedModulusSwitchedMultiBitLweCiphertext::from_raw_parts(
                self.body,
                mask_without_body,
                self.packed_diffs,
                self.lwe_dimension,
                self.uncompressed_ciphertext_modulus,
                self.grouping_factor,
            ),
        )
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedMultiBitLweCiphertextVersions<
    Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>,
> {
    V0(CompressedModulusSwitchedMultiBitLweCiphertextV0<Scalar>),
    V1(CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>),
}
