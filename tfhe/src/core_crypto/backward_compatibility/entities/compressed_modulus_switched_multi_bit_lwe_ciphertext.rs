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
    Upgrade<CompressedModulusSwitchedMultiBitLweCiphertextV1<Scalar>>
    for CompressedModulusSwitchedMultiBitLweCiphertextV0<Scalar>
{
    type Error = Infallible;

    fn upgrade(
        self,
    ) -> Result<CompressedModulusSwitchedMultiBitLweCiphertextV1<Scalar>, Self::Error> {
        // In the previous version a last coefficient for the body was stored along the mask
        // elements. This was a duplicate, so we remove it.

        let mask_without_body = PackedIntegers::from_raw_parts(
            self.packed_mask.packed_coeffs()[..self.lwe_dimension.0].to_vec(),
            self.packed_mask.log_modulus(),
            self.packed_mask.initial_len(),
        );
        Ok(CompressedModulusSwitchedMultiBitLweCiphertextV1 {
            body: self.body,
            packed_mask: mask_without_body,
            packed_diffs: self.packed_diffs,
            lwe_dimension: self.lwe_dimension,
            uncompressed_ciphertext_modulus: self.uncompressed_ciphertext_modulus,
            grouping_factor: self.grouping_factor,
        })
    }
}

#[derive(Version)]
pub struct CompressedModulusSwitchedMultiBitLweCiphertextV1<
    Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>,
> {
    body: usize,
    packed_mask: PackedIntegers<usize>,
    packed_diffs: Option<PackedIntegers<usize>>,
    lwe_dimension: LweDimension,
    uncompressed_ciphertext_modulus: CiphertextModulus<Scalar>,
    grouping_factor: LweBskGroupingFactor,
}

impl<Scalar> Upgrade<CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>>
    for CompressedModulusSwitchedMultiBitLweCiphertextV1<Scalar>
where
    Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>,
{
    type Error = Infallible;

    // Previous versions were stored as usize, we upgrade to the PackingScalar by
    // unpacking/repacking
    fn upgrade(
        self,
    ) -> Result<CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>, Self::Error> {
        let mask: Vec<_> = self.packed_mask.unpack::<Scalar>().collect();
        let diffs_opt: Option<(Vec<_>, _)> = self
            .packed_diffs
            .map(|diffs| (diffs.unpack::<Scalar>().collect(), diffs.log_modulus()));
        Ok(
            CompressedModulusSwitchedMultiBitLweCiphertext::from_raw_parts(
                self.body.cast_into(),
                PackedIntegers::pack(&mask, self.packed_mask.log_modulus()),
                diffs_opt.map(|(diffs, log_modulus)| PackedIntegers::pack(&diffs, log_modulus)),
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
    V1(CompressedModulusSwitchedMultiBitLweCiphertextV1<Scalar>),
    V2(CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>),
}
