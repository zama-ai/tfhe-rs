use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::packed_integers::PackedIntegers;
use crate::core_crypto::prelude::{
    CastFrom, CastInto, CiphertextModulus, CompressedModulusSwitchedMultiBitLweCiphertext,
    LweBskGroupingFactor, LweDimension, UnsignedInteger,
};

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

impl<Scalar> Upgrade<CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>>
    for CompressedModulusSwitchedMultiBitLweCiphertextV0<Scalar>
where
    Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>,
{
    type Error = Infallible;

    fn upgrade(
        self,
    ) -> Result<CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>, Self::Error> {
        let mask: Vec<_> = self
            .packed_mask
            .unpack()
            .map(|value| value.cast_into())
            .collect();
        let diffs_opt: Option<(Vec<_>, _)> = self.packed_diffs.map(|diffs| {
            (
                diffs.unpack().map(|value| value.cast_into()).collect(),
                diffs.log_modulus(),
            )
        });
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
    V1(CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>),
}
