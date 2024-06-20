use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{
    CastFrom, CastInto, CompressedModulusSwitchedMultiBitLweCiphertext, UnsignedInteger,
};

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedMultiBitLweCiphertextVersions<
    Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>,
> {
    V0(CompressedModulusSwitchedMultiBitLweCiphertext<Scalar>),
}
