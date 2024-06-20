use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::packed_integers::PackedIntegers;
use crate::core_crypto::prelude::UnsignedInteger;

#[derive(VersionsDispatch)]
pub enum PackedIntegersVersions<Scalar: UnsignedInteger> {
    V0(PackedIntegers<Scalar>),
}
