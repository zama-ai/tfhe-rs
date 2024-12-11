use tfhe_versionable::VersionsDispatch;

use crate::prelude::packed_integers::PackedIntegers;
use crate::prelude::UnsignedInteger;

#[derive(VersionsDispatch)]
pub enum PackedIntegersVersions<Scalar: UnsignedInteger> {
    V0(PackedIntegers<Scalar>),
}
