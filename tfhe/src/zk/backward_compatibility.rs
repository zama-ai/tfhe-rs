use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};
use tfhe_zk_pok::backward_compatibility::pke::ProofV0;
use tfhe_zk_pok::backward_compatibility::{IncompleteProof, SerializablePKEv1PublicParamsV0};
use tfhe_zk_pok::proofs::pke::Proof;
use tfhe_zk_pok::serialization::InvalidSerializedPublicParamsError;

type Curve = tfhe_zk_pok::curve_api::Bls12_446;

use super::{
    CompactPkeCrs, CompactPkeProof, CompressedCompactPkeCrs, SerializableCompactPkePublicParams,
};

#[derive(Version)]
#[repr(transparent)]
pub struct CompactPkeCrsV0(SerializablePKEv1PublicParamsV0);

impl Upgrade<CompactPkeCrs> for CompactPkeCrsV0 {
    type Error = InvalidSerializedPublicParamsError;

    fn upgrade(self) -> Result<CompactPkeCrs, Self::Error> {
        Ok(CompactPkeCrs::PkeV1(
            self.0
                .upgrade()
                .unwrap() // update is infallible so it is ok to unwrap
                .try_into()?,
        ))
    }
}

#[derive(VersionsDispatch)]
#[allow(clippy::large_enum_variant)]
pub enum CompactPkeCrsVersions {
    V0(CompactPkeCrsV0),
    V1(CompactPkeCrs),
}

#[derive(Version)]
#[repr(transparent)]
pub struct CompressedCompactPkeCrsV0(SerializableCompactPkePublicParams);

impl Upgrade<CompressedCompactPkeCrs> for CompressedCompactPkeCrsV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCompactPkeCrs, Self::Error> {
        Ok(CompressedCompactPkeCrs::PkeV1(self.0))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedCompactPkeCrsVersions {
    V0(CompressedCompactPkeCrsV0),
    V1(CompressedCompactPkeCrs),
}

#[derive(Version)]
#[repr(transparent)]
pub struct CompactPkeProofV0(ProofV0<Curve>);

impl Upgrade<CompactPkeProofV1> for CompactPkeProofV0 {
    type Error = IncompleteProof;

    fn upgrade(self) -> Result<CompactPkeProofV1, Self::Error> {
        Ok(CompactPkeProofV1(self.0.upgrade()?))
    }
}

#[derive(Version)]
#[repr(transparent)]
pub struct CompactPkeProofV1(Proof<Curve>);

impl Upgrade<CompactPkeProof> for CompactPkeProofV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompactPkeProof, Self::Error> {
        Ok(CompactPkeProof::PkeV1(self.0))
    }
}

#[derive(VersionsDispatch)]
#[allow(clippy::large_enum_variant)]
pub enum CompactPkeProofVersions {
    V0(CompactPkeProofV0),
    V1(CompactPkeProofV1),
    V2(CompactPkeProof),
}
