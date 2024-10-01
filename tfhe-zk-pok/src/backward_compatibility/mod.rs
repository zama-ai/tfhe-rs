use tfhe_versionable::VersionsDispatch;

use crate::curve_api::{Compressible, Curve};
use crate::proofs::pke::{CompressedProof as PKEv1CompressedProof, Proof as PKEv1Proof};
use crate::proofs::pke_v2::{CompressedProof as PKEv2CompressedProof, Proof as PKEv2Proof};
use crate::proofs::GroupElements;
use crate::serialization::{
    SerializableAffine, SerializableCubicExtField, SerializableFp, SerializableFp2,
    SerializableFp6, SerializableGroupElements, SerializablePKEv1PublicParams,
    SerializablePKEv2PublicParams, SerializableQuadExtField,
};

#[derive(VersionsDispatch)]
pub enum SerializableAffineVersions<F> {
    V0(SerializableAffine<F>),
}

#[derive(VersionsDispatch)]
pub enum SerializableFpVersions {
    V0(SerializableFp),
}

#[derive(VersionsDispatch)]
pub enum SerializableQuadExtFieldVersions<F> {
    V0(SerializableQuadExtField<F>),
}

#[derive(VersionsDispatch)]
pub enum SerializableCubicExtFieldVersions<F> {
    V0(SerializableCubicExtField<F>),
}

pub type SerializableG1AffineVersions = SerializableAffineVersions<SerializableFp>;
pub type SerializableG2AffineVersions = SerializableAffineVersions<SerializableFp2>;
pub type SerializableFp12Versions = SerializableQuadExtFieldVersions<SerializableFp6>;

#[derive(VersionsDispatch)]
pub enum PKEv1ProofVersions<G: Curve> {
    V0(PKEv1Proof<G>),
}

#[derive(VersionsDispatch)]
pub enum PKEv2ProofVersions<G: Curve> {
    V0(PKEv2Proof<G>),
}

#[derive(VersionsDispatch)]
pub enum PKEv1CompressedProofVersions<G: Curve>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    V0(PKEv1CompressedProof<G>),
}

#[derive(VersionsDispatch)]
pub enum PKEv2CompressedProofVersions<G: Curve>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    V0(PKEv2CompressedProof<G>),
}

#[derive(VersionsDispatch)]
#[allow(dead_code)]
pub(crate) enum GroupElementsVersions<G: Curve> {
    V0(GroupElements<G>),
}

#[derive(VersionsDispatch)]
#[allow(dead_code)]
pub(crate) enum SerializableGroupElementsVersions {
    V0(SerializableGroupElements),
}

#[derive(VersionsDispatch)]
pub enum SerializablePKEv2PublicParamsVersions {
    V0(SerializablePKEv2PublicParams),
}

#[derive(VersionsDispatch)]
pub enum SerializablePKEv1PublicParamsVersions {
    V0(SerializablePKEv1PublicParams),
}
