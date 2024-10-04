pub mod pke;
pub mod pke_v2;

use std::error::Error;
use std::fmt::Display;

use tfhe_versionable::VersionsDispatch;

use crate::curve_api::Curve;
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

/// The proof was missing some elements
#[derive(Debug)]
pub struct IncompleteProof;

impl Display for IncompleteProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "incomplete serialized ZK proof, missing some pre-computed elements"
        )
    }
}

impl Error for IncompleteProof {}

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
