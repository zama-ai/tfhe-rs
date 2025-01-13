// to follow the notation of the paper
#![allow(non_snake_case)]

pub mod pke;
pub mod pke_v2;

use std::convert::Infallible;
use std::error::Error;
use std::fmt::Display;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::curve_api::Curve;
use crate::four_squares::sqr;
use crate::proofs::pke_v2::Bound;
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
pub(crate) enum GroupElementsVersions<G: Curve> {
    #[allow(dead_code)]
    V0(GroupElements<G>),
}

#[derive(VersionsDispatch)]
pub(crate) enum SerializableGroupElementsVersions {
    #[allow(dead_code)]
    V0(SerializableGroupElements),
}

#[derive(Version)]
pub struct SerializablePKEv2PublicParamsV0 {
    pub(crate) g_lists: SerializableGroupElements,
    pub(crate) D: usize,
    pub n: usize,
    pub d: usize,
    pub k: usize,
    pub B: u64,
    pub B_r: u64,
    pub B_bound: u64,
    pub m_bound: usize,
    pub q: u64,
    pub t: u64,
    pub msbs_zero_padding_bit_count: u64,
    // We use Vec<u8> since serde does not support fixed size arrays of 256 elements
    pub(crate) hash: Vec<u8>,
    pub(crate) hash_R: Vec<u8>,
    pub(crate) hash_t: Vec<u8>,
    pub(crate) hash_w: Vec<u8>,
    pub(crate) hash_agg: Vec<u8>,
    pub(crate) hash_lmap: Vec<u8>,
    pub(crate) hash_phi: Vec<u8>,
    pub(crate) hash_xi: Vec<u8>,
    pub(crate) hash_z: Vec<u8>,
    pub(crate) hash_chi: Vec<u8>,
}

impl Upgrade<SerializablePKEv2PublicParams> for SerializablePKEv2PublicParamsV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<SerializablePKEv2PublicParams, Self::Error> {
        let slack_factor = (self.d + self.k).isqrt() as u64;
        let B_inf = self.B / slack_factor;
        Ok(SerializablePKEv2PublicParams {
            g_lists: self.g_lists,
            D: self.D,
            n: self.n,
            d: self.d,
            k: self.k,
            B_bound_squared: sqr(self.B_bound),
            B_inf,
            q: self.q,
            t: self.t,
            msbs_zero_padding_bit_count: self.msbs_zero_padding_bit_count,
            bound_type: Bound::CS,
            hash: self.hash,
            hash_R: self.hash_R,
            hash_t: self.hash_t,
            hash_w: self.hash_w,
            hash_agg: self.hash_agg,
            hash_lmap: self.hash_lmap,
            hash_phi: self.hash_phi,
            hash_xi: self.hash_xi,
            hash_z: self.hash_z,
            hash_chi: self.hash_chi,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum SerializablePKEv2PublicParamsVersions {
    V0(SerializablePKEv2PublicParams),
}

#[derive(VersionsDispatch)]
pub enum SerializablePKEv1PublicParamsVersions {
    V0(SerializablePKEv1PublicParams),
}

#[derive(VersionsDispatch)]
pub enum BoundVersions {
    V0(Bound),
}
