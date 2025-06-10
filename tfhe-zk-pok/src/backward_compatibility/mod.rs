// to follow the notation of the paper
#![allow(non_snake_case)]

pub mod pke;
pub mod pke_v2;

use std::convert::Infallible;
use std::error::Error;
use std::fmt::Display;

use sha3::digest::{ExtendableOutput, Update};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::curve_api::Curve;
use crate::proofs::pke_v2::Bound;
use crate::proofs::GroupElements;
use crate::serialization::*;

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
    g_lists: SerializableGroupElements,
    D: usize,
    n: usize,
    d: usize,
    k: usize,
    B_bound_squared: u128,
    B_inf: u64,
    q: u64,
    t: u64,
    msbs_zero_padding_bit_count: u64,
    bound_type: Bound,
    // We use Vec<u8> since serde does not support fixed size arrays of 256 elements
    hash: Vec<u8>,
    hash_R: Vec<u8>,
    hash_t: Vec<u8>,
    hash_w: Vec<u8>,
    hash_agg: Vec<u8>,
    hash_lmap: Vec<u8>,
    hash_phi: Vec<u8>,
    hash_xi: Vec<u8>,
    hash_z: Vec<u8>,
    hash_chi: Vec<u8>,
}

impl Upgrade<SerializablePKEv2PublicParams> for SerializablePKEv2PublicParamsV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<SerializablePKEv2PublicParams, Self::Error> {
        let domain_separators = SerializablePKEv2DomainSeparatorsV0 {
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
        };

        Ok(SerializablePKEv2PublicParams {
            g_lists: self.g_lists,
            D: self.D,
            n: self.n,
            d: self.d,
            k: self.k,
            B_bound_squared: self.B_bound_squared,
            B_inf: self.B_inf,
            q: self.q,
            t: self.t,
            msbs_zero_padding_bit_count: self.msbs_zero_padding_bit_count,
            bound_type: self.bound_type,
            sid: None,
            domain_separators: domain_separators.upgrade().unwrap(), // upgrade is infallible
        })
    }
}

#[derive(VersionsDispatch)]
pub enum SerializablePKEv2PublicParamsVersions {
    V0(SerializablePKEv2PublicParamsV0),
    V1(SerializablePKEv2PublicParams),
}

#[derive(Version)]
pub struct SerializablePKEv2DomainSeparatorsV0 {
    hash: Vec<u8>,
    hash_R: Vec<u8>,
    hash_t: Vec<u8>,
    hash_w: Vec<u8>,
    hash_agg: Vec<u8>,
    hash_lmap: Vec<u8>,
    hash_phi: Vec<u8>,
    hash_xi: Vec<u8>,
    hash_z: Vec<u8>,
    hash_chi: Vec<u8>,
}

impl Upgrade<SerializablePKEv2DomainSeparators> for SerializablePKEv2DomainSeparatorsV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<SerializablePKEv2DomainSeparators, Self::Error> {
        // V0 used an unspecified random for gamma anyways, so we can simply use a random DS.
        // We use Shake256 XoF to get a reproducible value for a given CRS.
        let mut hasher = sha3::Shake256::default();
        for data in &[
            &self.hash,
            &self.hash_t,
            &self.hash_w,
            &self.hash_agg,
            &self.hash_lmap,
            &self.hash_z,
        ] {
            hasher.update(data);
        }

        let len = self.hash.len();
        let mut hash_gamma = vec![0u8; len];
        hasher.finalize_xof_into(&mut hash_gamma);

        Ok(SerializablePKEv2DomainSeparators {
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
            hash_gamma,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum SerializablePKEv2DomainSeparatorsVersions {
    V0(SerializablePKEv2DomainSeparatorsV0),
    V1(SerializablePKEv2DomainSeparators),
}

#[derive(Version)]
pub struct SerializablePKEv1PublicParamsV0 {
    g_lists: SerializableGroupElements,
    big_d: usize,
    n: usize,
    d: usize,
    k: usize,
    b: u64,
    b_r: u64,
    q: u64,
    t: u64,
    msbs_zero_padding_bit_count: u64,
    hash: Vec<u8>,
    hash_t: Vec<u8>,
    hash_agg: Vec<u8>,
    hash_lmap: Vec<u8>,
    hash_z: Vec<u8>,
    hash_w: Vec<u8>,
}

impl Upgrade<SerializablePKEv1PublicParams> for SerializablePKEv1PublicParamsV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<SerializablePKEv1PublicParams, Self::Error> {
        let domain_separators = SerializablePKEv1DomainSeparatorsV0 {
            hash: self.hash,
            hash_t: self.hash_t,
            hash_agg: self.hash_agg,
            hash_lmap: self.hash_lmap,
            hash_w: self.hash_w,
            hash_z: self.hash_z,
        };

        Ok(SerializablePKEv1PublicParams {
            g_lists: self.g_lists,
            big_d: self.big_d,
            n: self.n,
            d: self.d,
            k: self.k,
            b: self.b,
            b_r: self.b_r,
            q: self.q,
            t: self.t,
            msbs_zero_padding_bit_count: self.msbs_zero_padding_bit_count,
            sid: None,
            domain_separators: domain_separators.upgrade().unwrap(), // upgrade is infallible
        })
    }
}

#[derive(VersionsDispatch)]
pub enum SerializablePKEv1PublicParamsVersions {
    V0(SerializablePKEv1PublicParamsV0),
    V1(SerializablePKEv1PublicParams),
}

#[derive(Version)]
pub struct SerializablePKEv1DomainSeparatorsV0 {
    hash: Vec<u8>,
    hash_t: Vec<u8>,
    hash_agg: Vec<u8>,
    hash_lmap: Vec<u8>,
    hash_w: Vec<u8>,
    hash_z: Vec<u8>,
}

impl Upgrade<SerializablePKEv1DomainSeparators> for SerializablePKEv1DomainSeparatorsV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<SerializablePKEv1DomainSeparators, Self::Error> {
        // V0 used an unspecified random for gamma anyways, so we can simply use a random DS.
        // We use Shake256 XoF to get a reproducible value for a given CRS.
        let mut hasher = sha3::Shake256::default();
        for data in &[
            &self.hash,
            &self.hash_t,
            &self.hash_w,
            &self.hash_agg,
            &self.hash_lmap,
            &self.hash_z,
        ] {
            hasher.update(data);
        }

        let len = self.hash.len();
        let mut hash_gamma = vec![0u8; len];
        hasher.finalize_xof_into(&mut hash_gamma);

        Ok(SerializablePKEv1DomainSeparators {
            hash: self.hash,
            hash_t: self.hash_t,
            hash_w: self.hash_w,
            hash_agg: self.hash_agg,
            hash_lmap: self.hash_lmap,
            hash_z: self.hash_z,
            hash_gamma,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum SerializablePKEv1DomainSeparatorsVersions {
    V0(SerializablePKEv1DomainSeparatorsV0),
    V1(SerializablePKEv1DomainSeparators),
}

#[derive(VersionsDispatch)]
pub enum BoundVersions {
    V0(Bound),
}
