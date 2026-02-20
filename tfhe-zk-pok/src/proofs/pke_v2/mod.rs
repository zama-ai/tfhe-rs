// to follow the notation of the paper
#![allow(non_snake_case)]

#[cfg(feature = "gpu-experimental")]
pub mod gpu;

use super::*;
use crate::backward_compatibility::pke_v2::*;
use crate::backward_compatibility::BoundVersions;
use crate::curve_api::{CompressedG1, CompressedG2, FieldOps};
use crate::four_squares::*;
use crate::serialization::{
    InvalidSerializedAffineError, InvalidSerializedPublicParamsError, SerializableGroupElements,
    SerializablePKEv2PublicParams,
};

use core::marker::PhantomData;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

pub(crate) mod hashes;

use hashes::RHash;

pub use hashes::*;

pub(crate) fn bit_iter(x: u64, nbits: u32) -> impl Iterator<Item = bool> {
    (0..nbits).map(move |idx| ((x >> idx) & 1) != 0)
}

/// The CRS of the zk scheme
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[serde(
    try_from = "SerializablePKEv2PublicParams",
    into = "SerializablePKEv2PublicParams",
    bound(
        deserialize = "PublicParams<G>: TryFrom<SerializablePKEv2PublicParams, Error = InvalidSerializedPublicParamsError>",
        serialize = "PublicParams<G>: Into<SerializablePKEv2PublicParams>"
    )
)]
#[versionize(try_convert = SerializablePKEv2PublicParams)]
pub struct PublicParams<G: Curve> {
    pub(crate) g_lists: GroupElements<G>,
    pub(crate) D: usize,
    pub n: usize,
    pub d: usize,
    pub k: usize,
    // We store the square of the bound to avoid rounding on sqrt operations
    pub B_bound_squared: u128,
    pub B_inf: u64,
    pub q: u64,
    pub t: u64,
    pub msbs_zero_padding_bit_count: u64,
    pub bound_type: Bound,
    pub(crate) sid: Sid,
    pub(crate) domain_separators: PKEv2DomainSeparators,
}

#[derive(Clone, Debug)]
pub(crate) enum PKEv2DomainSeparators {
    Legacy(Box<LegacyPKEv2DomainSeparators>),
    Short(ShortPKEv2DomainSeparators),
}

impl PKEv2DomainSeparators {
    pub(crate) fn new(rng: &mut dyn RngCore) -> Self {
        let ds = ShortPKEv2DomainSeparators {
            hash: core::array::from_fn(|_| rng.gen()),
            hash_R: core::array::from_fn(|_| rng.gen()),
            hash_t: core::array::from_fn(|_| rng.gen()),
            hash_w: core::array::from_fn(|_| rng.gen()),
            hash_agg: core::array::from_fn(|_| rng.gen()),
            hash_lmap: core::array::from_fn(|_| rng.gen()),
            hash_phi: core::array::from_fn(|_| rng.gen()),
            hash_xi: core::array::from_fn(|_| rng.gen()),
            hash_z: core::array::from_fn(|_| rng.gen()),
            hash_chi: core::array::from_fn(|_| rng.gen()),
            hash_gamma: core::array::from_fn(|_| rng.gen()),
        };

        Self::Short(ds)
    }

    pub(crate) fn hash(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash,
            PKEv2DomainSeparators::Short(ds) => &ds.hash,
        }
    }

    pub(crate) fn hash_R(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash_R,
            PKEv2DomainSeparators::Short(ds) => &ds.hash_R,
        }
    }

    pub(crate) fn hash_t(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash_t,
            PKEv2DomainSeparators::Short(ds) => &ds.hash_t,
        }
    }

    pub(crate) fn hash_w(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash_w,
            PKEv2DomainSeparators::Short(ds) => &ds.hash_w,
        }
    }

    pub(crate) fn hash_agg(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash_agg,
            PKEv2DomainSeparators::Short(ds) => &ds.hash_agg,
        }
    }

    pub(crate) fn hash_lmap(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash_lmap,
            PKEv2DomainSeparators::Short(ds) => &ds.hash_lmap,
        }
    }

    pub(crate) fn hash_phi(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash_phi,
            PKEv2DomainSeparators::Short(ds) => &ds.hash_phi,
        }
    }

    pub(crate) fn hash_xi(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash_xi,
            PKEv2DomainSeparators::Short(ds) => &ds.hash_xi,
        }
    }

    pub(crate) fn hash_z(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash_z,
            PKEv2DomainSeparators::Short(ds) => &ds.hash_z,
        }
    }

    pub(crate) fn hash_chi(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash_chi,
            PKEv2DomainSeparators::Short(ds) => &ds.hash_chi,
        }
    }

    pub(crate) fn hash_gamma(&self) -> &[u8] {
        match self {
            PKEv2DomainSeparators::Legacy(ds) => &ds.hash_gamma,
            PKEv2DomainSeparators::Short(ds) => &ds.hash_gamma,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LegacyPKEv2DomainSeparators {
    pub(crate) hash: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_R: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_t: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_w: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_agg: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_lmap: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_phi: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_xi: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_z: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_chi: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_gamma: [u8; LEGACY_HASH_DS_LEN_BYTES],
}

#[derive(Clone, Debug)]
pub struct ShortPKEv2DomainSeparators {
    pub(crate) hash: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_R: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_t: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_w: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_agg: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_lmap: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_phi: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_xi: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_z: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_chi: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_gamma: [u8; HASH_DS_LEN_BYTES],
}

impl<G: Curve> Compressible for PublicParams<G>
where
    GroupElements<G>: Compressible<
        Compressed = SerializableGroupElements,
        UncompressError = InvalidSerializedGroupElementsError,
    >,
{
    type Compressed = SerializablePKEv2PublicParams;

    type UncompressError = InvalidSerializedPublicParamsError;

    fn compress(&self) -> Self::Compressed {
        let PublicParams {
            g_lists,
            D,
            n,
            d,
            k,
            B_bound_squared,
            B_inf,
            q,
            t,
            msbs_zero_padding_bit_count,
            bound_type,
            sid,
            domain_separators,
        } = self;
        SerializablePKEv2PublicParams {
            g_lists: g_lists.compress(),
            D: *D,
            n: *n,
            d: *d,
            k: *k,
            B_inf: *B_inf,
            B_bound_squared: *B_bound_squared,
            q: *q,
            t: *t,
            msbs_zero_padding_bit_count: *msbs_zero_padding_bit_count,
            bound_type: *bound_type,
            sid: sid.0,
            domain_separators: domain_separators.clone().into(),
        }
    }

    fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
        let SerializablePKEv2PublicParams {
            g_lists,
            D,
            n,
            d,
            k,
            B_bound_squared,
            B_inf,
            q,
            t,
            msbs_zero_padding_bit_count,
            bound_type,
            sid,
            domain_separators,
        } = compressed;

        let uncompressed_g_lists = GroupElements::uncompress(g_lists)?;
        if G::G1::projective(uncompressed_g_lists.g_list[n + 1]) != G::G1::ZERO {
            return Err(InvalidSerializedPublicParamsError::InvalidGroupElements(
                InvalidSerializedGroupElementsError::MissingPuncteredElement,
            ));
        }

        Ok(Self {
            g_lists: uncompressed_g_lists,
            D,
            n,
            d,
            k,
            B_bound_squared,
            B_inf,
            q,
            t,
            msbs_zero_padding_bit_count,
            bound_type,
            sid: Sid(sid),
            domain_separators: domain_separators.try_into()?,
        })
    }
}

impl<G: Curve> PublicParams<G> {
    /// Builds a crs from raw elements. When the elements are received from an untrusted party, the
    /// resulting crs should be validated with [`Self::is_usable`]
    #[allow(clippy::too_many_arguments)]
    pub fn from_vec(
        g_list: Vec<Affine<G::Zp, G::G1>>,
        g_hat_list: Vec<Affine<G::Zp, G::G2>>,
        d: usize,
        k: usize,
        B_inf: u64,
        q: u64,
        t: u64,
        msbs_zero_padding_bit_count: u64,
        bound_type: Bound,
        sid: u128,
        hash: [u8; HASH_DS_LEN_BYTES],
        hash_R: [u8; HASH_DS_LEN_BYTES],
        hash_t: [u8; HASH_DS_LEN_BYTES],
        hash_w: [u8; HASH_DS_LEN_BYTES],
        hash_agg: [u8; HASH_DS_LEN_BYTES],
        hash_lmap: [u8; HASH_DS_LEN_BYTES],
        hash_phi: [u8; HASH_DS_LEN_BYTES],
        hash_xi: [u8; HASH_DS_LEN_BYTES],
        hash_z: [u8; HASH_DS_LEN_BYTES],
        hash_chi: [u8; HASH_DS_LEN_BYTES],
        hash_gamma: [u8; HASH_DS_LEN_BYTES],
    ) -> Self {
        let B_squared = inf_norm_bound_to_euclidean_squared(B_inf, d + k);
        let (n, D, B_bound_squared, _) =
            compute_crs_params(d, k, B_squared, t, msbs_zero_padding_bit_count, bound_type);
        Self {
            g_lists: GroupElements::<G>::from_vec(g_list, g_hat_list),
            D,
            n,
            d,
            k,
            B_bound_squared,
            B_inf,
            q,
            t,
            msbs_zero_padding_bit_count,
            bound_type,
            sid: Sid(Some(sid)),
            domain_separators: PKEv2DomainSeparators::Short(ShortPKEv2DomainSeparators {
                hash,
                hash_R,
                hash_t,
                hash_w,
                hash_agg,
                hash_lmap,
                hash_phi,
                hash_xi,
                hash_z,
                hash_chi,
                hash_gamma,
            }),
        }
    }

    pub fn exclusive_max_noise(&self) -> u64 {
        // Here we return the bound without slack because users aren't supposed to generate noise
        // inside the slack
        self.B_inf + 1
    }

    /// Check if the crs can be used to generate or verify a proof
    ///
    /// This means checking that the points are:
    /// - valid points of the curve
    /// - in the correct subgroup
    /// - the size of the list is correct and the element at index n is 0
    pub fn is_usable(&self) -> bool {
        self.g_lists.is_valid(self.n)
    }
}

/// This represents a proof that the given ciphertext is a valid encryptions of the input messages
/// with the provided public key.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(
    deserialize = "G: Curve, G::G1: serde::Deserialize<'de>, G::G2: serde::Deserialize<'de>",
    serialize = "G: Curve, G::G1: serde::Serialize, G::G2: serde::Serialize"
))]
#[versionize(ProofVersions)]
pub struct Proof<G: Curve> {
    pub(crate) C_hat_e: G::G2,
    pub(crate) C_e: G::G1,
    pub(crate) C_r_tilde: G::G1,
    pub(crate) C_R: G::G1,
    pub(crate) C_hat_bin: G::G2,
    pub(crate) C_y: G::G1,
    pub(crate) C_h1: G::G1,
    pub(crate) C_h2: G::G1,
    pub(crate) C_hat_t: G::G2,
    pub(crate) pi: G::G1,
    pub(crate) pi_kzg: G::G1,
    pub(crate) compute_load_proof_fields: Option<ComputeLoadProofFields<G>>,
    pub(crate) hash_config: PkeV2SupportedHashConfig,
}

impl<G: Curve> Proof<G> {
    /// Check if the proof can be used by the Verifier.
    ///
    /// This means checking that the points in the proof are:
    /// - valid points of the curve
    /// - in the correct subgroup
    pub fn is_usable(&self) -> bool {
        let &Proof {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            ref compute_load_proof_fields,
            hash_config: _,
        } = self;

        C_hat_e.validate_projective()
            && C_e.validate_projective()
            && C_r_tilde.validate_projective()
            && C_R.validate_projective()
            && C_hat_bin.validate_projective()
            && C_y.validate_projective()
            && C_h1.validate_projective()
            && C_h2.validate_projective()
            && C_hat_t.validate_projective()
            && pi.validate_projective()
            && pi_kzg.validate_projective()
            && compute_load_proof_fields.as_ref().is_none_or(
                |&ComputeLoadProofFields { C_hat_h3, C_hat_w }| {
                    C_hat_h3.validate_projective() && C_hat_w.validate_projective()
                },
            )
    }

    pub fn compute_load(&self) -> ComputeLoad {
        match self.compute_load_proof_fields {
            Some(_) => ComputeLoad::Proof,
            None => ComputeLoad::Verify,
        }
    }

    pub fn hash_config(&self) -> PkeV2SupportedHashConfig {
        self.hash_config
    }
}

/// These fields can be pre-computed on the prover side in the faster Verifier scheme. If that's the
/// case, they should be included in the proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(ComputeLoadProofFieldsVersions)]
pub(crate) struct ComputeLoadProofFields<G: Curve> {
    pub(crate) C_hat_h3: G::G2,
    pub(crate) C_hat_w: G::G2,
}

impl<G: Curve> ComputeLoadProofFields<G> {
    pub(crate) fn to_le_bytes(fields: &Option<Self>) -> (Box<[u8]>, Box<[u8]>) {
        if let Some(ComputeLoadProofFields { C_hat_h3, C_hat_w }) = fields.as_ref() {
            (
                Box::from(G::G2::to_le_bytes(*C_hat_h3).as_ref()),
                Box::from(G::G2::to_le_bytes(*C_hat_w).as_ref()),
            )
        } else {
            (Box::from([]), Box::from([]))
        }
    }
}

#[derive(Serialize, Deserialize, Versionize)]
#[serde(bound(
    deserialize = "G: Curve, CompressedG1<G>: serde::Deserialize<'de>, CompressedG2<G>: serde::Deserialize<'de>",
    serialize = "G: Curve, CompressedG1<G>: serde::Serialize, CompressedG2<G>: serde::Serialize"
))]
#[versionize(CompressedProofVersions)]
pub struct CompressedProof<G: Curve>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    pub(crate) C_hat_e: CompressedG2<G>,
    pub(crate) C_e: CompressedG1<G>,
    pub(crate) C_r_tilde: CompressedG1<G>,
    pub(crate) C_R: CompressedG1<G>,
    pub(crate) C_hat_bin: CompressedG2<G>,
    pub(crate) C_y: CompressedG1<G>,
    pub(crate) C_h1: CompressedG1<G>,
    pub(crate) C_h2: CompressedG1<G>,
    pub(crate) C_hat_t: CompressedG2<G>,
    pub(crate) pi: CompressedG1<G>,
    pub(crate) pi_kzg: CompressedG1<G>,
    pub(crate) compute_load_proof_fields: Option<CompressedComputeLoadProofFields<G>>,
    pub(crate) hash_config: PkeV2SupportedHashConfig,
}

#[derive(Serialize, Deserialize, Versionize)]
#[serde(bound(
    deserialize = "G: Curve, CompressedG1<G>: serde::Deserialize<'de>, CompressedG2<G>: serde::Deserialize<'de>",
    serialize = "G: Curve, CompressedG1<G>: serde::Serialize, CompressedG2<G>: serde::Serialize"
))]
#[versionize(CompressedComputeLoadProofFieldsVersions)]
pub(crate) struct CompressedComputeLoadProofFields<G: Curve>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    pub(crate) C_hat_h3: CompressedG2<G>,
    pub(crate) C_hat_w: CompressedG2<G>,
}

impl<G: Curve> Compressible for Proof<G>
where
    G::G1: Compressible<UncompressError = InvalidSerializedAffineError>,
    G::G2: Compressible<UncompressError = InvalidSerializedAffineError>,
{
    type Compressed = CompressedProof<G>;

    type UncompressError = InvalidSerializedAffineError;

    fn compress(&self) -> Self::Compressed {
        let Proof {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            compute_load_proof_fields,
            hash_config,
        } = self;

        CompressedProof {
            C_hat_e: C_hat_e.compress(),
            C_e: C_e.compress(),
            C_r_tilde: C_r_tilde.compress(),
            C_R: C_R.compress(),
            C_hat_bin: C_hat_bin.compress(),
            C_y: C_y.compress(),
            C_h1: C_h1.compress(),
            C_h2: C_h2.compress(),
            C_hat_t: C_hat_t.compress(),
            pi: pi.compress(),
            pi_kzg: pi_kzg.compress(),

            compute_load_proof_fields: compute_load_proof_fields.as_ref().map(
                |ComputeLoadProofFields { C_hat_h3, C_hat_w }| CompressedComputeLoadProofFields {
                    C_hat_h3: C_hat_h3.compress(),
                    C_hat_w: C_hat_w.compress(),
                },
            ),
            hash_config: *hash_config,
        }
    }

    fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
        let CompressedProof {
            C_hat_e,
            C_e,
            C_r_tilde,
            C_R,
            C_hat_bin,
            C_y,
            C_h1,
            C_h2,
            C_hat_t,
            pi,
            pi_kzg,
            compute_load_proof_fields,
            hash_config,
        } = compressed;

        Ok(Proof {
            C_hat_e: G::G2::uncompress(C_hat_e)?,
            C_e: G::G1::uncompress(C_e)?,
            C_r_tilde: G::G1::uncompress(C_r_tilde)?,
            C_R: G::G1::uncompress(C_R)?,
            C_hat_bin: G::G2::uncompress(C_hat_bin)?,
            C_y: G::G1::uncompress(C_y)?,
            C_h1: G::G1::uncompress(C_h1)?,
            C_h2: G::G1::uncompress(C_h2)?,
            C_hat_t: G::G2::uncompress(C_hat_t)?,
            pi: G::G1::uncompress(pi)?,
            pi_kzg: G::G1::uncompress(pi_kzg)?,

            compute_load_proof_fields: if let Some(CompressedComputeLoadProofFields {
                C_hat_h3,
                C_hat_w,
            }) = compute_load_proof_fields
            {
                Some(ComputeLoadProofFields {
                    C_hat_h3: G::G2::uncompress(C_hat_h3)?,
                    C_hat_w: G::G2::uncompress(C_hat_w)?,
                })
            } else {
                None
            },
            hash_config,
        })
    }
}

/// This is the public part of the commitment.
#[derive(Clone, Debug)]
pub struct PublicCommit<G: Curve> {
    /// Mask of the public key
    pub(crate) a: Vec<i64>,
    /// Body of the public key
    pub(crate) b: Vec<i64>,
    /// Mask of the ciphertexts
    pub(crate) c1: Vec<i64>,
    /// Bodies of the ciphertexts
    pub(crate) c2: Vec<i64>,
    __marker: PhantomData<G>,
}

impl<G: Curve> PublicCommit<G> {
    pub fn new(a: Vec<i64>, b: Vec<i64>, c1: Vec<i64>, c2: Vec<i64>) -> Self {
        Self {
            a,
            b,
            c1,
            c2,
            __marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PrivateCommit<G: Curve> {
    /// Public key sampling vector
    pub(crate) r: Vec<i64>,
    /// Error vector associated with the masks
    pub(crate) e1: Vec<i64>,
    /// Input messages
    pub(crate) m: Vec<i64>,
    /// Error vector associated with the bodies
    pub(crate) e2: Vec<i64>,
    __marker: PhantomData<G>,
}

#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(BoundVersions)]
pub enum Bound {
    GHL,
    CS,
}

fn ceil_ilog2(value: u128) -> u64 {
    value.ilog2() as u64 + if value.is_power_of_two() { 0 } else { 1 }
}

pub fn compute_crs_params(
    d: usize,
    k: usize,
    B_squared: u128,
    t: u64,
    msbs_zero_padding_bit_count: u64,
    bound_type: Bound,
) -> (usize, usize, u128, usize) {
    assert!(
        k <= d,
        "Invalid parameters for zk_pok, the maximum number of messages k should be smaller \
than the lwe dimension d. Please pick a smaller k: k = {k}, d = {d}"
    );

    let mut B_bound_squared = {
        (match bound_type {
            // GHL factor is 9.75, 9.75**2 = 95.0625
            // Result is multiplied and divided by 10000 to avoid floating point operations.
            // This could be avoided if one day we need to support bigger params.
            Bound::GHL => 950625,
            Bound::CS => 2 * (d as u128 + k as u128) + 4,
        })
        .checked_mul(B_squared + (sqr((d + 2) as u64) * (d + k) as u128) / 4)
        .unwrap_or_else(|| {
            panic!(
                "Invalid parameters for zk_pok, B_squared: {B_squared}, d: {d}, k: {k}. \
Please select a smaller B, d and/or k"
            )
        })
    };

    if bound_type == Bound::GHL {
        B_bound_squared = B_bound_squared.div_ceil(10000);
    }

    // Formula is round_up(1 + B_bound.ilog2()).
    // Since we use B_bound_square, the log is divided by 2
    let m_bound = 1 + ceil_ilog2(B_bound_squared).div_ceil(2) as usize;

    // m_bound is used to do the bit decomposition of a u64 integer, so we check that it can be
    // safely used for this
    assert!(
        m_bound <= 64,
        "Invalid parameters for zk_pok, we only support 64 bits integer. \
The computed m parameter is {m_bound} > 64. Please select a smaller B, d and/or k"
    );

    // This is also the effective t for encryption
    let effective_t_for_decomposition = t >> msbs_zero_padding_bit_count;

    // formula in Prove_pp: 2.
    let D = d + k * (effective_t_for_decomposition.ilog2() as usize);
    let n = D + 128 * m_bound;

    (n, D, B_bound_squared, m_bound)
}

/// Convert a bound on the infinite norm  of a vector into a bound on the square of the euclidean
/// norm.
///
/// Use the relationship: `||x||_2 <= sqrt(dim)*||x||_inf`. Since we are only interested in the
/// squared bound, we avoid the sqrt by returning dim*(||x||_inf)^2.
pub(crate) fn inf_norm_bound_to_euclidean_squared(B_inf: u64, dim: usize) -> u128 {
    let norm_squared = sqr(B_inf);
    norm_squared
        .checked_mul(dim as u128)
        .unwrap_or_else(|| panic!("Invalid parameters for zk_pok, B_inf: {B_inf}, d+k: {dim}"))
}

/// Generates a CRS based on the bound the heuristic provided by the lemma 2 of the paper.
pub fn crs_gen_ghl<G: Curve>(
    d: usize,
    k: usize,
    B_inf: u64,
    q: u64,
    t: u64,
    msbs_zero_padding_bit_count: u64,
    rng: &mut dyn RngCore,
) -> PublicParams<G> {
    let bound_type = Bound::GHL;
    let alpha = G::Zp::rand(rng);
    let B_squared = inf_norm_bound_to_euclidean_squared(B_inf, d + k);
    let (n, D, B_bound_squared, _) =
        compute_crs_params(d, k, B_squared, t, msbs_zero_padding_bit_count, bound_type);
    PublicParams {
        g_lists: GroupElements::<G>::new(n, alpha),
        D,
        n,
        d,
        k,
        B_inf,
        B_bound_squared,
        q,
        t,
        msbs_zero_padding_bit_count,
        bound_type,
        sid: Sid::new(rng),
        domain_separators: PKEv2DomainSeparators::new(rng),
    }
}

/// Generates a CRS based on the Cauchy-Schwartz inequality. This removes the need of a heuristic
/// used by GHL (see section 3.5 of the reference paper), but the bound is less strict.
pub fn crs_gen_cs<G: Curve>(
    d: usize,
    k: usize,
    B_inf: u64,
    q: u64,
    t: u64,
    msbs_zero_padding_bit_count: u64,
    rng: &mut dyn RngCore,
) -> PublicParams<G> {
    let bound_type = Bound::CS;
    let alpha = G::Zp::rand(rng);
    let B_squared = inf_norm_bound_to_euclidean_squared(B_inf, d + k);
    let (n, D, B_bound_squared, _) =
        compute_crs_params(d, k, B_squared, t, msbs_zero_padding_bit_count, bound_type);
    PublicParams {
        g_lists: GroupElements::<G>::new(n, alpha),
        D,
        n,
        d,
        k,
        B_bound_squared,
        B_inf,
        q,
        t,
        msbs_zero_padding_bit_count,
        bound_type,
        sid: Sid::new(rng),
        domain_separators: PKEv2DomainSeparators::new(rng),
    }
}

/// Generates a new CRS. When applied to TFHE, the parameters are mapped like this:
/// - d: lwe_dimension
/// - k: max_num_cleartext
/// - B: noise_bound
/// - q: ciphertext_modulus
/// - t: plaintext_modulus
pub fn crs_gen<G: Curve>(
    d: usize,
    k: usize,
    B: u64,
    q: u64,
    t: u64,
    msbs_zero_padding_bit_count: u64,
    rng: &mut dyn RngCore,
) -> PublicParams<G> {
    crs_gen_cs(d, k, B, q, t, msbs_zero_padding_bit_count, rng)
}

#[allow(clippy::too_many_arguments)]
pub fn commit<G: Curve>(
    a: Vec<i64>,
    b: Vec<i64>,
    c1: Vec<i64>,
    c2: Vec<i64>,
    r: Vec<i64>,
    e1: Vec<i64>,
    m: Vec<i64>,
    e2: Vec<i64>,
    public: &PublicParams<G>,
) -> (PublicCommit<G>, PrivateCommit<G>) {
    let _ = public;
    (
        PublicCommit {
            a,
            b,
            c1,
            c2,
            __marker: PhantomData,
        },
        PrivateCommit {
            r,
            e1,
            m,
            e2,
            __marker: PhantomData,
        },
    )
}

pub fn prove<G: Curve>(
    public: (&PublicParams<G>, &PublicCommit<G>),
    private_commit: &PrivateCommit<G>,
    metadata: &[u8],
    load: ComputeLoad,
    seed: &[u8],
) -> Proof<G> {
    prove_impl(
        public,
        private_commit,
        metadata,
        load,
        seed,
        PkeV2SupportedHashConfig::default(),
        ProofSanityCheckMode::Panic,
    )
}

fn prove_impl<G: Curve>(
    public: (&PublicParams<G>, &PublicCommit<G>),
    private_commit: &PrivateCommit<G>,
    metadata: &[u8],
    load: ComputeLoad,
    seed: &[u8],
    hash_config: PkeV2SupportedHashConfig,
    sanity_check_mode: ProofSanityCheckMode,
) -> Proof<G> {
    _ = load;
    let (
        &PublicParams {
            ref g_lists,
            D: D_max,
            n,
            d,
            k: k_max,
            B_bound_squared,
            B_inf,
            q,
            t: t_input,
            msbs_zero_padding_bit_count,
            bound_type,
            sid: _,
            domain_separators: ref ds,
        },
        PublicCommit { a, b, c1, c2, .. },
    ) = public;
    let stored_hash_config = hash_config;
    let hash_config = hash_config.into();

    let g_list = &*g_lists.g_list.0;
    let g_hat_list = &*g_lists.g_hat_list.0;

    let PrivateCommit { r, e1, m, e2, .. } = private_commit;

    let k = c2.len();

    let effective_cleartext_t = t_input >> msbs_zero_padding_bit_count;

    let decoded_q = decode_q(q);

    // Recompute some params for our case if k is smaller than the k max
    let B_squared = inf_norm_bound_to_euclidean_squared(B_inf, d + k);
    let (_, D, _, m_bound) = compute_crs_params(
        d,
        k,
        B_squared,
        t_input,
        msbs_zero_padding_bit_count,
        bound_type,
    );

    let e_sqr_norm = e1
        .iter()
        .chain(e2)
        .map(|x| sqr(x.unsigned_abs()))
        .sum::<u128>();

    if sanity_check_mode == ProofSanityCheckMode::Panic {
        assert_pke_proof_preconditions(a, b, c1, e1, c2, e2, d, k_max, D, D_max);
        assert!(
            B_squared >= e_sqr_norm,
            "squared norm of error ({e_sqr_norm}) exceeds threshold ({B_squared})",
        );
        assert_eq!(G::G1::projective(g_list[n]), G::G1::ZERO);
    }

    // FIXME: div_round
    let delta = {
        // delta takes the encoding with the padding bit
        (decoded_q / t_input as u128) as u64
    };

    let g = G::G1::GENERATOR;
    let g_hat = G::G2::GENERATOR;
    let mut gamma_list = [G::Zp::ZERO; 6];
    G::Zp::hash(&mut gamma_list, &[ds.hash_gamma(), seed]);
    let [gamma_e, gamma_hat_e, gamma_r, gamma_R, gamma_bin, gamma_y] = gamma_list;

    let r1 = compute_r1(e1, c1, a, r, d, decoded_q);
    let r2 = compute_r2(e2, c2, m, b, r, d, delta, decoded_q);

    let u64 = |x: i64| x as u64;

    let w_tilde = r
        .iter()
        .rev()
        .map(|&r| r != 0)
        .chain(
            m.iter()
                .flat_map(|&m| bit_iter(u64(m), effective_cleartext_t.ilog2())),
        )
        .collect::<Box<[_]>>();

    let v = four_squares(B_squared - e_sqr_norm, sanity_check_mode).map(|v| v as i64);

    let e1_zp = &*e1
        .iter()
        .copied()
        .map(G::Zp::from_i64)
        .collect::<Box<[_]>>();
    let e2_zp = &*e2
        .iter()
        .copied()
        .map(G::Zp::from_i64)
        .collect::<Box<[_]>>();
    let v_zp = v.map(G::Zp::from_i64);

    let r1_zp = &*r1
        .iter()
        .copied()
        .map(G::Zp::from_i64)
        .collect::<Box<[_]>>();
    let r2_zp = &*r2
        .iter()
        .copied()
        .map(G::Zp::from_i64)
        .collect::<Box<[_]>>();

    let scalars_e = e1_zp
        .iter()
        .copied()
        .chain(e2_zp.iter().copied())
        .chain(v_zp)
        .collect::<Box<[_]>>();
    let scalars_e_rev: Box<[_]> = scalars_e.iter().copied().rev().collect();
    let scalars_r: Box<[_]> = r1_zp.iter().chain(r2_zp.iter()).copied().collect();

    let mut C_hat_e = None;
    let mut C_e = None;
    let mut C_r_tilde = None;

    rayon::scope(|s| {
        s.spawn(|_| {
            C_hat_e = Some(
                g_hat.mul_scalar(gamma_hat_e)
                    + G::G2::multi_mul_scalar(&g_hat_list[..d + k + 4], &scalars_e),
            );
        });

        s.spawn(|_| {
            C_e = Some(
                g.mul_scalar(gamma_e)
                    + G::G1::multi_mul_scalar(&g_list[n - (d + k + 4)..n], &scalars_e_rev),
            );
        });

        s.spawn(|_| {
            C_r_tilde =
                Some(g.mul_scalar(gamma_r) + G::G1::multi_mul_scalar(&g_list[..d + k], &scalars_r));
        });
    });

    let C_hat_e = C_hat_e.unwrap();
    let C_e = C_e.unwrap();
    let C_r_tilde = C_r_tilde.unwrap();

    let C_hat_e_bytes = C_hat_e.to_le_bytes();
    let C_e_bytes = C_e.to_le_bytes();
    let C_r_tilde_bytes = C_r_tilde.to_le_bytes();

    let (R, R_hash) = RHash::new(
        public,
        metadata,
        C_hat_e_bytes.as_ref(),
        C_e_bytes.as_ref(),
        C_r_tilde_bytes.as_ref(),
        hash_config,
    );
    let R = |i: usize, j: usize| R[i + j * 128];

    let w_R = (0..128)
        .map(|i| {
            let R = |j| R(i, j);

            let mut acc = 0i128;
            e1.iter()
                .chain(e2)
                .chain(&v)
                .chain(&r1)
                .chain(&r2)
                .copied()
                .enumerate()
                .for_each(|(j, x)| match R(j) {
                    0 => {}
                    1 => acc += x as i128,
                    -1 => acc -= x as i128,
                    _ => unreachable!(),
                });
            if sanity_check_mode == ProofSanityCheckMode::Panic {
                assert!(
                    checked_sqr(acc.unsigned_abs()).unwrap() <= B_bound_squared,
                    "sqr(acc) ({}) > B_bound_squared ({B_bound_squared})",
                    checked_sqr(acc.unsigned_abs()).unwrap()
                );
            }
            acc as i64
        })
        .collect::<Box<[_]>>();

    let C_R = g.mul_scalar(gamma_R)
        + G::G1::multi_mul_scalar(
            &g_list[..128],
            &w_R.iter()
                .copied()
                .map(G::Zp::from_i64)
                .collect::<Box<[_]>>(),
        );

    let C_R_bytes = C_R.to_le_bytes();
    let (phi, phi_hash) = R_hash.gen_phi(C_R_bytes.as_ref());

    let m = m_bound;

    let w_R_bin = w_R
        .iter()
        .flat_map(|&x| bit_iter(x as u64, m as u32))
        .collect::<Box<[_]>>();
    let w_bin = w_tilde
        .iter()
        .copied()
        .chain(w_R_bin.iter().copied())
        .collect::<Box<[_]>>();

    let C_hat_bin = g_hat.mul_scalar(gamma_bin)
        + g_hat_list
            .iter()
            .zip(&*w_bin)
            .filter(|&(_, &w)| w)
            .map(|(&x, _)| x)
            .map(G::G2::projective)
            .sum::<G::G2>();

    let C_hat_bin_bytes = C_hat_bin.to_le_bytes();
    let (xi, xi_hash) = phi_hash.gen_xi::<G::Zp>(C_hat_bin_bytes.as_ref());

    let (y, y_hash) = xi_hash.gen_y();

    if sanity_check_mode == ProofSanityCheckMode::Panic {
        assert_eq!(y.len(), w_bin.len());
    }
    let scalars = y
        .iter()
        .zip(w_bin.iter())
        .rev()
        .map(|(&y, &w)| if w { y } else { G::Zp::ZERO })
        .collect::<Box<[_]>>();
    let C_y =
        g.mul_scalar(gamma_y) + G::G1::multi_mul_scalar(&g_list[n - (D + 128 * m)..n], &scalars);

    let C_y_bytes = C_y.to_le_bytes();
    let (t, t_hash) = y_hash.gen_t(C_y_bytes.as_ref());

    let (theta, theta_hash) = t_hash.gen_theta();

    let mut a_theta = vec![G::Zp::ZERO; D];
    compute_a_theta::<G>(
        &mut a_theta,
        &theta,
        a,
        d,
        k,
        b,
        effective_cleartext_t,
        delta,
    );

    let t_theta = theta
        .iter()
        .copied()
        .zip(c1.iter().chain(c2.iter()).copied().map(G::Zp::from_i64))
        .map(|(x, y)| x * y)
        .sum::<G::Zp>();

    let (omega, omega_hash) = theta_hash.gen_omega();

    let (delta, delta_hash) = omega_hash.gen_delta::<G::Zp>();
    let [delta_r, delta_dec, delta_eq, delta_y, delta_theta, delta_e, delta_l] = delta;

    // Precompute xi powers to enable parallel polynomial construction
    let xi_powers = precompute_xi_powers(&xi, m);
    let delta_theta_q = delta_theta * G::Zp::from_u128(decoded_q);

    // Build all polynomial pairs in parallel
    let mut poly_0_lhs = None;
    let mut poly_0_rhs = None;
    let mut poly_1_lhs = None;
    let mut poly_1_rhs = None;
    let mut poly_2_lhs = None;
    let mut poly_2_rhs = None;
    let mut poly_3_lhs = None;
    let mut poly_3_rhs = None;
    let mut poly_4_lhs = None;
    let mut poly_4_rhs = None;
    let mut poly_5_lhs = None;
    let mut poly_5_rhs = None;

    rayon::scope(|s| {
        s.spawn(|_| {
            let mut lhs = vec![G::Zp::ZERO; 1 + n];
            let mut rhs = vec![G::Zp::ZERO; 1 + D + 128 * m];

            lhs[0] = delta_y * gamma_y;
            for j in 0..D + 128 * m {
                let p = &mut lhs[n - j];

                if !w_bin[j] {
                    *p -= delta_y * y[j];
                }

                if j < D {
                    *p += delta_theta * a_theta[j];
                }
                *p += delta_eq * t[j] * y[j];

                if j >= D {
                    let j_inner = j - D;
                    let r = delta_dec * xi_powers[j_inner];

                    if j_inner % m < m - 1 {
                        *p += r;
                    } else {
                        *p -= r;
                    }
                }
            }

            rhs[0] = gamma_bin;
            for j in 0..D + 128 * m {
                let p = &mut rhs[j + 1];

                if w_bin[j] {
                    *p = G::Zp::ONE;
                }
            }

            poly_0_lhs = Some(lhs);
            poly_0_rhs = Some(rhs);
        });

        s.spawn(|_| {
            let mut lhs = vec![G::Zp::ZERO; 1 + n];
            let mut rhs = vec![G::Zp::ZERO; 1 + d + k + 4];

            lhs[0] = delta_l * gamma_e;
            for j in 0..d {
                let p = &mut lhs[n - j];
                *p = delta_l * e1_zp[j];
            }
            for j in 0..k {
                let p = &mut lhs[n - (d + j)];
                *p = delta_l * e2_zp[j];
            }
            for j in 0..4 {
                let p = &mut lhs[n - (d + k + j)];
                *p = delta_l * v_zp[j];
            }

            for j in 0..n {
                let p = &mut lhs[n - j];
                let mut acc = delta_e * omega[j];
                if j < d + k {
                    acc += delta_theta * theta[j];
                }

                if j < d + k + 4 {
                    let mut acc2 = G::Zp::ZERO;
                    for (i, &phi_val) in phi.iter().enumerate() {
                        match R(i, j) {
                            0 => {}
                            1 => acc2 += phi_val,
                            -1 => acc2 -= phi_val,
                            _ => unreachable!(),
                        }
                    }
                    acc += delta_r * acc2;
                }
                *p += acc;
            }

            rhs[0] = gamma_hat_e;
            for j in 0..d {
                let p = &mut rhs[1 + j];
                *p = e1_zp[j];
            }
            for j in 0..k {
                let p = &mut rhs[1 + (d + j)];
                *p = e2_zp[j];
            }
            for j in 0..4 {
                let p = &mut rhs[1 + (d + k + j)];
                *p = v_zp[j];
            }

            poly_1_lhs = Some(lhs);
            poly_1_rhs = Some(rhs);
        });

        s.spawn(|_| {
            let mut lhs = vec![G::Zp::ZERO; 1 + d + k];
            let mut rhs = vec![G::Zp::ZERO; 1 + n];

            lhs[0] = gamma_r;
            for j in 0..d {
                let p = &mut lhs[1 + j];
                *p = r1_zp[j];
            }
            for j in 0..k {
                let p = &mut lhs[1 + (d + j)];
                *p = r2_zp[j];
            }

            for j in 0..d + k {
                let p = &mut rhs[n - j];

                let mut acc = G::Zp::ZERO;
                for (i, &phi_val) in phi.iter().enumerate() {
                    match R(i, d + k + 4 + j) {
                        0 => {}
                        1 => acc += phi_val,
                        -1 => acc -= phi_val,
                        _ => unreachable!(),
                    }
                }
                *p = delta_r * acc - delta_theta_q * theta[j];
            }

            poly_2_lhs = Some(lhs);
            poly_2_rhs = Some(rhs);
        });

        s.spawn(|_| {
            let mut lhs = vec![G::Zp::ZERO; 1 + 128];
            let mut rhs = vec![G::Zp::ZERO; 1 + n];

            lhs[0] = gamma_R;
            for j in 0..128 {
                let p = &mut lhs[1 + j];
                *p = G::Zp::from_i64(w_R[j]);
            }

            for j in 0..128 {
                let p = &mut rhs[n - j];
                *p = delta_r * phi[j] + delta_dec * xi_powers[j * m];
            }

            poly_3_lhs = Some(lhs);
            poly_3_rhs = Some(rhs);
        });

        s.spawn(|_| {
            let mut lhs = vec![G::Zp::ZERO; 1 + n];
            let mut rhs = vec![G::Zp::ZERO; 1 + d + k + 4];

            lhs[0] = delta_e * gamma_e;
            for j in 0..d {
                let p = &mut lhs[n - j];
                *p = delta_e * e1_zp[j];
            }
            for j in 0..k {
                let p = &mut lhs[n - (d + j)];
                *p = delta_e * e2_zp[j];
            }
            for j in 0..4 {
                let p = &mut lhs[n - (d + k + j)];
                *p = delta_e * v_zp[j];
            }

            for j in 0..d + k + 4 {
                let p = &mut rhs[1 + j];
                *p = omega[j];
            }

            poly_4_lhs = Some(lhs);
            poly_4_rhs = Some(rhs);
        });

        s.spawn(|_| {
            let mut lhs = vec![G::Zp::ZERO; 1 + n];
            let mut rhs = vec![G::Zp::ZERO; 1 + n];

            lhs[0] = delta_eq * gamma_y;
            for j in 0..D + 128 * m {
                let p = &mut lhs[n - j];

                if w_bin[j] {
                    *p = delta_eq * y[j];
                }
            }

            for j in 0..n {
                let p = &mut rhs[1 + j];
                *p = t[j];
            }

            poly_5_lhs = Some(lhs);
            poly_5_rhs = Some(rhs);
        });
    });

    let poly_0_lhs = poly_0_lhs.unwrap();
    let poly_0_rhs = poly_0_rhs.unwrap();
    let poly_1_lhs = poly_1_lhs.unwrap();
    let poly_1_rhs = poly_1_rhs.unwrap();
    let poly_2_lhs = poly_2_lhs.unwrap();
    let poly_2_rhs = poly_2_rhs.unwrap();
    let poly_3_lhs = poly_3_lhs.unwrap();
    let poly_3_rhs = poly_3_rhs.unwrap();
    let poly_4_lhs = poly_4_lhs.unwrap();
    let poly_4_rhs = poly_4_rhs.unwrap();
    let poly_5_lhs = poly_5_lhs.unwrap();
    let poly_5_rhs = poly_5_rhs.unwrap();

    let poly = [
        (&poly_0_lhs, &poly_0_rhs),
        (&poly_1_lhs, &poly_1_rhs),
        (&poly_2_lhs, &poly_2_rhs),
        (&poly_3_lhs, &poly_3_rhs),
        (&poly_4_lhs, &poly_4_rhs),
        (&poly_5_lhs, &poly_5_rhs),
    ];

    let [mut poly_0, poly_1, poly_2, poly_3, poly_4, poly_5] = {
        let tmp: Box<[Vec<G::Zp>; 6]> = poly
            .into_par_iter()
            .map(|(lhs, rhs)| G::Zp::poly_mul(lhs, rhs))
            .collect::<Box<[_]>>()
            .try_into()
            .unwrap();
        *tmp
    };

    let len = [
        poly_0.len(),
        poly_1.len(),
        poly_2.len(),
        poly_3.len(),
        poly_4.len(),
        poly_5.len(),
    ]
    .into_iter()
    .max()
    .unwrap();

    poly_0.resize(len, G::Zp::ZERO);

    {
        let chunk_size = len.div_ceil(rayon::current_num_threads());

        poly_0
            .par_chunks_mut(chunk_size)
            .enumerate()
            .for_each(|(j, p0)| {
                let offset = j * chunk_size;
                let p1 = poly_1.get(offset..).unwrap_or(&[]);
                let p2 = poly_2.get(offset..).unwrap_or(&[]);
                let p3 = poly_3.get(offset..).unwrap_or(&[]);
                let p4 = poly_4.get(offset..).unwrap_or(&[]);
                let p5 = poly_5.get(offset..).unwrap_or(&[]);

                for (j, p0) in p0.iter_mut().enumerate() {
                    if j < p1.len() {
                        *p0 += p1[j];
                    }
                    if j < p2.len() {
                        *p0 += p2[j];
                    }
                    if j < p3.len() {
                        *p0 -= p3[j];
                    }
                    if j < p4.len() {
                        *p0 -= p4[j];
                    }
                    if j < p5.len() {
                        *p0 -= p5[j];
                    }
                }
            });
    }
    let mut P_pi = poly_0;
    if P_pi.len() > n + 1 {
        P_pi[n + 1] -= delta_theta * t_theta + delta_l * G::Zp::from_u128(B_squared);
    }

    // Parallelize pi, C_h1, C_h2, compute_load_proof_fields, and C_hat_t computations
    let mut pi = None;
    let mut C_h1 = None;
    let mut C_h2 = None;
    let mut compute_load_proof_fields = None;
    let mut C_hat_t = None;

    rayon::scope(|s| {
        s.spawn(|_| {
            pi = Some(if P_pi.is_empty() {
                G::G1::ZERO
            } else {
                g.mul_scalar(P_pi[0])
                    + G::G1::multi_mul_scalar(&g_list[..P_pi.len() - 1], &P_pi[1..])
            });
        });

        s.spawn(|_| {
            let scalars_h1: Box<[_]> = (0..D + 128 * m)
                .rev()
                .map(|j| {
                    let mut acc = G::Zp::ZERO;
                    if j < D {
                        acc += delta_theta * a_theta[j];
                    }
                    acc -= delta_y * y[j];
                    acc += delta_eq * t[j] * y[j];

                    if j >= D {
                        let j_inner = j - D;
                        let r = delta_dec * xi_powers[j_inner];

                        if j_inner % m < m - 1 {
                            acc += r;
                        } else {
                            acc -= r;
                        }
                    }

                    acc
                })
                .collect();
            C_h1 = Some(G::G1::multi_mul_scalar(
                &g_list[n - (D + 128 * m)..n],
                &scalars_h1,
            ));
        });

        s.spawn(|_| {
            let scalars_h2: Box<[_]> = (0..n)
                .rev()
                .map(|j| {
                    let mut acc = G::Zp::ZERO;
                    if j < d + k {
                        acc += delta_theta * theta[j];
                    }

                    acc += delta_e * omega[j];

                    if j < d + k + 4 {
                        let mut acc2 = G::Zp::ZERO;
                        for (i, &phi_val) in phi.iter().enumerate() {
                            match R(i, j) {
                                0 => {}
                                1 => acc2 += phi_val,
                                -1 => acc2 -= phi_val,
                                _ => unreachable!(),
                            }
                        }
                        acc += delta_r * acc2;
                    }
                    acc
                })
                .collect();
            C_h2 = Some(G::G1::multi_mul_scalar(&g_list[..n], &scalars_h2));
        });

        s.spawn(|_| {
            compute_load_proof_fields = Some(match load {
                ComputeLoad::Proof => {
                    let mut C_hat_h3 = None;
                    let mut C_hat_w = None;

                    rayon::scope(|s_inner| {
                        s_inner.spawn(|_| {
                            C_hat_h3 = Some(G::G2::multi_mul_scalar(
                                &g_hat_list[n - (d + k)..n],
                                &(0..d + k)
                                    .rev()
                                    .map(|j| {
                                        let mut acc = G::Zp::ZERO;
                                        for (i, &phi_val) in phi.iter().enumerate() {
                                            match R(i, d + k + 4 + j) {
                                                0 => {}
                                                1 => acc += phi_val,
                                                -1 => acc -= phi_val,
                                                _ => unreachable!(),
                                            }
                                        }
                                        delta_r * acc - delta_theta_q * theta[j]
                                    })
                                    .collect::<Box<[_]>>(),
                            ));
                        });

                        s_inner.spawn(|_| {
                            C_hat_w = Some(G::G2::multi_mul_scalar(
                                &g_hat_list[..d + k + 4],
                                &omega[..d + k + 4],
                            ));
                        });
                    });

                    Some(ComputeLoadProofFields {
                        C_hat_h3: C_hat_h3.unwrap(),
                        C_hat_w: C_hat_w.unwrap(),
                    })
                }
                ComputeLoad::Verify => None,
            });
        });

        s.spawn(|_| {
            C_hat_t = Some(G::G2::multi_mul_scalar(g_hat_list, &t));
        });
    });

    let pi = pi.unwrap();
    let C_h1 = C_h1.unwrap();
    let C_h2 = C_h2.unwrap();
    let compute_load_proof_fields = compute_load_proof_fields.unwrap();
    let C_hat_t = C_hat_t.unwrap();

    let (C_hat_h3_bytes, C_hat_w_bytes) =
        ComputeLoadProofFields::to_le_bytes(&compute_load_proof_fields);

    let C_h1_bytes = C_h1.to_le_bytes();
    let C_h2_bytes = C_h2.to_le_bytes();
    let C_hat_t_bytes = C_hat_t.to_le_bytes();

    let (z, z_hash) = delta_hash.gen_z(
        C_h1_bytes.as_ref(),
        C_h2_bytes.as_ref(),
        C_hat_t_bytes.as_ref(),
        &C_hat_h3_bytes,
        &C_hat_w_bytes,
    );

    // Compute P_t and P_omega inline (too cheap to justify a rayon task)
    let P_t = {
        let mut poly = vec![G::Zp::ZERO; 1 + n];
        poly[1..].copy_from_slice(&t);
        poly
    };
    let P_omega = match load {
        ComputeLoad::Proof => {
            let mut poly = vec![G::Zp::ZERO; 1 + d + k + 4];
            poly[1..].copy_from_slice(&omega[..d + k + 4]);
            poly
        }
        ComputeLoad::Verify => vec![],
    };

    // Build P_h1, P_h2, P_h3 in parallel
    let mut P_h1 = None;
    let mut P_h2 = None;
    let mut P_h3 = None;

    rayon::scope(|s| {
        s.spawn(|_| {
            let mut poly = vec![G::Zp::ZERO; 1 + n];
            for j in 0..D + 128 * m {
                let p = &mut poly[n - j];
                if j < D {
                    *p += delta_theta * a_theta[j];
                }
                *p -= delta_y * y[j];
                *p += delta_eq * t[j] * y[j];

                if j >= D {
                    let j_inner = j - D;
                    let r = delta_dec * xi_powers[j_inner];

                    if j_inner % m < m - 1 {
                        *p += r;
                    } else {
                        *p -= r;
                    }
                }
            }
            P_h1 = Some(poly);
        });

        s.spawn(|_| {
            let mut poly = vec![G::Zp::ZERO; 1 + n];
            for j in 0..n {
                let p = &mut poly[n - j];

                if j < d + k {
                    *p += delta_theta * theta[j];
                }

                *p += delta_e * omega[j];

                if j < d + k + 4 {
                    let mut acc = G::Zp::ZERO;
                    for (i, &phi_val) in phi.iter().enumerate() {
                        match R(i, j) {
                            0 => {}
                            1 => acc += phi_val,
                            -1 => acc -= phi_val,
                            _ => unreachable!(),
                        }
                    }
                    *p += delta_r * acc;
                }
            }
            P_h2 = Some(poly);
        });

        s.spawn(|_| {
            P_h3 = Some(match load {
                ComputeLoad::Proof => {
                    let mut poly = vec![G::Zp::ZERO; 1 + n];
                    for j in 0..d + k {
                        let p = &mut poly[n - j];

                        let mut acc = G::Zp::ZERO;
                        for (i, &phi_val) in phi.iter().enumerate() {
                            match R(i, d + k + 4 + j) {
                                0 => {}
                                1 => acc += phi_val,
                                -1 => acc -= phi_val,
                                _ => unreachable!(),
                            }
                        }
                        *p = delta_r * acc - delta_theta_q * theta[j];
                    }
                    poly
                }
                ComputeLoad::Verify => vec![],
            });
        });
    });

    let P_h1 = P_h1.unwrap();
    let P_h2 = P_h2.unwrap();
    let P_h3 = P_h3.unwrap();

    // Precompute powers of z for parallel polynomial evaluation
    let z_powers: Box<[_]> = {
        let mut powers = Vec::with_capacity(n + 1);
        let mut pow = G::Zp::ONE;
        for _ in 0..n + 1 {
            powers.push(pow);
            pow = pow * z;
        }
        powers.into_boxed_slice()
    };

    // Evaluate polynomials at z in parallel
    let mut p_h1 = None;
    let mut p_h2 = None;
    let mut p_t = None;
    let mut p_h3 = None;
    let mut p_omega = None;

    rayon::scope(|s| {
        s.spawn(|_| {
            p_h1 = Some(
                P_h1.iter()
                    .zip(z_powers.iter())
                    .map(|(&p, &pow)| p * pow)
                    .sum::<G::Zp>(),
            );
        });

        s.spawn(|_| {
            p_h2 = Some(
                P_h2.iter()
                    .zip(z_powers.iter())
                    .map(|(&p, &pow)| p * pow)
                    .sum::<G::Zp>(),
            );
        });

        s.spawn(|_| {
            p_t = Some(
                P_t.iter()
                    .zip(z_powers.iter())
                    .map(|(&p, &pow)| p * pow)
                    .sum::<G::Zp>(),
            );
        });

        s.spawn(|_| {
            p_h3 = Some(if P_h3.is_empty() {
                G::Zp::ZERO
            } else {
                P_h3.iter()
                    .zip(z_powers.iter())
                    .map(|(&p, &pow)| p * pow)
                    .sum::<G::Zp>()
            });
        });

        s.spawn(|_| {
            p_omega = Some(if P_omega.is_empty() {
                G::Zp::ZERO
            } else {
                P_omega
                    .iter()
                    .zip(z_powers.iter())
                    .map(|(&p, &pow)| p * pow)
                    .sum::<G::Zp>()
            });
        });
    });

    let p_h1 = p_h1.unwrap();
    let p_h2 = p_h2.unwrap();
    let p_t = p_t.unwrap();
    let p_h3 = p_h3.unwrap();
    let p_omega = p_omega.unwrap();

    let p_h3_opt = if P_h3.is_empty() { None } else { Some(p_h3) };
    let p_omega_opt = if P_omega.is_empty() {
        None
    } else {
        Some(p_omega)
    };

    let chi = z_hash.gen_chi(p_h1, p_h2, p_t, p_h3_opt, p_omega_opt);

    let mut Q_kzg = vec![G::Zp::ZERO; 1 + n];
    let chi2 = chi * chi;
    let chi3 = chi2 * chi;
    let chi4 = chi3 * chi;
    for j in 1..n + 1 {
        Q_kzg[j] = P_h1[j] + chi * P_h2[j] + chi2 * P_t[j];
        if j < P_h3.len() {
            Q_kzg[j] += chi3 * P_h3[j];
        }
        if j < P_omega.len() {
            Q_kzg[j] += chi4 * P_omega[j];
        }
    }
    Q_kzg[0] -= p_h1 + chi * p_h2 + chi2 * p_t + chi3 * p_h3 + chi4 * p_omega;

    // https://en.wikipedia.org/wiki/Polynomial_long_division#Pseudocode
    let mut q = vec![G::Zp::ZERO; n];
    for j in (0..n).rev() {
        Q_kzg[j] = Q_kzg[j] + z * Q_kzg[j + 1];
        q[j] = Q_kzg[j + 1];
        Q_kzg[j + 1] = G::Zp::ZERO;
    }

    let pi_kzg = g.mul_scalar(q[0]) + G::G1::multi_mul_scalar(&g_list[..n - 1], &q[1..n]);

    Proof {
        C_hat_e,
        C_e,
        C_r_tilde,
        C_R,
        C_hat_bin,
        C_y,
        C_h1,
        C_h2,
        C_hat_t,
        pi,
        pi_kzg,
        compute_load_proof_fields,
        hash_config: stored_hash_config,
    }
}

/// Precompute xi powers: for each index j in 0..128*m, compute 2^(j % m) * xi[j / m]
/// This replaces the sequential accumulator pattern that mutates xi_scaled.
fn precompute_xi_powers<Zp: FieldOps>(xi: &[Zp; 128], m: usize) -> Box<[Zp]> {
    let mut result = Vec::with_capacity(128 * m);
    for &xi_val in xi {
        let mut power = xi_val;
        for _ in 0..m {
            result.push(power);
            power = power + power;
        }
    }
    result.into_boxed_slice()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_a_theta<G: Curve>(
    a_theta: &mut [G::Zp],
    theta: &[G::Zp],
    a: &[i64],
    d: usize,
    k: usize,
    b: &[i64],
    t: u64,
    delta: u64,
) {
    // a_theta = Ã.T theta
    //  = [
    //    rot(a).T theta1 + phi[d](bar(b)) theta2_1 + ... + phi[d-k+1](bar(b)) theta2_k
    //
    //    delta g[log t].T theta2_1
    //    delta g[log t].T theta2_2
    //    ...
    //    delta g[log t].T theta2_k
    //    ]
    assert_eq!(a.len(), d);
    assert!(theta.len() >= d);

    let theta1 = &theta[..d];
    let theta2 = &theta[d..];

    {
        // rewrite rot(a).T theta1 and rot(b).T theta2.rev() as negacyclic polynomial multiplication
        let a_theta = &mut a_theta[..d];

        let mut a_rev = vec![G::Zp::ZERO; d].into_boxed_slice();
        a_rev[0] = G::Zp::from_i64(a[0]);
        for i in 1..d {
            a_rev[i] = -G::Zp::from_i64(a[d - i]);
        }

        let mut b_rev = vec![G::Zp::ZERO; d].into_boxed_slice();
        b_rev[0] = G::Zp::from_i64(b[0]);
        for i in 1..d {
            b_rev[i] = -G::Zp::from_i64(b[d - i]);
        }

        let theta2_rev = &*(0..d - k)
            .map(|_| G::Zp::ZERO)
            .chain(theta2.iter().copied().rev())
            .collect::<Box<[_]>>();

        // compute full poly mul
        let (a_rev_theta1, b_rev_theta2_rev) = rayon::join(
            || G::Zp::poly_mul(&a_rev, theta1),
            || G::Zp::poly_mul(&b_rev, theta2_rev),
        );

        // make it negacyclic
        let min = usize::min(a_theta.len(), a_rev_theta1.len());
        a_theta[..min].copy_from_slice(&a_rev_theta1[..min]);

        let len = a_theta.len();
        let chunk_size = len.div_ceil(rayon::current_num_threads());
        a_theta
            .par_chunks_mut(chunk_size)
            .enumerate()
            .for_each(|(j, a_theta)| {
                let offset = j * chunk_size;
                let a_rev_theta1 = a_rev_theta1.get(offset..).unwrap_or(&[]);
                let b_rev_theta2_rev = b_rev_theta2_rev.get(offset..).unwrap_or(&[]);

                for (j, a_theta) in a_theta.iter_mut().enumerate() {
                    if j + d < a_rev_theta1.len() {
                        *a_theta -= a_rev_theta1[j + d];
                    }
                    if j < b_rev_theta2_rev.len() {
                        *a_theta += b_rev_theta2_rev[j];
                    }
                    if j + d < b_rev_theta2_rev.len() {
                        *a_theta -= b_rev_theta2_rev[j + d];
                    }
                }
            });
    }

    {
        let a_theta = &mut a_theta[d..];
        let delta = G::Zp::from_u64(delta);
        let step = t.ilog2() as usize;

        a_theta
            .par_chunks_exact_mut(step)
            .zip_eq(theta2)
            .for_each(|(a_theta, &theta)| {
                let mut theta = delta * theta;
                let mut first = true;
                for a_theta in a_theta {
                    if !first {
                        theta = theta + theta;
                    }
                    first = false;
                    *a_theta = theta;
                }
            });
    }
}

/// At the end of the verification, we perform several pairings on computed g1/g2 elements, to
/// derive an equality that should hold if the proof is correct.
///
/// This defines how these pairings should be done. Note that this choice is made by the verifier
/// and will not make any non perf related difference in the verification output.
#[derive(Copy, Clone, Debug, Default)]
pub enum VerificationPairingMode {
    /// Perform the pairings in two steps, resulting in 2 equalities (eq. (50) and (51) of the
    /// reference)
    // On a hpc7, this is measured to be approx. equivalent with compute load verify and slightly
    // slower on compute load proof.
    #[default]
    TwoSteps,
    /// Generate a random scalar and use it to batch the pairings (eq. (52) of the reference)
    Batched,
}

pub(crate) struct GeneratedScalars<G: Curve> {
    pub(crate) phi: [G::Zp; 128],
    pub(crate) xi: [G::Zp; 128],
    pub(crate) theta: Vec<G::Zp>,
    pub(crate) omega: Vec<G::Zp>,
    pub(crate) delta: [G::Zp; 7],
    pub(crate) chi_powers: [G::Zp; 4],
    pub(crate) z: G::Zp,
    pub(crate) t_theta: G::Zp,
}

pub(crate) struct EvaluationPoints<G: Curve> {
    pub(crate) p_h1: G::Zp,
    pub(crate) p_h2: G::Zp,
    pub(crate) p_h3: G::Zp,
    pub(crate) p_t: G::Zp,
    pub(crate) p_omega: G::Zp,
}

#[allow(clippy::result_unit_err)]
pub fn verify<G: Curve + Send + Sync>(
    proof: &Proof<G>,
    public: (&PublicParams<G>, &PublicCommit<G>),
    metadata: &[u8],
    pairing_mode: VerificationPairingMode,
) -> Result<(), ()> {
    // By running it in a limited thread pool, we make sure that the rayon overhead stays minimal
    // compared to the actual verification work
    run_in_pool(|| verify_impl(proof, public, metadata, pairing_mode))
}

#[allow(clippy::result_unit_err)]
pub fn verify_impl<G: Curve>(
    proof: &Proof<G>,
    public: (&PublicParams<G>, &PublicCommit<G>),
    metadata: &[u8],
    pairing_mode: VerificationPairingMode,
) -> Result<(), ()> {
    let &Proof {
        C_hat_e,
        C_e,
        C_r_tilde,
        C_R,
        C_hat_bin,
        C_y,
        C_h1,
        C_h2,
        C_hat_t,
        pi: _,
        pi_kzg: _,
        ref compute_load_proof_fields,
        hash_config,
    } = proof;
    let hash_config = hash_config.into();

    let &PublicParams {
        g_lists: _,
        D: D_max,
        n,
        d,
        k: k_max,
        B_bound_squared: _,
        B_inf,
        q,
        t: t_input,
        msbs_zero_padding_bit_count,
        bound_type,
        sid: _,
        domain_separators: _,
    } = public.0;

    let decoded_q = decode_q(q);

    // FIXME: div_round
    let delta_encoding = {
        // delta takes the encoding with the padding bit
        (decoded_q / t_input as u128) as u64
    };

    let PublicCommit { a, b, c1, c2, .. } = public.1;
    let k = c2.len();
    if k > k_max {
        return Err(());
    }

    if a.len() != d || b.len() != d {
        return Err(());
    }

    let effective_cleartext_t = t_input >> msbs_zero_padding_bit_count;
    let B_squared = inf_norm_bound_to_euclidean_squared(B_inf, d + k);
    let (_, D, _, m_bound) = compute_crs_params(
        d,
        k,
        B_squared,
        t_input,
        msbs_zero_padding_bit_count,
        bound_type,
    );

    let m = m_bound;

    if D > D_max {
        return Err(());
    }

    let C_hat_e_bytes = C_hat_e.to_le_bytes();
    let C_e_bytes = C_e.to_le_bytes();
    let C_r_tilde_bytes = C_r_tilde.to_le_bytes();

    let (R_matrix, R_hash) = RHash::new(
        public,
        metadata,
        C_hat_e_bytes.as_ref(),
        C_e_bytes.as_ref(),
        C_r_tilde_bytes.as_ref(),
        hash_config,
    );
    let R = |i: usize, j: usize| R_matrix[i + j * 128];

    let C_R_bytes = C_R.to_le_bytes();
    let (phi, phi_hash) = R_hash.gen_phi(C_R_bytes.as_ref());

    let C_hat_bin_bytes = C_hat_bin.to_le_bytes();
    let (xi, xi_hash) = phi_hash.gen_xi::<G::Zp>(C_hat_bin_bytes.as_ref());

    let (y, y_hash) = xi_hash.gen_y();

    let C_y_bytes = C_y.to_le_bytes();
    let (t, t_hash) = y_hash.gen_t(C_y_bytes.as_ref());

    let (theta, theta_hash) = t_hash.gen_theta();

    let t_theta = theta
        .iter()
        .copied()
        .zip(c1.iter().chain(c2.iter()).copied().map(G::Zp::from_i64))
        .map(|(x, y)| x * y)
        .sum::<G::Zp>();

    let (omega, omega_hash) = theta_hash.gen_omega();

    let (delta, delta_hash) = omega_hash.gen_delta();
    let [delta_r, delta_dec, delta_eq, delta_y, delta_theta, delta_e, _delta_l] = delta;

    let delta_theta_q = delta_theta * G::Zp::from_u128(decoded_q);

    let mut a_theta = vec![G::Zp::ZERO; D];
    compute_a_theta::<G>(
        &mut a_theta,
        &theta,
        a,
        d,
        k,
        b,
        effective_cleartext_t,
        delta_encoding,
    );

    let load = if compute_load_proof_fields.is_some() {
        ComputeLoad::Proof
    } else {
        ComputeLoad::Verify
    };

    let (C_hat_h3_bytes, C_hat_w_bytes) =
        ComputeLoadProofFields::to_le_bytes(compute_load_proof_fields);

    let C_h1_bytes = C_h1.to_le_bytes();
    let C_h2_bytes = C_h2.to_le_bytes();
    let C_hat_t_bytes = C_hat_t.to_le_bytes();

    let (z, z_hash) = delta_hash.gen_z(
        C_h1_bytes.as_ref(),
        C_h2_bytes.as_ref(),
        C_hat_t_bytes.as_ref(),
        &C_hat_h3_bytes,
        &C_hat_w_bytes,
    );

    let mut P_h1 = vec![G::Zp::ZERO; 1 + n];
    let mut P_h2 = vec![G::Zp::ZERO; 1 + n];
    let mut P_t = vec![G::Zp::ZERO; 1 + n];
    let mut P_h3 = match load {
        ComputeLoad::Proof => vec![G::Zp::ZERO; 1 + n],
        ComputeLoad::Verify => vec![],
    };
    let mut P_omega = match load {
        ComputeLoad::Proof => vec![G::Zp::ZERO; 1 + d + k + 4],
        ComputeLoad::Verify => vec![],
    };

    let mut xi_scaled = xi;
    for j in 0..D + 128 * m {
        let p = &mut P_h1[n - j];
        if j < D {
            *p += delta_theta * a_theta[j];
        }
        *p -= delta_y * y[j];
        *p += delta_eq * t[j] * y[j];

        if j >= D {
            let j = j - D;
            let xi = &mut xi_scaled[j / m];
            let H_xi = *xi;
            *xi = *xi + *xi;

            let r = delta_dec * H_xi;

            if j % m < m - 1 {
                *p += r;
            } else {
                *p -= r;
            }
        }
    }

    for j in 0..n {
        let p = &mut P_h2[n - j];

        if j < d + k {
            *p += delta_theta * theta[j];
        }

        *p += delta_e * omega[j];

        if j < d + k + 4 {
            let mut acc = G::Zp::ZERO;
            for (i, &phi) in phi.iter().enumerate() {
                match R(i, j) {
                    0 => {}
                    1 => acc += phi,
                    -1 => acc -= phi,
                    _ => unreachable!(),
                }
            }
            *p += delta_r * acc;
        }
    }

    P_t[1..].copy_from_slice(&t);

    if !P_h3.is_empty() {
        for j in 0..d + k {
            let p = &mut P_h3[n - j];

            let mut acc = G::Zp::ZERO;
            for (i, &phi) in phi.iter().enumerate() {
                match R(i, d + k + 4 + j) {
                    0 => {}
                    1 => acc += phi,
                    -1 => acc -= phi,
                    _ => unreachable!(),
                }
            }
            *p = delta_r * acc - delta_theta_q * theta[j];
        }
    }

    if !P_omega.is_empty() {
        P_omega[1..].copy_from_slice(&omega[..d + k + 4]);
    }

    let mut p_h1 = G::Zp::ZERO;
    let mut p_h2 = G::Zp::ZERO;
    let mut p_t = G::Zp::ZERO;
    let mut p_h3 = G::Zp::ZERO;
    let mut p_omega = G::Zp::ZERO;

    let mut pow = G::Zp::ONE;
    for j in 0..n + 1 {
        p_h1 += P_h1[j] * pow;
        p_h2 += P_h2[j] * pow;
        p_t += P_t[j] * pow;

        if j < P_h3.len() {
            p_h3 += P_h3[j] * pow;
        }
        if j < P_omega.len() {
            p_omega += P_omega[j] * pow;
        }

        pow = pow * z;
    }

    let p_h3_opt = if P_h3.is_empty() { None } else { Some(p_h3) };
    let p_omega_opt = if P_omega.is_empty() {
        None
    } else {
        Some(p_omega)
    };

    let chi = z_hash.gen_chi(p_h1, p_h2, p_t, p_h3_opt, p_omega_opt);

    // Compared to the reference document, chi2 and chi3 are reversed in compute load proof, that
    // way the equation are not modified between compute load proof/verify. This is ok as long as
    // chi2 and chi3 are reversed everywhere.
    let chi2 = chi * chi;
    let chi3 = chi2 * chi;
    let chi4 = chi3 * chi;

    let scalars = GeneratedScalars {
        phi,
        xi,
        theta,
        omega,
        delta,
        chi_powers: [chi, chi2, chi3, chi4],
        z,
        t_theta,
    };

    let eval_points = EvaluationPoints {
        p_h1,
        p_h2,
        p_h3,
        p_t,
        p_omega,
    };

    match pairing_mode {
        VerificationPairingMode::TwoSteps => pairing_check_two_steps(
            proof,
            &public.0.g_lists,
            n,
            d,
            B_squared,
            decoded_q,
            k,
            R,
            scalars,
            eval_points,
        ),
        VerificationPairingMode::Batched => pairing_check_batched(
            proof,
            &public.0.g_lists,
            n,
            d,
            B_squared,
            decoded_q,
            k,
            R,
            scalars,
            eval_points,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn pairing_check_two_steps<G: Curve>(
    proof: &Proof<G>,
    g_lists: &GroupElements<G>,
    n: usize,
    d: usize,
    B_squared: u128,
    decoded_q: u128,
    k: usize,
    R: impl Fn(usize, usize) -> i8 + Sync,
    scalars: GeneratedScalars<G>,
    eval_points: EvaluationPoints<G>,
) -> Result<(), ()> {
    let &Proof {
        C_hat_e,
        C_e,
        C_r_tilde,
        C_R,
        C_hat_bin,
        C_y,
        C_h1,
        C_h2,
        C_hat_t,
        pi,
        pi_kzg,
        ref compute_load_proof_fields,
        hash_config: _,
    } = proof;

    let GeneratedScalars {
        phi,
        xi,
        theta,
        omega,
        delta,
        chi_powers: [chi, chi2, chi3, chi4],
        z,
        t_theta,
    } = scalars;

    let EvaluationPoints {
        p_h1,
        p_h2,
        p_h3,
        p_t,
        p_omega,
    } = eval_points;

    let g_list = &*g_lists.g_list.0;
    let g_hat_list = &*g_lists.g_hat_list.0;

    let [delta_r, delta_dec, delta_eq, delta_y, delta_theta, delta_e, delta_l] = delta;

    let delta_theta_q = delta_theta * G::Zp::from_u128(decoded_q);

    let pairing = G::Gt::pairing;
    let g = G::G1::GENERATOR;
    let g_hat = G::G2::GENERATOR;

    let mut rhs = None;
    let mut lhs0 = None;
    let mut lhs1 = None;
    let mut lhs2 = None;
    let mut lhs3 = None;
    let mut lhs4 = None;
    let mut lhs5 = None;
    let mut lhs6 = None;

    let mut rhs_eq2 = None;
    let mut lhs0_eq2 = None;
    let mut lhs1_eq2 = None;

    rayon::scope(|s| {
        s.spawn(|_| rhs = Some(pairing(pi, g_hat)));
        s.spawn(|_| lhs0 = Some(pairing(C_y.mul_scalar(delta_y) + C_h1, C_hat_bin)));
        s.spawn(|_| lhs1 = Some(pairing(C_e.mul_scalar(delta_l) + C_h2, C_hat_e)));
        s.spawn(|_| {
            lhs2 = Some(pairing(
                C_r_tilde,
                match compute_load_proof_fields.as_ref() {
                    Some(&ComputeLoadProofFields {
                        C_hat_h3,
                        C_hat_w: _,
                    }) => C_hat_h3,
                    None => G::G2::multi_mul_scalar(
                        &g_hat_list[n - (d + k)..n],
                        &(0..d + k)
                            .rev()
                            .map(|j| {
                                let mut acc = G::Zp::ZERO;
                                for (i, &phi) in phi.iter().enumerate() {
                                    match R(i, d + k + 4 + j) {
                                        0 => {}
                                        1 => acc += phi,
                                        -1 => acc -= phi,
                                        _ => unreachable!(),
                                    }
                                }
                                delta_r * acc - delta_theta_q * theta[j]
                            })
                            .collect::<Box<[_]>>(),
                    ),
                },
            ))
        });
        s.spawn(|_| {
            lhs3 = Some(pairing(
                C_R,
                G::G2::multi_mul_scalar(
                    &g_hat_list[n - 128..n],
                    &(0..128)
                        .rev()
                        .map(|j| delta_r * phi[j] + delta_dec * xi[j])
                        .collect::<Box<[_]>>(),
                ),
            ))
        });
        s.spawn(|_| {
            lhs4 = Some(pairing(
                C_e.mul_scalar(delta_e),
                match compute_load_proof_fields.as_ref() {
                    Some(&ComputeLoadProofFields {
                        C_hat_h3: _,
                        C_hat_w,
                    }) => C_hat_w,
                    None => G::G2::multi_mul_scalar(&g_hat_list[..d + k + 4], &omega[..d + k + 4]),
                },
            ))
        });
        s.spawn(|_| lhs5 = Some(pairing(C_y.mul_scalar(delta_eq), C_hat_t)));
        s.spawn(|_| {
            lhs6 = Some(
                pairing(
                    G::G1::projective(g_list[0]),
                    G::G2::projective(g_hat_list[n - 1]),
                )
                .mul_scalar(delta_theta * t_theta + delta_l * G::Zp::from_u128(B_squared)),
            )
        });

        s.spawn(|_| {
            lhs0_eq2 = Some(pairing(
                C_h1 + C_h2.mul_scalar(chi) - g.mul_scalar(p_h1 + chi * p_h2),
                g_hat,
            ));
        });

        s.spawn(|_| {
            lhs1_eq2 = Some(pairing(
                g,
                {
                    let mut C_hat = C_hat_t.mul_scalar(chi2);
                    if let Some(ComputeLoadProofFields { C_hat_h3, C_hat_w }) =
                        compute_load_proof_fields
                    {
                        C_hat += C_hat_h3.mul_scalar(chi3);
                        C_hat += C_hat_w.mul_scalar(chi4);
                    }
                    C_hat
                } - g_hat.mul_scalar(p_t * chi2 + p_h3 * chi3 + p_omega * chi4),
            ));
        });

        s.spawn(|_| {
            rhs_eq2 = Some(pairing(
                pi_kzg,
                G::G2::projective(g_hat_list[0]) - g_hat.mul_scalar(z),
            ))
        });
    });

    let rhs = rhs.unwrap();
    let lhs0 = lhs0.unwrap();
    let lhs1 = lhs1.unwrap();
    let lhs2 = lhs2.unwrap();
    let lhs3 = lhs3.unwrap();
    let lhs4 = lhs4.unwrap();
    let lhs5 = lhs5.unwrap();
    let lhs6 = lhs6.unwrap();

    let lhs = lhs0 + lhs1 + lhs2 - lhs3 - lhs4 - lhs5 - lhs6;

    if lhs != rhs {
        return Err(());
    }

    let rhs = rhs_eq2.unwrap();
    let lhs0 = lhs0_eq2.unwrap();
    let lhs1 = lhs1_eq2.unwrap();
    let lhs = lhs0 + lhs1;

    if lhs != rhs {
        Err(())
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn pairing_check_batched<G: Curve>(
    proof: &Proof<G>,
    g_lists: &GroupElements<G>,
    n: usize,
    d: usize,
    B_squared: u128,
    decoded_q: u128,
    k: usize,
    R: impl Fn(usize, usize) -> i8 + Sync,
    scalars: GeneratedScalars<G>,
    eval_points: EvaluationPoints<G>,
) -> Result<(), ()> {
    let &Proof {
        C_hat_e,
        C_e,
        C_r_tilde,
        C_R,
        C_hat_bin,
        C_y,
        C_h1,
        C_h2,
        C_hat_t,
        pi,
        pi_kzg,
        ref compute_load_proof_fields,
        hash_config: _,
    } = proof;

    let GeneratedScalars {
        phi,
        xi,
        theta,
        omega,
        delta,
        chi_powers: [chi, chi2, chi3, chi4],
        z,
        t_theta,
    } = scalars;

    let EvaluationPoints {
        p_h1,
        p_h2,
        p_h3,
        p_t,
        p_omega,
    } = eval_points;

    let g_list = &*g_lists.g_list.0;
    let g_hat_list = &*g_lists.g_hat_list.0;

    let [delta_r, delta_dec, delta_eq, delta_y, delta_theta, delta_e, delta_l] = delta;

    let delta_theta_q = delta_theta * G::Zp::from_u128(decoded_q);

    let pairing = G::Gt::pairing;
    let g = G::G1::GENERATOR;
    let g_hat = G::G2::GENERATOR;

    let mut rhs = None;
    let mut lhs0 = None;
    let mut lhs1 = None;
    let mut lhs2 = None;
    let mut lhs3 = None;
    let mut lhs4 = None;
    let mut lhs5 = None;
    let mut lhs6 = None;

    // TODO: should the user be able to control the randomness source here?
    let eta = G::Zp::rand(&mut rand::thread_rng());

    rayon::scope(|s| {
        s.spawn(|_| {
            rhs = Some(pairing(
                pi - C_h1.mul_scalar(eta)
                    + g.mul_scalar(
                        eta * (p_h1 + chi * p_h2 + chi3 * p_h3 + chi2 * p_t + chi4 * p_omega),
                    )
                    - C_h2.mul_scalar(chi * eta)
                    - pi_kzg.mul_scalar(z * eta),
                g_hat,
            ))
        });
        s.spawn(|_| lhs0 = Some(pairing(C_y.mul_scalar(delta_y) + C_h1, C_hat_bin)));
        s.spawn(|_| lhs1 = Some(pairing(C_e.mul_scalar(delta_l) + C_h2, C_hat_e)));
        s.spawn(|_| match compute_load_proof_fields.as_ref() {
            Some(&ComputeLoadProofFields {
                C_hat_h3,
                C_hat_w: _,
            }) => lhs2 = Some(pairing(C_r_tilde + g.mul_scalar(eta * chi3), C_hat_h3)),
            None => {
                lhs2 = Some(pairing(
                    C_r_tilde,
                    G::G2::multi_mul_scalar(
                        &g_hat_list[n - (d + k)..n],
                        &(0..d + k)
                            .rev()
                            .map(|j| {
                                let mut acc = G::Zp::ZERO;
                                for (i, &phi) in phi.iter().enumerate() {
                                    match R(i, d + k + 4 + j) {
                                        0 => {}
                                        1 => acc += phi,
                                        -1 => acc -= phi,
                                        _ => unreachable!(),
                                    }
                                }
                                delta_r * acc - delta_theta_q * theta[j]
                            })
                            .collect::<Box<[_]>>(),
                    ),
                ))
            }
        });
        s.spawn(|_| {
            lhs3 = Some(pairing(
                C_R,
                G::G2::multi_mul_scalar(
                    &g_hat_list[n - 128..n],
                    &(0..128)
                        .rev()
                        .map(|j| delta_r * phi[j] + delta_dec * xi[j])
                        .collect::<Box<[_]>>(),
                ),
            ))
        });
        s.spawn(|_| match compute_load_proof_fields.as_ref() {
            Some(&ComputeLoadProofFields {
                C_hat_h3: _,
                C_hat_w,
            }) => {
                lhs4 = Some(pairing(
                    C_e.mul_scalar(delta_e) - g.mul_scalar(eta * chi4),
                    C_hat_w,
                ))
            }
            None => {
                lhs4 = Some(pairing(
                    C_e.mul_scalar(delta_e),
                    G::G2::multi_mul_scalar(&g_hat_list[..d + k + 4], &omega[..d + k + 4]),
                ))
            }
        });
        s.spawn(|_| {
            lhs5 = Some(pairing(
                C_y.mul_scalar(delta_eq) - g.mul_scalar(eta * chi2),
                C_hat_t,
            ))
        });
        s.spawn(|_| {
            lhs6 = Some(pairing(
                -G::G1::projective(g_list[n - 1])
                    .mul_scalar(delta_theta * t_theta + delta_l * G::Zp::from_u128(B_squared))
                    - pi_kzg.mul_scalar(eta),
                G::G2::projective(g_hat_list[0]),
            ))
        });
    });

    let rhs = rhs.unwrap();
    let lhs0 = lhs0.unwrap();
    let lhs1 = lhs1.unwrap();
    let lhs2 = lhs2.unwrap();
    let lhs3 = lhs3.unwrap();
    let lhs4 = lhs4.unwrap();
    let lhs5 = lhs5.unwrap();
    let lhs6 = lhs6.unwrap();

    let lhs = lhs0 + lhs1 + lhs2 - lhs3 - lhs4 - lhs5 + lhs6;

    if lhs != rhs {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::curve_api::{self, bls12_446};

    use super::super::test::*;
    use super::*;
    use rand::rngs::StdRng;
    use rand::{thread_rng, Rng, SeedableRng};
    use tfhe_versionable::Unversionize;

    type Curve = curve_api::Bls12_446;

    /// Compact key params used with pkev2
    pub(crate) const PKEV2_TEST_PARAMS: PkeTestParameters = PkeTestParameters {
        d: 2048,
        k: 320,
        B: 131072, // 2**17
        q: 0,
        t: 32, // 2b msg, 2b carry, 1b padding
        msbs_zero_padding_bit_count: 1,
    };

    /// Compact key params used with pkve2 to encrypt a single message
    pub(super) const PKEV2_TEST_PARAMS_SINGLE: PkeTestParameters = PkeTestParameters {
        d: 2048,
        k: 1,
        B: 131072, // 2**17
        q: 0,
        t: 32, // 2b msg, 2b carry, 1b padding
        msbs_zero_padding_bit_count: 1,
    };

    /// Compact key params with limits values to test that there is no overflow, using a GHL bound
    pub(super) const BIG_TEST_PARAMS_CS: PkeTestParameters = PkeTestParameters {
        d: 2048,
        k: 2048,
        B: 1125899906842624, // 2**50
        q: 0,
        t: 4, // 1b message, 1b padding
        msbs_zero_padding_bit_count: 1,
    };

    /// Compact key params with limits values to test that there is no overflow, using a
    /// Cauchy-Schwarz bound
    pub(super) const BIG_TEST_PARAMS_GHL: PkeTestParameters = PkeTestParameters {
        d: 2048,
        k: 2048,
        B: 281474976710656, // 2**48
        q: 0,
        t: 4, // 1b message, 1b padding
        msbs_zero_padding_bit_count: 1,
    };

    /// Test that the proof is rejected if we use a different value between encryption and proof
    #[test]
    fn test_pke() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

        let seed = thread_rng().gen();
        println!("pkev2 seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV2_TEST_PARAMS);
        let ct = testcase.encrypt(PKEV2_TEST_PARAMS);

        let fake_e1 = (0..d)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();
        let fake_e2 = (0..k)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();

        let fake_r = (0..d)
            .map(|_| (rng.gen::<u64>() % 2) as i64)
            .collect::<Vec<_>>();

        let fake_m = (0..k)
            .map(|_| (rng.gen::<u64>() % effective_cleartext_t) as i64)
            .collect::<Vec<_>>();

        let mut fake_metadata = [255u8; METADATA_LEN];
        fake_metadata.fill_with(|| rng.gen::<u8>());

        // To check management of bigger k_max from CRS during test
        let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

        let original_public_param =
            crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);
        let public_param_that_was_compressed =
            serialize_then_deserialize(&original_public_param, Compress::Yes).unwrap();
        let public_param_that_was_not_compressed =
            serialize_then_deserialize(&original_public_param, Compress::No).unwrap();

        for (
            public_param,
            use_fake_r,
            use_fake_e1,
            use_fake_e2,
            use_fake_m,
            use_fake_metadata_verify,
        ) in itertools::iproduct!(
            [
                original_public_param,
                public_param_that_was_compressed,
                public_param_that_was_not_compressed,
            ],
            [false, true],
            [false, true],
            [false, true],
            [false, true],
            [false, true]
        ) {
            let (public_commit, private_commit) = commit(
                testcase.a.clone(),
                testcase.b.clone(),
                ct.c1.clone(),
                ct.c2.clone(),
                if use_fake_r {
                    fake_r.clone()
                } else {
                    testcase.r.clone()
                },
                if use_fake_e1 {
                    fake_e1.clone()
                } else {
                    testcase.e1.clone()
                },
                if use_fake_m {
                    fake_m.clone()
                } else {
                    testcase.m.clone()
                },
                if use_fake_e2 {
                    fake_e2.clone()
                } else {
                    testcase.e2.clone()
                },
                &public_param,
            );

            for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
                let proof = prove(
                    (&public_param, &public_commit),
                    &private_commit,
                    &testcase.metadata,
                    load,
                    &seed.to_le_bytes(),
                );

                let verify_metadata = if use_fake_metadata_verify {
                    &fake_metadata
                } else {
                    &testcase.metadata
                };

                assert_eq!(
                    verify_all_pairing_modes(
                        &proof,
                        (&public_param, &public_commit),
                        verify_metadata
                    )
                    .is_err(),
                    use_fake_e1
                        || use_fake_e2
                        || use_fake_r
                        || use_fake_m
                        || use_fake_metadata_verify
                );
            }
        }
    }

    #[test]
    fn test_pke_legacy_hash() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

        let seed = thread_rng().gen();
        println!("pkev2 legacy hash seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV2_TEST_PARAMS);
        let ct = testcase.encrypt(PKEV2_TEST_PARAMS);

        let fake_e1 = (0..d)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();
        let fake_e2 = (0..k)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();

        let fake_r = (0..d)
            .map(|_| (rng.gen::<u64>() % 2) as i64)
            .collect::<Vec<_>>();

        let fake_m = (0..k)
            .map(|_| (rng.gen::<u64>() % effective_cleartext_t) as i64)
            .collect::<Vec<_>>();

        let mut fake_metadata = [255u8; METADATA_LEN];
        fake_metadata.fill_with(|| rng.gen::<u8>());

        // To check management of bigger k_max from CRS during test
        let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

        let public_param = crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);

        for (use_fake_r, use_fake_e1, use_fake_e2, use_fake_m, use_fake_metadata_verify) in itertools::iproduct!(
            [false, true],
            [false, true],
            [false, true],
            [false, true],
            [false, true]
        ) {
            let (public_commit, private_commit) = commit(
                testcase.a.clone(),
                testcase.b.clone(),
                ct.c1.clone(),
                ct.c2.clone(),
                if use_fake_r {
                    fake_r.clone()
                } else {
                    testcase.r.clone()
                },
                if use_fake_e1 {
                    fake_e1.clone()
                } else {
                    testcase.e1.clone()
                },
                if use_fake_m {
                    fake_m.clone()
                } else {
                    testcase.m.clone()
                },
                if use_fake_e2 {
                    fake_e2.clone()
                } else {
                    testcase.e2.clone()
                },
                &public_param,
            );

            for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
                for hash_config in [
                    PkeV2SupportedHashConfig::V0_4_0,
                    PkeV2SupportedHashConfig::V0_7_0,
                ] {
                    let proof = prove_impl(
                        (&public_param, &public_commit),
                        &private_commit,
                        &testcase.metadata,
                        load,
                        &seed.to_le_bytes(),
                        hash_config,
                        ProofSanityCheckMode::Panic,
                    );

                    let verify_metadata = if use_fake_metadata_verify {
                        &fake_metadata
                    } else {
                        &testcase.metadata
                    };

                    assert_eq!(
                        verify_all_pairing_modes(
                            &proof,
                            (&public_param, &public_commit),
                            verify_metadata,
                        )
                        .is_err(),
                        use_fake_e1
                            || use_fake_e2
                            || use_fake_r
                            || use_fake_m
                            || use_fake_metadata_verify
                    );
                }
            }
        }
    }

    fn verify_all_pairing_modes(
        proof: &Proof<Curve>,
        public: (&PublicParams<Curve>, &PublicCommit<Curve>),
        metadata: &[u8],
    ) -> Result<(), ()> {
        let res1 = verify(proof, public, metadata, VerificationPairingMode::TwoSteps);

        let res2 = verify(proof, public, metadata, VerificationPairingMode::Batched);

        assert_eq!(res1, res2);
        res1
    }

    fn prove_and_verify(
        testcase: &PkeTestcase,
        ct: &PkeTestCiphertext,
        crs: &PublicParams<Curve>,
        load: ComputeLoad,
        seed: &[u8],
        hash_config: PkeV2SupportedHashConfig,
        sanity_check_mode: ProofSanityCheckMode,
    ) -> VerificationResult {
        let (public_commit, private_commit) = commit(
            testcase.a.clone(),
            testcase.b.clone(),
            ct.c1.clone(),
            ct.c2.clone(),
            testcase.r.clone(),
            testcase.e1.clone(),
            testcase.m.clone(),
            testcase.e2.clone(),
            crs,
        );

        let proof = prove_impl(
            (crs, &public_commit),
            &private_commit,
            &testcase.metadata,
            load,
            seed,
            hash_config,
            sanity_check_mode,
        );

        if verify_all_pairing_modes(&proof, (crs, &public_commit), &testcase.metadata).is_ok() {
            VerificationResult::Accept
        } else {
            VerificationResult::Reject
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_prove_and_verify(
        testcase: &PkeTestcase,
        ct: &PkeTestCiphertext,
        testcase_name: &str,
        crs: &PublicParams<Curve>,
        seed: &[u8],
        hash_config: PkeV2SupportedHashConfig,
        sanity_check_mode: ProofSanityCheckMode,
        expected_result: VerificationResult,
    ) {
        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            assert_eq!(
                prove_and_verify(
                    testcase,
                    ct,
                    crs,
                    load,
                    seed,
                    hash_config,
                    sanity_check_mode
                ),
                expected_result,
                "Testcase {testcase_name} {hash_config:?} hash with load {load} failed"
            )
        }
    }

    #[derive(Clone, Copy)]
    enum BoundTestSlackMode {
        /// Generate test noise vectors with all coeffs at 0 except one
        // Here ||e||inf == ||e||2 so the slack is the biggest, since B is multiplied by
        // sqrt(d+k) anyways
        Max,
        /// Generate test noise vectors with random coeffs and one just around the bound
        // Here the slack should be "average"
        Avg,
        /// Generate test noise vectors with all coeffs equals to B except one at +/-1
        // Here the slack should be minimal since ||e||_2 = sqrt(d+k)*||e||_inf, which is exactly
        // what we are proving.
        Min,
    }

    impl Display for BoundTestSlackMode {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                BoundTestSlackMode::Min => write!(f, "min_slack"),
                BoundTestSlackMode::Avg => write!(f, "avg_slack"),
                BoundTestSlackMode::Max => write!(f, "max_slack"),
            }
        }
    }

    #[derive(Clone, Copy)]
    enum TestedCoeffOffsetType {
        /// Noise term is after the bound, the proof should be refused
        After,
        /// Noise term is right on the bound, the proof should be accepted
        On,
        /// Noise term is before the bound, the proof should be accepted
        Before,
    }

    impl Display for TestedCoeffOffsetType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                TestedCoeffOffsetType::After => write!(f, "after_bound"),
                TestedCoeffOffsetType::On => write!(f, "on_bound"),
                TestedCoeffOffsetType::Before => write!(f, "before_bound"),
            }
        }
    }

    impl TestedCoeffOffsetType {
        fn offset(self) -> i64 {
            match self {
                TestedCoeffOffsetType::After => 1,
                TestedCoeffOffsetType::On => 0,
                TestedCoeffOffsetType::Before => -1,
            }
        }

        fn expected_result(self) -> VerificationResult {
            match self {
                TestedCoeffOffsetType::After => VerificationResult::Reject,
                TestedCoeffOffsetType::On => VerificationResult::Accept,
                TestedCoeffOffsetType::Before => VerificationResult::Accept,
            }
        }
    }

    #[derive(Clone, Copy)]
    enum TestedCoeffType {
        E1,
        E2,
    }

    impl Display for TestedCoeffType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                TestedCoeffType::E1 => write!(f, "e1"),
                TestedCoeffType::E2 => write!(f, "e2"),
            }
        }
    }

    struct PkeBoundTestcase {
        name: String,
        testcase: PkeTestcase,
        expected_result: VerificationResult,
    }

    impl PkeBoundTestcase {
        fn new(
            ref_testcase: &PkeTestcase,
            B: u64,
            slack_mode: BoundTestSlackMode,
            offset_type: TestedCoeffOffsetType,
            coeff_type: TestedCoeffType,
            rng: &mut StdRng,
        ) -> Self {
            let mut testcase = ref_testcase.clone();

            let d = testcase.e1.len();
            let k = testcase.e2.len();

            // Select a random index for the tested term
            let tested_idx = match coeff_type {
                TestedCoeffType::E1 => rng.gen::<usize>() % d,
                TestedCoeffType::E2 => rng.gen::<usize>() % k,
            };

            // Initialize the "good" terms of the error, that are not above the bound
            match slack_mode {
                BoundTestSlackMode::Max => {
                    // In this mode, all the terms are 0 except the tested one
                    testcase.e1 = vec![0; d];
                    testcase.e2 = vec![0; k];
                }
                BoundTestSlackMode::Avg => {
                    // In this mode we keep the original random vector
                }
                BoundTestSlackMode::Min => {
                    // In this mode all the terms are exactly at the bound
                    let good_term = B as i64;
                    testcase.e1 = (0..d)
                        .map(|_| if rng.gen() { good_term } else { -good_term })
                        .collect();
                    testcase.e2 = (0..k)
                        .map(|_| if rng.gen() { good_term } else { -good_term })
                        .collect();
                }
            };

            let B_with_slack_squared = inf_norm_bound_to_euclidean_squared(B, d + k);
            let B_with_slack = u64::try_from(B_with_slack_squared.isqrt()).unwrap();

            let coeff_at_bound = match slack_mode {
                // The slack is maximal, any term above B+slack should be refused
                BoundTestSlackMode::Max => i64::try_from(B_with_slack).unwrap(),
                // The actual accepted bound depends on the content of the test vector
                // To create a bound testcase, we have to modify the tested coeff such that the
                // squared norm 2 of the noise vector is equal to B_with_slack_squared
                BoundTestSlackMode::Avg => {
                    let e_sqr_norm = testcase
                        .e1
                        .iter()
                        .chain(&testcase.e2)
                        .map(|x| sqr(x.unsigned_abs()))
                        .sum::<u128>();

                    let orig_coeff = match coeff_type {
                        TestedCoeffType::E1 => testcase.e1[tested_idx],
                        TestedCoeffType::E2 => testcase.e2[tested_idx],
                    };

                    let sqr_norm_without_tested_coeff =
                        Strict(e_sqr_norm) - Strict(sqr(orig_coeff.unsigned_abs()));
                    let sqr_modified_coeff =
                        Strict(B_with_slack_squared) - sqr_norm_without_tested_coeff;
                    i64::try_from(sqr_modified_coeff.0.isqrt()).unwrap()
                }
                // There is no slack effect, any term above B should be refused
                BoundTestSlackMode::Min => i64::try_from(B).unwrap(),
            };

            // Depending on what we want to test, add -1, 0 or 1 to the coeff at the bound
            let tested_coeff = coeff_at_bound + offset_type.offset();

            match coeff_type {
                TestedCoeffType::E1 => testcase.e1[tested_idx] = tested_coeff,
                TestedCoeffType::E2 => testcase.e2[tested_idx] = tested_coeff,
            };

            Self {
                name: format!("test_{slack_mode}_{offset_type}_{coeff_type}"),
                testcase,
                expected_result: offset_type.expected_result(),
            }
        }
    }

    /// Test that the proof is rejected if we use a noise outside of the bounds, taking the slack
    /// into account
    #[test]
    fn test_pke_bad_noise() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let seed = thread_rng().gen();
        println!("pkev2_bad_noise seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV2_TEST_PARAMS);

        let crs = crs_gen::<Curve>(d, k, B, q, t, msbs_zero_padding_bit_count, rng);
        let crs_max_k = crs_gen::<Curve>(d, d, B, q, t, msbs_zero_padding_bit_count, rng);

        let B_with_slack_squared = inf_norm_bound_to_euclidean_squared(B, d + k);
        let B_with_slack_upper = B_with_slack_squared.isqrt() as u64 + 1;

        // Generate test noise vectors with random coeffs and one completely out of bounds

        let mut testcases = Vec::new();
        let mut testcase_bad_e1 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % d;
        let bad_term =
            (rng.gen::<u64>() % (i64::MAX as u64 - B_with_slack_upper)) + B_with_slack_upper;
        let bad_term = bad_term as i64;

        testcase_bad_e1.e1[bad_idx] = if rng.gen() { bad_term } else { -bad_term };

        testcases.push(PkeBoundTestcase {
            name: "testcase_bad_e1".to_string(),
            testcase: testcase_bad_e1,
            expected_result: VerificationResult::Reject,
        });

        let mut testcase_bad_e2 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % k;

        testcase_bad_e2.e2[bad_idx] = if rng.gen() { bad_term } else { -bad_term };

        testcases.push(PkeBoundTestcase {
            name: "testcase_bad_e2".to_string(),
            testcase: testcase_bad_e2,
            expected_result: VerificationResult::Reject,
        });

        // Generate test vectors with a noise term right around the bound

        testcases.extend(
            itertools::iproduct!(
                [
                    BoundTestSlackMode::Min,
                    BoundTestSlackMode::Avg,
                    BoundTestSlackMode::Max
                ],
                [
                    TestedCoeffOffsetType::Before,
                    TestedCoeffOffsetType::On,
                    TestedCoeffOffsetType::After
                ],
                [TestedCoeffType::E1, TestedCoeffType::E2]
            )
            .map(|(slack_mode, offset_type, coeff_type)| {
                PkeBoundTestcase::new(&testcase, B, slack_mode, offset_type, coeff_type, rng)
            }),
        );

        for PkeBoundTestcase {
            name,
            testcase,
            expected_result,
        } in testcases
        {
            let ct = testcase.encrypt_unchecked(PKEV2_TEST_PARAMS);
            assert_prove_and_verify(
                &testcase,
                &ct,
                &format!("{name}_crs"),
                &crs,
                &seed.to_le_bytes(),
                PkeV2SupportedHashConfig::default(),
                ProofSanityCheckMode::Ignore,
                expected_result,
            );
            assert_prove_and_verify(
                &testcase,
                &ct,
                &format!("{name}_crs_max_k"),
                &crs_max_k,
                &seed.to_le_bytes(),
                PkeV2SupportedHashConfig::default(),
                ProofSanityCheckMode::Ignore,
                expected_result,
            );
        }
    }

    /// Compare the computed params with manually calculated ones to check the formula
    #[test]
    fn test_compute_crs_params() {
        let PkeTestParameters {
            d,
            k,
            B,
            q: _,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let B_squared = inf_norm_bound_to_euclidean_squared(B, d + k);
        assert_eq!(B_squared, 40681930227712);

        let (n, D, B_bound_squared, m_bound) =
            compute_crs_params(d, k, B_squared, t, msbs_zero_padding_bit_count, Bound::GHL);
        assert_eq!(n, 6784);
        assert_eq!(D, 3328);
        assert_eq!(B_bound_squared, 3867562496364372);
        assert_eq!(m_bound, 27);

        let (n, D, B_bound_squared, m_bound) =
            compute_crs_params(d, k, B_squared, t, msbs_zero_padding_bit_count, Bound::CS);
        assert_eq!(n, 7168);
        assert_eq!(D, 3328);
        assert_eq!(B_bound_squared, 192844141830554880);
        assert_eq!(m_bound, 30);
    }

    /// Test that the proof is rejected if we don't have the padding bit set to 0
    #[test]
    fn test_pke_w_padding_fail_verify() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

        let seed = thread_rng().gen();
        println!("pkev2_w_padding_fail_verify seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let mut testcase = PkeTestcase::gen(rng, PKEV2_TEST_PARAMS);
        // Generate messages with padding set to fail verification
        testcase.m = {
            let mut tmp = (0..k)
                .map(|_| (rng.gen::<u64>() % t) as i64)
                .collect::<Vec<_>>();
            while tmp.iter().all(|&x| (x as u64) < effective_cleartext_t) {
                tmp.fill_with(|| (rng.gen::<u64>() % t) as i64);
            }

            tmp
        };

        let ct = testcase.encrypt(PKEV2_TEST_PARAMS);

        // To check management of bigger k_max from CRS during test
        let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

        let original_public_param =
            crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);
        let public_param_that_was_compressed =
            serialize_then_deserialize(&original_public_param, Compress::Yes).unwrap();
        let public_param_that_was_not_compressed =
            serialize_then_deserialize(&original_public_param, Compress::No).unwrap();

        for (public_param, test_name) in [
            (original_public_param, "original_params"),
            (
                public_param_that_was_compressed,
                "serialized_compressed_params",
            ),
            (public_param_that_was_not_compressed, "serialize_params"),
        ] {
            assert_prove_and_verify(
                &testcase,
                &ct,
                test_name,
                &public_param,
                &seed.to_le_bytes(),
                PkeV2SupportedHashConfig::default(),
                ProofSanityCheckMode::Panic,
                VerificationResult::Reject,
            );
        }
    }

    /// Test that the proof is rejected without panic if the public key elements are not of the
    /// correct size
    #[test]
    fn test_pke_wrong_pk_size() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let seed = thread_rng().gen();
        println!("pke_wrong_pk_size seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV2_TEST_PARAMS);
        let ct = testcase.encrypt(PKEV2_TEST_PARAMS);

        let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

        let crs = crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);

        let (public_commit, private_commit) = commit(
            testcase.a.clone(),
            testcase.b.clone(),
            ct.c1.clone(),
            ct.c2.clone(),
            testcase.r.clone(),
            testcase.e1.clone(),
            testcase.m.clone(),
            testcase.e2.clone(),
            &crs,
        );

        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let proof = prove(
                (&crs, &public_commit),
                &private_commit,
                &testcase.metadata,
                load,
                &seed.to_le_bytes(),
            );

            for (a_size_kind, b_size_kind) in itertools::iproduct!(
                [
                    InputSizeVariation::Oversized,
                    InputSizeVariation::Undersized,
                    InputSizeVariation::Nominal,
                ],
                [
                    InputSizeVariation::Oversized,
                    InputSizeVariation::Undersized,
                    InputSizeVariation::Nominal,
                ]
            ) {
                if a_size_kind == InputSizeVariation::Nominal
                    && b_size_kind == InputSizeVariation::Nominal
                {
                    // This is the nominal case that is already tested
                    continue;
                }

                let mut public_commit = public_commit.clone();

                match a_size_kind {
                    InputSizeVariation::Oversized => public_commit.a.push(rng.gen()),
                    InputSizeVariation::Undersized => {
                        public_commit.a.pop();
                    }
                    InputSizeVariation::Nominal => {}
                };

                match b_size_kind {
                    InputSizeVariation::Oversized => public_commit.b.push(rng.gen()),
                    InputSizeVariation::Undersized => {
                        public_commit.b.pop();
                    }
                    InputSizeVariation::Nominal => {}
                };

                // Should not panic but return an error
                assert!(verify(
                    &proof,
                    (&crs, &public_commit),
                    &testcase.metadata,
                    VerificationPairingMode::default()
                )
                .is_err())
            }
        }
    }

    /// Test verification with modified ciphertexts
    #[test]
    fn test_bad_ct() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

        let seed = thread_rng().gen();
        println!("pkev2_bad_ct seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV2_TEST_PARAMS_SINGLE);
        let ct = testcase.encrypt(PKEV2_TEST_PARAMS_SINGLE);

        let ct_zero = testcase.sk_encrypt_zero(PKEV2_TEST_PARAMS_SINGLE, rng);

        let c1_plus_zero = ct
            .c1
            .iter()
            .zip(ct_zero.iter())
            .map(|(a1, az)| a1.wrapping_add(*az))
            .collect();
        let c2_plus_zero = vec![ct.c2[0].wrapping_add(*ct_zero.last().unwrap())];

        let ct_plus_zero = PkeTestCiphertext {
            c1: c1_plus_zero,
            c2: c2_plus_zero,
        };

        let m_plus_zero = testcase.decrypt(&ct_plus_zero, PKEV2_TEST_PARAMS_SINGLE);
        assert_eq!(testcase.m, m_plus_zero);

        let delta = {
            let q = decode_q(q) as i128;
            // delta takes the encoding with the padding bit
            (q / t as i128) as u64
        };

        // If trivial is 0 the ct is not modified so the proof will be accepted
        let trivial = rng.gen_range(1..effective_cleartext_t);

        let trivial_pt = trivial * delta;
        let c2_plus_trivial = vec![ct.c2[0].wrapping_add(trivial_pt as i64)];

        let ct_plus_trivial = PkeTestCiphertext {
            c1: ct.c1.clone(),
            c2: c2_plus_trivial,
        };

        let m_plus_trivial = testcase.decrypt(&ct_plus_trivial, PKEV2_TEST_PARAMS_SINGLE);
        assert_eq!(testcase.m[0] + trivial as i64, m_plus_trivial[0]);

        let crs = crs_gen::<Curve>(d, k, B, q, t, msbs_zero_padding_bit_count, rng);

        // Test proving with one ct and verifying another
        let (public_commit_proof, private_commit) = commit(
            testcase.a.clone(),
            testcase.b.clone(),
            ct.c1.clone(),
            ct.c2.clone(),
            testcase.r.clone(),
            testcase.e1.clone(),
            testcase.m.clone(),
            testcase.e2.clone(),
            &crs,
        );

        let (public_commit_verify_zero, _) = commit(
            testcase.a.clone(),
            testcase.b.clone(),
            ct_plus_zero.c1.clone(),
            ct_plus_zero.c2.clone(),
            testcase.r.clone(),
            testcase.e1.clone(),
            testcase.m.clone(),
            testcase.e2.clone(),
            &crs,
        );

        let (public_commit_verify_trivial, _) = commit(
            testcase.a.clone(),
            testcase.b.clone(),
            ct_plus_trivial.c1.clone(),
            ct_plus_trivial.c2.clone(),
            testcase.r.clone(),
            testcase.e1.clone(),
            m_plus_trivial,
            testcase.e2.clone(),
            &crs,
        );

        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let proof = prove(
                (&crs, &public_commit_proof),
                &private_commit,
                &testcase.metadata,
                load,
                &seed.to_le_bytes(),
            );

            assert!(verify_all_pairing_modes(
                &proof,
                (&crs, &public_commit_verify_zero),
                &testcase.metadata,
            )
            .is_err());

            assert!(verify_all_pairing_modes(
                &proof,
                (&crs, &public_commit_verify_trivial),
                &testcase.metadata,
            )
            .is_err());
        }
    }

    /// Test encryption of a message where the delta used for encryption is not the one used for
    /// proof/verify
    #[test]
    fn test_bad_delta() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

        let seed = thread_rng().gen();
        println!("pkev2_bad_delta seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV2_TEST_PARAMS);
        let mut testcase_bad_delta = testcase.clone();

        // Make sure that the messages lower bit is set so the change of delta has an impact on the
        // validity of the ct
        testcase_bad_delta.m = (0..k)
            .map(|_| (rng.gen::<u64>() % effective_cleartext_t) as i64 | 1)
            .collect::<Vec<_>>();

        let mut params_bad_delta = PKEV2_TEST_PARAMS;
        params_bad_delta.t *= 2; // Multiply t by 2 to "spill" 1 bit of message into the noise

        // Encrypt using wrong delta
        let ct_bad_delta = testcase_bad_delta.encrypt(params_bad_delta);

        // Prove using a crs built using the "right" delta
        let crs = crs_gen::<Curve>(d, k, B, q, t, msbs_zero_padding_bit_count, rng);

        assert_prove_and_verify(
            &testcase,
            &ct_bad_delta,
            "testcase_bad_delta",
            &crs,
            &seed.to_le_bytes(),
            PkeV2SupportedHashConfig::default(),
            ProofSanityCheckMode::Panic,
            VerificationResult::Reject,
        );
    }

    /// Test encryption of a message with params that are at the limits of what is supported
    #[test]
    fn test_big_params() {
        let seed = thread_rng().gen();
        println!("pkev2_big_params seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        for bound in [Bound::CS, Bound::GHL] {
            let params = match bound {
                Bound::GHL => BIG_TEST_PARAMS_GHL,
                Bound::CS => BIG_TEST_PARAMS_CS,
            };
            let PkeTestParameters {
                d,
                k,
                B,
                q,
                t,
                msbs_zero_padding_bit_count,
            } = params;

            let testcase = PkeTestcase::gen(rng, params);
            let ct = testcase.encrypt(params);

            // Check that there is no overflow with both bounds
            let crs = match bound {
                Bound::GHL => crs_gen_ghl::<Curve>(d, k, B, q, t, msbs_zero_padding_bit_count, rng),
                Bound::CS => crs_gen_cs::<Curve>(d, k, B, q, t, msbs_zero_padding_bit_count, rng),
            };

            assert_prove_and_verify(
                &testcase,
                &ct,
                &format!("testcase_big_params_{bound:?}"),
                &crs,
                &seed.to_le_bytes(),
                PkeV2SupportedHashConfig::default(),
                ProofSanityCheckMode::Panic,
                VerificationResult::Accept,
            );
        }
    }

    /// Test compression of proofs
    #[test]
    fn test_proof_compression() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let seed = thread_rng().gen();
        println!("pkev2_proof_compression seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV2_TEST_PARAMS);
        let ct = testcase.encrypt(PKEV2_TEST_PARAMS);

        let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

        let public_param = crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);

        let (public_commit, private_commit) = commit(
            testcase.a.clone(),
            testcase.b.clone(),
            ct.c1.clone(),
            ct.c2.clone(),
            testcase.r.clone(),
            testcase.e1.clone(),
            testcase.m.clone(),
            testcase.e2.clone(),
            &public_param,
        );

        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let proof = prove(
                (&public_param, &public_commit),
                &private_commit,
                &testcase.metadata,
                load,
                &seed.to_le_bytes(),
            );

            let compressed_proof = bincode::serialize(&proof.compress().versionize()).unwrap();
            let proof = Proof::uncompress(
                CompressedProof::unversionize(bincode::deserialize(&compressed_proof).unwrap())
                    .unwrap(),
            )
            .unwrap();

            verify(
                &proof,
                (&public_param, &public_commit),
                &testcase.metadata,
                VerificationPairingMode::default(),
            )
            .unwrap()
        }
    }

    /// Test the `is_usable` method, that checks the correctness of the the crs
    #[test]
    fn test_crs_usable() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let seed = thread_rng().gen();
        println!("pkev2_crs_usable seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

        let public_param = crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);

        assert!(public_param.is_usable());

        let public_param_that_was_compressed =
            serialize_then_deserialize(&public_param, Compress::Yes).unwrap();

        assert!(public_param_that_was_compressed.is_usable());

        let mut bad_crs = public_param.clone();
        bad_crs.g_lists.g_list[public_param.n + 1] = bad_crs.g_lists.g_list[public_param.n];

        assert!(!bad_crs.is_usable());
    }

    /// Test the `is_usable` method, that checks the correctness of the EC points in the proof
    #[test]
    fn test_proof_usable() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV2_TEST_PARAMS;

        let seed = thread_rng().gen();
        println!("pkev2_proof_usable seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV2_TEST_PARAMS);
        let ct = testcase.encrypt(PKEV2_TEST_PARAMS);

        let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

        let public_param = crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);

        let (public_commit, private_commit) = commit(
            testcase.a.clone(),
            testcase.b.clone(),
            ct.c1.clone(),
            ct.c2.clone(),
            testcase.r.clone(),
            testcase.e1.clone(),
            testcase.m.clone(),
            testcase.e2.clone(),
            &public_param,
        );

        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let valid_proof = prove(
                (&public_param, &public_commit),
                &private_commit,
                &testcase.metadata,
                load,
                &seed.to_le_bytes(),
            );

            let compressed_proof = bincode::serialize(&valid_proof.compress()).unwrap();
            let proof_that_was_compressed: Proof<Curve> =
                Proof::uncompress(bincode::deserialize(&compressed_proof).unwrap()).unwrap();

            assert!(valid_proof.is_usable());
            assert!(proof_that_was_compressed.is_usable());

            let not_on_curve_g1 = bls12_446::G1::projective(bls12_446::G1Affine {
                inner: point_not_on_curve(rng),
            });

            let not_on_curve_g2 = bls12_446::G2::projective(bls12_446::G2Affine {
                inner: point_not_on_curve(rng),
            });

            let not_in_group_g1 = bls12_446::G1::projective(bls12_446::G1Affine {
                inner: point_on_curve_wrong_subgroup(rng),
            });

            let not_in_group_g2 = bls12_446::G2::projective(bls12_446::G2Affine {
                inner: point_on_curve_wrong_subgroup(rng),
            });

            {
                let mut proof = valid_proof.clone();
                proof.C_hat_e = not_on_curve_g2;
                assert!(!proof.is_usable());
                proof.C_hat_e = not_in_group_g2;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.C_e = not_on_curve_g1;
                assert!(!proof.is_usable());
                proof.C_e = not_in_group_g1;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.C_r_tilde = not_on_curve_g1;
                assert!(!proof.is_usable());
                proof.C_r_tilde = not_in_group_g1;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.C_R = not_on_curve_g1;
                assert!(!proof.is_usable());
                proof.C_R = not_in_group_g1;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.C_hat_bin = not_on_curve_g2;
                assert!(!proof.is_usable());
                proof.C_hat_bin = not_in_group_g2;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.C_y = not_on_curve_g1;
                assert!(!proof.is_usable());
                proof.C_y = not_in_group_g1;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.C_h1 = not_on_curve_g1;
                assert!(!proof.is_usable());
                proof.C_h1 = not_in_group_g1;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.C_h2 = not_on_curve_g1;
                assert!(!proof.is_usable());
                proof.C_h2 = not_in_group_g1;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.C_hat_t = not_on_curve_g2;
                assert!(!proof.is_usable());
                proof.C_hat_t = not_in_group_g2;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.pi = not_on_curve_g1;
                assert!(!proof.is_usable());
                proof.pi = not_in_group_g1;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.pi_kzg = not_on_curve_g1;
                assert!(!proof.is_usable());
                proof.pi_kzg = not_in_group_g1;
                assert!(!proof.is_usable());
            }

            if let Some(ref valid_compute_proof_fields) = valid_proof.compute_load_proof_fields {
                {
                    let mut proof = valid_proof.clone();
                    proof.compute_load_proof_fields = Some(ComputeLoadProofFields {
                        C_hat_h3: not_on_curve_g2,
                        C_hat_w: valid_compute_proof_fields.C_hat_w,
                    });

                    assert!(!proof.is_usable());
                    proof.compute_load_proof_fields = Some(ComputeLoadProofFields {
                        C_hat_h3: not_in_group_g2,
                        C_hat_w: valid_compute_proof_fields.C_hat_w,
                    });

                    assert!(!proof.is_usable());
                }

                {
                    let mut proof = valid_proof.clone();
                    proof.compute_load_proof_fields = Some(ComputeLoadProofFields {
                        C_hat_h3: valid_compute_proof_fields.C_hat_h3,
                        C_hat_w: not_on_curve_g2,
                    });

                    assert!(!proof.is_usable());

                    proof.compute_load_proof_fields = Some(ComputeLoadProofFields {
                        C_hat_h3: valid_compute_proof_fields.C_hat_h3,
                        C_hat_w: not_in_group_g2,
                    });

                    assert!(!proof.is_usable());
                }
            }
        }
    }
}
