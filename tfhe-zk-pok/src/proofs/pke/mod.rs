#[cfg(feature = "gpu-experimental")]
pub mod gpu;

// TODO: refactor copy-pasted code in proof/verify

use crate::backward_compatibility::pke::{
    CompressedComputeLoadProofFieldsVersions, CompressedProofVersions,
    ComputeLoadProofFieldsVersions, ProofVersions,
};
use crate::serialization::{
    InvalidSerializedAffineError, InvalidSerializedPublicParamsError, SerializableGroupElements,
    SerializablePKEv1PublicParams,
};

use super::*;
use core::marker::PhantomData;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

pub(crate) fn bit_iter(x: u64, nbits: u32) -> impl Iterator<Item = bool> {
    (0..nbits).map(move |idx| ((x >> idx) & 1) != 0)
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[serde(
    try_from = "SerializablePKEv1PublicParams",
    into = "SerializablePKEv1PublicParams",
    bound(
        deserialize = "PublicParams<G>: TryFrom<SerializablePKEv1PublicParams, Error = InvalidSerializedPublicParamsError>",
        serialize = "PublicParams<G>: Into<SerializablePKEv1PublicParams>"
    )
)]
#[versionize(try_convert = SerializablePKEv1PublicParams)]
pub struct PublicParams<G: Curve> {
    pub(crate) g_lists: GroupElements<G>,
    pub(crate) big_d: usize,
    pub n: usize,
    pub d: usize,
    pub k: usize,
    pub b: u64,
    pub b_r: u64,
    pub q: u64,
    pub t: u64,
    pub msbs_zero_padding_bit_count: u64,
    pub(crate) sid: Sid,
    pub(crate) domain_separators: PKEv1DomainSeparators,
}

#[derive(Clone, Debug)]
pub(crate) enum PKEv1DomainSeparators {
    Legacy(Box<LegacyPKEv1DomainSeparators>),
    Short(ShortPKEv1DomainSeparators),
}

impl PKEv1DomainSeparators {
    pub(crate) fn new(rng: &mut dyn RngCore) -> Self {
        let ds = ShortPKEv1DomainSeparators {
            hash: core::array::from_fn(|_| rng.gen()),
            hash_t: core::array::from_fn(|_| rng.gen()),
            hash_agg: core::array::from_fn(|_| rng.gen()),
            hash_lmap: core::array::from_fn(|_| rng.gen()),
            hash_z: core::array::from_fn(|_| rng.gen()),
            hash_w: core::array::from_fn(|_| rng.gen()),
            hash_gamma: core::array::from_fn(|_| rng.gen()),
        };

        Self::Short(ds)
    }

    pub(crate) fn hash(&self) -> &[u8] {
        match self {
            PKEv1DomainSeparators::Legacy(ds) => &ds.hash,
            PKEv1DomainSeparators::Short(ds) => &ds.hash,
        }
    }

    pub(crate) fn hash_t(&self) -> &[u8] {
        match self {
            PKEv1DomainSeparators::Legacy(ds) => &ds.hash_t,
            PKEv1DomainSeparators::Short(ds) => &ds.hash_t,
        }
    }

    pub(crate) fn hash_agg(&self) -> &[u8] {
        match self {
            PKEv1DomainSeparators::Legacy(ds) => &ds.hash_agg,
            PKEv1DomainSeparators::Short(ds) => &ds.hash_agg,
        }
    }

    pub(crate) fn hash_lmap(&self) -> &[u8] {
        match self {
            PKEv1DomainSeparators::Legacy(ds) => &ds.hash_lmap,
            PKEv1DomainSeparators::Short(ds) => &ds.hash_lmap,
        }
    }

    pub(crate) fn hash_w(&self) -> &[u8] {
        match self {
            PKEv1DomainSeparators::Legacy(ds) => &ds.hash_w,
            PKEv1DomainSeparators::Short(ds) => &ds.hash_w,
        }
    }

    pub(crate) fn hash_z(&self) -> &[u8] {
        match self {
            PKEv1DomainSeparators::Legacy(ds) => &ds.hash_z,
            PKEv1DomainSeparators::Short(ds) => &ds.hash_z,
        }
    }

    pub(crate) fn hash_gamma(&self) -> &[u8] {
        match self {
            PKEv1DomainSeparators::Legacy(ds) => &ds.hash_gamma,
            PKEv1DomainSeparators::Short(ds) => &ds.hash_gamma,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LegacyPKEv1DomainSeparators {
    pub(crate) hash: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_t: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_agg: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_lmap: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_w: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_z: [u8; LEGACY_HASH_DS_LEN_BYTES],
    pub(crate) hash_gamma: [u8; LEGACY_HASH_DS_LEN_BYTES],
}

#[derive(Clone, Debug)]
pub struct ShortPKEv1DomainSeparators {
    pub(crate) hash: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_t: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_agg: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_lmap: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_z: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_w: [u8; HASH_DS_LEN_BYTES],
    pub(crate) hash_gamma: [u8; HASH_DS_LEN_BYTES],
}

impl<G: Curve> Compressible for PublicParams<G>
where
    GroupElements<G>: Compressible<
        Compressed = SerializableGroupElements,
        UncompressError = InvalidSerializedGroupElementsError,
    >,
{
    type Compressed = SerializablePKEv1PublicParams;

    type UncompressError = InvalidSerializedPublicParamsError;

    fn compress(&self) -> Self::Compressed {
        let PublicParams {
            g_lists,
            big_d,
            n,
            d,
            k,
            b,
            b_r,
            q,
            t,
            msbs_zero_padding_bit_count,
            sid,
            domain_separators,
        } = self;
        SerializablePKEv1PublicParams {
            g_lists: g_lists.compress(),
            big_d: *big_d,
            n: *n,
            d: *d,
            k: *k,
            b: *b,
            b_r: *b_r,
            q: *q,
            t: *t,
            msbs_zero_padding_bit_count: *msbs_zero_padding_bit_count,
            sid: sid.0,
            domain_separators: domain_separators.clone().into(),
        }
    }

    fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
        let SerializablePKEv1PublicParams {
            g_lists,
            big_d,
            n,
            d,
            k,
            b,
            b_r,
            q,
            t,
            msbs_zero_padding_bit_count,
            sid,
            domain_separators,
        } = compressed;
        Ok(Self {
            g_lists: GroupElements::uncompress(g_lists)?,
            big_d,
            n,
            d,
            k,
            b,
            b_r,
            q,
            t,
            msbs_zero_padding_bit_count,
            sid: Sid(sid),
            domain_separators: domain_separators.try_into()?,
        })
    }
}

impl<G: Curve> PublicParams<G> {
    #[allow(clippy::too_many_arguments)]
    pub fn from_vec(
        g_list: Vec<Affine<G::Zp, G::G1>>,
        g_hat_list: Vec<Affine<G::Zp, G::G2>>,
        big_d: usize,
        n: usize,
        d: usize,
        k: usize,
        b: u64,
        b_r: u64,
        q: u64,
        t: u64,
        msbs_zero_padding_bit_count: u64,
        sid: u128,
        hash: [u8; HASH_DS_LEN_BYTES],
        hash_t: [u8; HASH_DS_LEN_BYTES],
        hash_agg: [u8; HASH_DS_LEN_BYTES],
        hash_lmap: [u8; HASH_DS_LEN_BYTES],
        hash_z: [u8; HASH_DS_LEN_BYTES],
        hash_w: [u8; HASH_DS_LEN_BYTES],
        hash_gamma: [u8; HASH_DS_LEN_BYTES],
    ) -> Self {
        Self {
            g_lists: GroupElements::<G>::from_vec(g_list, g_hat_list),
            big_d,
            n,
            d,
            k,
            b,
            b_r,
            q,
            t,
            msbs_zero_padding_bit_count,
            sid: Sid(Some(sid)),
            domain_separators: PKEv1DomainSeparators::Short(ShortPKEv1DomainSeparators {
                hash,
                hash_t,
                hash_agg,
                hash_lmap,
                hash_z,
                hash_w,
                hash_gamma,
            }),
        }
    }

    pub fn exclusive_max_noise(&self) -> u64 {
        self.b
    }

    /// Check if the crs can be used to generate or verify a proof
    ///
    /// This means checking that the points are:
    /// - valid points of the curve
    /// - in the correct subgroup
    pub fn is_usable(&self) -> bool {
        self.g_lists.is_valid(self.n)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(
    deserialize = "G: Curve, G::G1: serde::Deserialize<'de>, G::G2: serde::Deserialize<'de>",
    serialize = "G: Curve, G::G1: serde::Serialize, G::G2: serde::Serialize"
))]
#[versionize(ProofVersions)]
pub struct Proof<G: Curve> {
    pub(crate) c_hat: G::G2,
    pub(crate) c_y: G::G1,
    pub(crate) pi: G::G1,
    pub(crate) compute_load_proof_fields: Option<ComputeLoadProofFields<G>>,
}

impl<G: Curve> Proof<G> {
    /// Check if the proof can be used by the Verifier.
    ///
    /// This means checking that the points in the proof are:
    /// - valid points of the curve
    /// - in the correct subgroup
    pub fn is_usable(&self) -> bool {
        let &Proof {
            c_hat,
            c_y,
            pi,
            ref compute_load_proof_fields,
        } = self;

        c_hat.validate_projective()
            && c_y.validate_projective()
            && pi.validate_projective()
            && compute_load_proof_fields.as_ref().is_none_or(
                |&ComputeLoadProofFields {
                     c_hat_t,
                     c_h,
                     pi_kzg,
                 }| {
                    c_hat_t.validate_projective()
                        && c_h.validate_projective()
                        && pi_kzg.validate_projective()
                },
            )
    }

    pub fn compute_load(&self) -> ComputeLoad {
        match self.compute_load_proof_fields {
            Some(_) => ComputeLoad::Proof,
            None => ComputeLoad::Verify,
        }
    }
}

/// These fields can be pre-computed on the prover side in the faster Verifier scheme. If that's the
/// case, they should be included in the proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(
    deserialize = "G: Curve, G::G1: serde::Deserialize<'de>, G::G2: serde::Deserialize<'de>",
    serialize = "G: Curve, G::G1: serde::Serialize, G::G2: serde::Serialize"
))]
#[versionize(ComputeLoadProofFieldsVersions)]
pub(crate) struct ComputeLoadProofFields<G: Curve> {
    pub(crate) c_hat_t: G::G2,
    pub(crate) c_h: G::G1,
    pub(crate) pi_kzg: G::G1,
}

type CompressedG2<G> = <<G as Curve>::G2 as Compressible>::Compressed;
type CompressedG1<G> = <<G as Curve>::G1 as Compressible>::Compressed;

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
    pub(crate) c_hat: CompressedG2<G>,
    pub(crate) c_y: CompressedG1<G>,
    pub(crate) pi: CompressedG1<G>,
    pub(crate) compute_load_proof_fields: Option<CompressedComputeLoadProofFields<G>>,
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
    pub(crate) c_hat_t: CompressedG2<G>,
    pub(crate) c_h: CompressedG1<G>,
    pub(crate) pi_kzg: CompressedG1<G>,
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
            c_hat,
            c_y,
            pi,
            compute_load_proof_fields,
        } = self;

        CompressedProof {
            c_hat: c_hat.compress(),
            c_y: c_y.compress(),
            pi: pi.compress(),
            compute_load_proof_fields: compute_load_proof_fields.as_ref().map(
                |ComputeLoadProofFields {
                     c_hat_t,
                     c_h,
                     pi_kzg,
                 }| CompressedComputeLoadProofFields {
                    c_hat_t: c_hat_t.compress(),
                    c_h: c_h.compress(),
                    pi_kzg: pi_kzg.compress(),
                },
            ),
        }
    }

    fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
        let CompressedProof {
            c_hat,
            c_y,
            pi,
            compute_load_proof_fields,
        } = compressed;

        Ok(Proof {
            c_hat: G::G2::uncompress(c_hat)?,
            c_y: G::G1::uncompress(c_y)?,
            pi: G::G1::uncompress(pi)?,

            compute_load_proof_fields: if let Some(CompressedComputeLoadProofFields {
                c_hat_t,
                c_h,
                pi_kzg,
            }) = compute_load_proof_fields
            {
                Some(ComputeLoadProofFields {
                    c_hat_t: G::G2::uncompress(c_hat_t)?,
                    c_h: G::G1::uncompress(c_h)?,
                    pi_kzg: G::G1::uncompress(pi_kzg)?,
                })
            } else {
                None
            },
        })
    }
}

#[derive(Clone, Debug)]
pub struct PublicCommit<G: Curve> {
    pub(crate) a: Vec<i64>,
    pub(crate) b: Vec<i64>,
    pub(crate) c1: Vec<i64>,
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
    pub(crate) r: Vec<i64>,
    pub(crate) e1: Vec<i64>,
    pub(crate) m: Vec<i64>,
    pub(crate) e2: Vec<i64>,
    __marker: PhantomData<G>,
}

pub fn compute_crs_params(
    d: usize,
    k: usize,
    b: u64,
    _q: u64, // we keep q here to make sure the API is consistent with [crs_gen]
    t: u64,
    msbs_zero_padding_bit_count: u64,
) -> (usize, usize, u64) {
    let b_r = d as u64 / 2 + 1;

    // This is also the effective t for encryption
    let effective_t_for_decomposition = t >> msbs_zero_padding_bit_count;

    // This formulation is equivalent to the formula of the paper as 1 + b_r.ilog2() == d.ilog2()
    // for any d power of 2 > 2
    let big_d = d
        + k * effective_t_for_decomposition.ilog2() as usize
        + (d + k) * (2 + b.ilog2() as usize + b_r.ilog2() as usize);
    let n = big_d + 1;
    (n, big_d, b_r)
}

pub fn crs_gen<G: Curve>(
    d: usize,
    k: usize,
    b: u64,
    q: u64,
    t: u64,
    msbs_zero_padding_bit_count: u64,
    rng: &mut dyn RngCore,
) -> PublicParams<G> {
    let alpha = G::Zp::rand(rng);
    let (n, big_d, b_r) = compute_crs_params(d, k, b, q, t, msbs_zero_padding_bit_count);
    PublicParams {
        g_lists: GroupElements::<G>::new(n, alpha),
        big_d,
        n,
        d,
        k,
        b,
        b_r,
        q,
        t,
        msbs_zero_padding_bit_count,
        sid: Sid::new(rng),
        domain_separators: PKEv1DomainSeparators::new(rng),
    }
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
        ProofSanityCheckMode::Panic,
    )
}

fn prove_impl<G: Curve>(
    public: (&PublicParams<G>, &PublicCommit<G>),
    private_commit: &PrivateCommit<G>,
    metadata: &[u8],
    load: ComputeLoad,
    seed: &[u8],
    sanity_check_mode: ProofSanityCheckMode,
) -> Proof<G> {
    let &PublicParams {
        ref g_lists,
        big_d: big_d_max,
        n,
        d,
        b,
        b_r,
        q,
        t,
        msbs_zero_padding_bit_count,
        k: k_max,
        sid,
        domain_separators: ref ds,
    } = public.0;
    let g_list = &g_lists.g_list;
    let g_hat_list = &g_lists.g_hat_list;

    let b_i = b;

    let PublicCommit { a, b, c1, c2, .. } = public.1;
    let PrivateCommit { r, e1, m, e2, .. } = private_commit;

    let k = c2.len();

    let effective_t_for_decomposition = t >> msbs_zero_padding_bit_count;

    let decoded_q = decode_q(q);

    let big_d = d
        + k * effective_t_for_decomposition.ilog2() as usize
        + (d + k) * (2 + b_i.ilog2() as usize + b_r.ilog2() as usize);

    if sanity_check_mode == ProofSanityCheckMode::Panic {
        assert_pke_proof_preconditions(a, b, c1, e1, c2, e2, d, k_max, big_d, big_d_max);
    }

    // FIXME: div_round
    let delta = {
        // delta takes the encoding with the padding bit
        (decoded_q / t as u128) as u64
    };

    let g = G::G1::GENERATOR;
    let g_hat = G::G2::GENERATOR;
    let mut gamma_list = [G::Zp::ZERO; 2];
    G::Zp::hash(&mut gamma_list, &[ds.hash_gamma(), seed]);
    let [gamma, gamma_y] = gamma_list;

    let r1 = compute_r1(e1, c1, a, r, d, decoded_q);
    let r2 = compute_r2(e2, c2, m, b, r, d, delta, decoded_q);

    let mut w = vec![false; n];

    let u64 = |x: i64| x as u64;

    w[..big_d]
        .iter_mut()
        .zip(
            r.iter()
                .rev()
                .flat_map(|&r| bit_iter(u64(r), 1))
                .chain(
                    m.iter()
                        .flat_map(|&m| bit_iter(u64(m), effective_t_for_decomposition.ilog2())),
                )
                .chain(e1.iter().flat_map(|&e1| bit_iter(u64(e1), 1 + b_i.ilog2())))
                .chain(e2.iter().flat_map(|&e2| bit_iter(u64(e2), 1 + b_i.ilog2())))
                .chain(r1.iter().flat_map(|&r1| bit_iter(u64(r1), 1 + b_r.ilog2())))
                .chain(r2.iter().flat_map(|&r2| bit_iter(u64(r2), 1 + b_r.ilog2()))),
        )
        .for_each(|(dst, src)| *dst = src);

    let w = OneBased(w);

    let mut c_hat = g_hat.mul_scalar(gamma);
    for j in 1..big_d + 1 {
        if w[j] {
            c_hat += G::G2::projective(g_hat_list[j]);
        }
    }

    let x_bytes = &*[
        q.to_le_bytes().as_slice(),
        (d as u64).to_le_bytes().as_slice(),
        b_i.to_le_bytes().as_slice(),
        t.to_le_bytes().as_slice(),
        msbs_zero_padding_bit_count.to_le_bytes().as_slice(),
        &*a.iter().flat_map(|&x| x.to_le_bytes()).collect::<Box<_>>(),
        &*b.iter().flat_map(|&x| x.to_le_bytes()).collect::<Box<_>>(),
        &*c1.iter().flat_map(|&x| x.to_le_bytes()).collect::<Box<_>>(),
        &*c2.iter().flat_map(|&x| x.to_le_bytes()).collect::<Box<_>>(),
    ]
    .iter()
    .copied()
    .flatten()
    .copied()
    .collect::<Box<_>>();

    let mut y = vec![G::Zp::ZERO; n];
    G::Zp::hash(
        &mut y,
        &[
            ds.hash(),
            sid.to_le_bytes().as_slice(),
            metadata,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
        ],
    );
    let y = OneBased(y);

    let scalars = (n + 1 - big_d..n + 1)
        .map(|j| y[n + 1 - j] * G::Zp::from_u64(w[n + 1 - j] as u64))
        .collect::<Vec<_>>();
    let c_y = g.mul_scalar(gamma_y) + G::G1::multi_mul_scalar(&g_list.0[n - big_d..n], &scalars);

    let mut theta = vec![G::Zp::ZERO; d + k + 1];
    G::Zp::hash(
        &mut theta,
        &[
            ds.hash_lmap(),
            sid.to_le_bytes().as_slice(),
            metadata,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );

    let theta0 = &theta[..d + k];

    let delta_theta = theta[d + k];

    let mut a_theta = vec![G::Zp::ZERO; big_d];

    compute_a_theta::<G>(
        theta0,
        d,
        a,
        k,
        b,
        &mut a_theta,
        effective_t_for_decomposition,
        delta,
        b_i,
        b_r,
        decoded_q,
    );

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash_128bit(
        &mut t,
        &[
            ds.hash_t(),
            sid.to_le_bytes().as_slice(),
            metadata,
            &(1..n + 1)
                .flat_map(|i| y[i].to_le_bytes().as_ref().to_vec())
                .collect::<Box<_>>(),
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let t = OneBased(t);

    let mut delta = [G::Zp::ZERO; 2];
    G::Zp::hash(
        &mut delta,
        &[
            ds.hash_agg(),
            sid.to_le_bytes().as_slice(),
            metadata,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let [delta_eq, delta_y] = delta;
    let delta = [delta_eq, delta_y, delta_theta];

    let mut poly_0 = vec![G::Zp::ZERO; n + 1];
    let mut poly_1 = vec![G::Zp::ZERO; big_d + 1];
    let mut poly_2 = vec![G::Zp::ZERO; n + 1];
    let mut poly_3 = vec![G::Zp::ZERO; n + 1];

    poly_0[0] = delta_y * gamma_y;
    for i in 1..n + 1 {
        poly_0[n + 1 - i] =
            delta_y * (y[i] * G::Zp::from_u64(w[i] as u64)) + (delta_eq * t[i] - delta_y) * y[i];

        if i < big_d + 1 {
            poly_0[n + 1 - i] += delta_theta * a_theta[i - 1];
        }
    }

    poly_1[0] = gamma;
    for i in 1..big_d + 1 {
        poly_1[i] = G::Zp::from_u64(w[i] as u64);
    }

    poly_2[0] = gamma_y;
    for i in 1..big_d + 1 {
        poly_2[n + 1 - i] = y[i] * G::Zp::from_u64(w[i] as u64);
    }

    for i in 1..n + 1 {
        poly_3[i] = delta_eq * t[i];
    }

    let mut t_theta = G::Zp::ZERO;
    for i in 0..d {
        t_theta += theta0[i] * G::Zp::from_i64(c1[i]);
    }
    for i in 0..k {
        t_theta += theta0[d + i] * G::Zp::from_i64(c2[i]);
    }

    let mul = rayon::join(
        || G::Zp::poly_mul(&poly_0, &poly_1),
        || G::Zp::poly_mul(&poly_2, &poly_3),
    );
    let mut poly = G::Zp::poly_sub(&mul.0, &mul.1);
    if poly.len() > n + 1 {
        poly[n + 1] -= t_theta * delta_theta;
    }

    let pi =
        g.mul_scalar(poly[0]) + G::G1::multi_mul_scalar(&g_list.0[..poly.len() - 1], &poly[1..]);

    if load == ComputeLoad::Proof {
        let c_hat_t = G::G2::multi_mul_scalar(&g_hat_list.0, &t.0);
        let scalars = (1..n + 1)
            .map(|i| {
                let i = n + 1 - i;
                (delta_eq * t[i] - delta_y) * y[i]
                    + if i < big_d + 1 {
                        delta_theta * a_theta[i - 1]
                    } else {
                        G::Zp::ZERO
                    }
            })
            .collect::<Vec<_>>();

        let c_h = G::G1::multi_mul_scalar(&g_list.0[..n], &scalars);

        let mut z = G::Zp::ZERO;
        G::Zp::hash(
            core::array::from_mut(&mut z),
            &[
                ds.hash_z(),
                sid.to_le_bytes().as_slice(),
                metadata,
                x_bytes,
                c_hat.to_le_bytes().as_ref(),
                c_y.to_le_bytes().as_ref(),
                pi.to_le_bytes().as_ref(),
                c_h.to_le_bytes().as_ref(),
                c_hat_t.to_le_bytes().as_ref(),
                &y.0.iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &t.0.iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &delta
                    .iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
            ],
        );

        let mut pow = z;
        let mut p_t = G::Zp::ZERO;
        let mut p_h = G::Zp::ZERO;

        for i in 1..n + 1 {
            p_t += t[i] * pow;
            if n - i < big_d {
                p_h += ((delta_eq * t[n + 1 - i] - delta_y) * y[n + 1 - i]
                    + delta_theta * a_theta[n - i])
                    * pow;
            } else {
                p_h += ((delta_eq * t[n + 1 - i] - delta_y) * y[n + 1 - i]) * pow;
            }
            pow = pow * z;
        }

        let mut w = G::Zp::ZERO;
        G::Zp::hash(
            core::array::from_mut(&mut w),
            &[
                ds.hash_w(),
                sid.to_le_bytes().as_slice(),
                metadata,
                x_bytes,
                c_hat.to_le_bytes().as_ref(),
                c_y.to_le_bytes().as_ref(),
                pi.to_le_bytes().as_ref(),
                c_h.to_le_bytes().as_ref(),
                c_hat_t.to_le_bytes().as_ref(),
                &y.0.iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &t.0.iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &delta
                    .iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                z.to_le_bytes().as_ref(),
                p_h.to_le_bytes().as_ref(),
                p_t.to_le_bytes().as_ref(),
            ],
        );

        let mut poly = vec![G::Zp::ZERO; n + 1];
        for i in 1..n + 1 {
            poly[i] += w * t[i];
            if i < big_d + 1 {
                poly[n + 1 - i] +=
                    (delta_eq * t[i] - delta_y) * y[i] + delta_theta * a_theta[i - 1];
            } else {
                poly[n + 1 - i] += (delta_eq * t[i] - delta_y) * y[i];
            }
        }

        let mut q = vec![G::Zp::ZERO; n];
        // https://en.wikipedia.org/wiki/Polynomial_long_division#Pseudocode
        for i in (0..n).rev() {
            poly[i] = poly[i] + z * poly[i + 1];
            q[i] = poly[i + 1];
            poly[i + 1] = G::Zp::ZERO;
        }
        let pi_kzg = g.mul_scalar(q[0]) + G::G1::multi_mul_scalar(&g_list.0[..n - 1], &q[1..n]);

        Proof {
            c_hat,
            c_y,
            pi,
            compute_load_proof_fields: Some(ComputeLoadProofFields {
                c_hat_t,
                c_h,
                pi_kzg,
            }),
        }
    } else {
        Proof {
            c_hat,
            c_y,
            pi,
            compute_load_proof_fields: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_a_theta<G: Curve>(
    theta0: &[G::Zp],
    d: usize,
    a: &[i64],
    k: usize,
    b: &[i64],
    a_theta: &mut [G::Zp],
    t: u64,
    delta: u64,
    b_i: u64,
    b_r: u64,
    decoded_q: u128,
) {
    // a_theta = Ã.T theta0
    //  = [
    //    rot(a).T theta1 + phi[d](bar(b)) theta2_1 + ... + phi[d-k+1](bar(b)) theta2_k
    //
    //    delta g[log t].T theta2_1
    //    delta g[log t].T theta2_2
    //    ...
    //    delta g[log t].T theta2_k
    //
    //    G[1 + log B].T theta1
    //
    //    g[1 + log B].T theta2_1
    //    g[1 + log B].T theta2_2
    //    ...
    //    g[1 + log B].T theta2_k
    //
    //    -q G[1 + log Br].T theta1
    //
    //    -q g[1 + log Br].T theta2_1
    //    -q g[1 + log Br].T theta2_2
    //    ...
    //    -q g[1 + log Br].T theta2_k
    //    ]

    let q = G::Zp::from_u128(decoded_q);

    let theta1 = &theta0[..d];
    let theta2 = &theta0[d..];

    let a = a.iter().map(|x| G::Zp::from_i64(*x)).collect::<Vec<_>>();
    let b = b.iter().map(|x| G::Zp::from_i64(*x)).collect::<Vec<_>>();

    {
        let a_theta = &mut a_theta[..d];
        a_theta
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, a_theta_i)| {
                let mut dot = G::Zp::ZERO;

                for j in 0..d {
                    if i <= j {
                        dot += a[j - i] * theta1[j];
                    } else {
                        dot -= a[(d + j) - i] * theta1[j];
                    }
                }

                for j in 0..k {
                    if i + j < d {
                        dot += b[d - i - j - 1] * theta2[j];
                    } else {
                        dot -= b[2 * d - i - j - 1] * theta2[j];
                    };
                }
                *a_theta_i = dot;
            });
    }

    let a_theta = &mut a_theta[d..];

    let step = t.ilog2() as usize;
    for i in 0..k {
        for j in 0..step {
            let pow2 = G::Zp::from_u64(delta) * G::Zp::from_u64(1 << j) * theta2[i];
            a_theta[step * i + j] = pow2;
        }
    }
    let a_theta = &mut a_theta[k * step..];

    let step = 1 + b_i.ilog2() as usize;
    for i in 0..d {
        for j in 0..step {
            let pow2 = G::Zp::from_u64(1 << j) * theta1[i];
            a_theta[step * i + j] = if j == step - 1 { -pow2 } else { pow2 };
        }
    }
    let a_theta = &mut a_theta[d * step..];
    for i in 0..k {
        for j in 0..step {
            let pow2 = G::Zp::from_u64(1 << j) * theta2[i];
            a_theta[step * i + j] = if j == step - 1 { -pow2 } else { pow2 };
        }
    }
    let a_theta = &mut a_theta[k * step..];

    let step = 1 + b_r.ilog2() as usize;
    for i in 0..d {
        for j in 0..step {
            let pow2 = -q * G::Zp::from_u64(1 << j) * theta1[i];
            a_theta[step * i + j] = if j == step - 1 { -pow2 } else { pow2 };
        }
    }
    let a_theta = &mut a_theta[d * step..];
    for i in 0..k {
        for j in 0..step {
            let pow2 = -q * G::Zp::from_u64(1 << j) * theta2[i];
            a_theta[step * i + j] = if j == step - 1 { -pow2 } else { pow2 };
        }
    }
}

#[allow(clippy::result_unit_err)]
pub fn verify<G: Curve>(
    proof: &Proof<G>,
    public: (&PublicParams<G>, &PublicCommit<G>),
    metadata: &[u8],
) -> Result<(), ()> {
    let &Proof {
        c_hat,
        c_y,
        pi,
        ref compute_load_proof_fields,
    } = proof;

    let e = G::Gt::pairing;

    let &PublicParams {
        ref g_lists,
        big_d: big_d_max,
        n,
        d,
        b,
        b_r,
        q,
        t,
        msbs_zero_padding_bit_count,
        k: k_max,
        sid,
        domain_separators: ref ds,
    } = public.0;
    let g_list = &g_lists.g_list;
    let g_hat_list = &g_lists.g_hat_list;

    let b_i = b;

    let decoded_q = decode_q(q);

    // FIXME: div_round
    let delta = {
        // delta takes the encoding with the padding bit
        (decoded_q / t as u128) as u64
    };

    let PublicCommit { a, b, c1, c2, .. } = public.1;
    let k = c2.len();
    if k > k_max {
        return Err(());
    }

    if a.len() != d || b.len() != d {
        return Err(());
    }

    let effective_t_for_decomposition = t >> msbs_zero_padding_bit_count;

    let big_d = d
        + k * effective_t_for_decomposition.ilog2() as usize
        + (d + k) * (2 + b_i.ilog2() as usize + b_r.ilog2() as usize);
    if big_d > big_d_max {
        return Err(());
    }

    let x_bytes = &*[
        q.to_le_bytes().as_slice(),
        (d as u64).to_le_bytes().as_slice(),
        b_i.to_le_bytes().as_slice(),
        t.to_le_bytes().as_slice(),
        msbs_zero_padding_bit_count.to_le_bytes().as_slice(),
        &*a.iter().flat_map(|&x| x.to_le_bytes()).collect::<Box<_>>(),
        &*b.iter().flat_map(|&x| x.to_le_bytes()).collect::<Box<_>>(),
        &*c1.iter().flat_map(|&x| x.to_le_bytes()).collect::<Box<_>>(),
        &*c2.iter().flat_map(|&x| x.to_le_bytes()).collect::<Box<_>>(),
    ]
    .iter()
    .copied()
    .flatten()
    .copied()
    .collect::<Box<_>>();

    let mut y = vec![G::Zp::ZERO; n];
    G::Zp::hash(
        &mut y,
        &[
            ds.hash(),
            sid.to_le_bytes().as_slice(),
            metadata,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
        ],
    );
    let y = OneBased(y);

    let mut theta = vec![G::Zp::ZERO; d + k + 1];
    G::Zp::hash(
        &mut theta,
        &[
            ds.hash_lmap(),
            sid.to_le_bytes().as_slice(),
            metadata,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let theta0 = &theta[..d + k];
    let delta_theta = theta[d + k];

    let mut a_theta = vec![G::Zp::ZERO; big_d];
    compute_a_theta::<G>(
        theta0,
        d,
        a,
        k,
        b,
        &mut a_theta,
        effective_t_for_decomposition,
        delta,
        b_i,
        b_r,
        decoded_q,
    );

    let mut t_theta = G::Zp::ZERO;
    for i in 0..d {
        t_theta += theta0[i] * G::Zp::from_i64(c1[i]);
    }
    for i in 0..k {
        t_theta += theta0[d + i] * G::Zp::from_i64(c2[i]);
    }

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash_128bit(
        &mut t,
        &[
            ds.hash_t(),
            sid.to_le_bytes().as_slice(),
            metadata,
            &(1..n + 1)
                .flat_map(|i| y[i].to_le_bytes().as_ref().to_vec())
                .collect::<Box<_>>(),
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let t = OneBased(t);

    let mut delta = [G::Zp::ZERO; 2];
    G::Zp::hash(
        &mut delta,
        &[
            ds.hash_agg(),
            sid.to_le_bytes().as_slice(),
            metadata,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let [delta_eq, delta_y] = delta;
    let delta = [delta_eq, delta_y, delta_theta];

    if let Some(&ComputeLoadProofFields {
        c_hat_t,
        c_h,
        pi_kzg,
    }) = compute_load_proof_fields.as_ref()
    {
        let mut z = G::Zp::ZERO;
        G::Zp::hash(
            core::array::from_mut(&mut z),
            &[
                ds.hash_z(),
                sid.to_le_bytes().as_slice(),
                metadata,
                x_bytes,
                c_hat.to_le_bytes().as_ref(),
                c_y.to_le_bytes().as_ref(),
                pi.to_le_bytes().as_ref(),
                c_h.to_le_bytes().as_ref(),
                c_hat_t.to_le_bytes().as_ref(),
                &y.0.iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &t.0.iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &delta
                    .iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
            ],
        );

        let mut pow = z;
        let mut p_t = G::Zp::ZERO;
        let mut p_h = G::Zp::ZERO;

        for i in 1..n + 1 {
            p_t += t[i] * pow;
            if n - i < big_d {
                p_h += ((delta_eq * t[n + 1 - i] - delta_y) * y[n + 1 - i]
                    + delta_theta * a_theta[n - i])
                    * pow;
            } else {
                p_h += ((delta_eq * t[n + 1 - i] - delta_y) * y[n + 1 - i]) * pow;
            }
            pow = pow * z;
        }

        if e(pi, G::G2::GENERATOR)
            != e(c_y.mul_scalar(delta_y) + c_h, c_hat)
                - e(c_y.mul_scalar(delta_eq), c_hat_t)
                - e(
                    G::G1::projective(g_list[1]),
                    G::G2::projective(g_hat_list[n]),
                )
                .mul_scalar(t_theta * delta_theta)
        {
            return Err(());
        }

        let mut w = G::Zp::ZERO;
        G::Zp::hash(
            core::array::from_mut(&mut w),
            &[
                ds.hash_w(),
                sid.to_le_bytes().as_slice(),
                metadata,
                x_bytes,
                c_hat.to_le_bytes().as_ref(),
                c_y.to_le_bytes().as_ref(),
                pi.to_le_bytes().as_ref(),
                c_h.to_le_bytes().as_ref(),
                c_hat_t.to_le_bytes().as_ref(),
                &y.0.iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &t.0.iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &delta
                    .iter()
                    .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                z.to_le_bytes().as_ref(),
                p_h.to_le_bytes().as_ref(),
                p_t.to_le_bytes().as_ref(),
            ],
        );

        if e(c_h - G::G1::GENERATOR.mul_scalar(p_h), G::G2::GENERATOR)
            + e(G::G1::GENERATOR, c_hat_t - G::G2::GENERATOR.mul_scalar(p_t)).mul_scalar(w)
            == e(
                pi_kzg,
                G::G2::projective(g_hat_list[1]) - G::G2::GENERATOR.mul_scalar(z),
            )
        {
            Ok(())
        } else {
            Err(())
        }
    } else {
        // PERF: rewrite as multi_mul_scalar?
        let (term0, term1) = rayon::join(
            || {
                let p = c_y.mul_scalar(delta_y)
                    + (1..n + 1)
                        .into_par_iter()
                        .map(|i| {
                            let mut factor = (delta_eq * t[i] - delta_y) * y[i];
                            if i < big_d + 1 {
                                factor += delta_theta * a_theta[i - 1];
                            }
                            G::G1::projective(g_list[n + 1 - i]).mul_scalar(factor)
                        })
                        .sum::<G::G1>();
                let q = c_hat;
                e(p, q)
            },
            || {
                let p = c_y;
                let q = (1..n + 1)
                    .into_par_iter()
                    .map(|i| G::G2::projective(g_hat_list[i]).mul_scalar(delta_eq * t[i]))
                    .sum::<G::G2>();
                e(p, q)
            },
        );
        let term2 = {
            let p = G::G1::projective(g_list[1]);
            let q = G::G2::projective(g_hat_list[n]);
            e(p, q)
        };

        let lhs = e(pi, G::G2::GENERATOR);
        let rhs = term0 - term1 - term2.mul_scalar(t_theta * delta_theta);

        if lhs == rhs {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::curve_api::{self, bls12_446};

    use super::super::test::*;
    use super::*;
    use rand::rngs::StdRng;
    use rand::{thread_rng, Rng, SeedableRng};

    type Curve = curve_api::Bls12_446;

    /// Compact key params used with pkev1
    pub(crate) const PKEV1_TEST_PARAMS: PkeTestParameters = PkeTestParameters {
        d: 1024,
        k: 320,
        B: 4398046511104, // 2**42
        q: 0,
        t: 32, // 2b msg, 2b carry, 1b padding
        msbs_zero_padding_bit_count: 1,
    };

    /// Compact key params used with pkve1 to encrypt a single message
    pub(super) const PKEV1_TEST_PARAMS_SINGLE: PkeTestParameters = PkeTestParameters {
        d: 1024,
        k: 1,
        B: 4398046511104, // 2**42
        q: 0,
        t: 32, // 2b msg, 2b carry, 1b padding
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
        } = PKEV1_TEST_PARAMS;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

        let seed = thread_rng().gen();
        println!("pke seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV1_TEST_PARAMS);

        let ct = testcase.encrypt(PKEV1_TEST_PARAMS);

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
            use_fake_e1,
            use_fake_e2,
            use_fake_m,
            use_fake_r,
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
                    &seed.to_be_bytes(),
                );

                let verify_metadata = if use_fake_metadata_verify {
                    &fake_metadata
                } else {
                    &testcase.metadata
                };

                assert_eq!(
                    verify(&proof, (&public_param, &public_commit), verify_metadata).is_err(),
                    use_fake_e1
                        || use_fake_e2
                        || use_fake_r
                        || use_fake_m
                        || use_fake_metadata_verify
                );
            }
        }
    }

    fn prove_and_verify(
        testcase: &PkeTestcase,
        ct: &PkeTestCiphertext,
        crs: &PublicParams<Curve>,
        load: ComputeLoad,
        seed: &[u8],
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
            sanity_check_mode,
        );

        if verify(&proof, (crs, &public_commit), &testcase.metadata).is_ok() {
            VerificationResult::Accept
        } else {
            VerificationResult::Reject
        }
    }

    fn assert_prove_and_verify(
        testcase: &PkeTestcase,
        ct: &PkeTestCiphertext,
        testcase_name: &str,
        crs: &PublicParams<Curve>,
        seed: &[u8],
        sanity_check_mode: ProofSanityCheckMode,
        expected_result: VerificationResult,
    ) {
        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            assert_eq!(
                prove_and_verify(testcase, ct, crs, load, seed, sanity_check_mode),
                expected_result,
                "Testcase {testcase_name} failed"
            )
        }
    }

    /// Test that the proof is rejected if we use a noise outside of the bounds
    #[test]
    fn test_pke_bad_noise() {
        let PkeTestParameters {
            d,
            k,
            B,
            q,
            t,
            msbs_zero_padding_bit_count,
        } = PKEV1_TEST_PARAMS;

        let seed = thread_rng().gen();
        println!("pke_bad_noise seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV1_TEST_PARAMS);

        // A CRS where the number of slots = the number of messages to encrypt
        let crs = crs_gen::<Curve>(d, k, B, q, t, msbs_zero_padding_bit_count, rng);

        // A CRS where the number of slots is bigger than the number of messages to encrypt
        let big_crs_k = k + 1 + (rng.gen::<usize>() % (d - k));
        let crs_bigger_k =
            crs_gen::<Curve>(d, big_crs_k, B, q, t, msbs_zero_padding_bit_count, rng);

        // ==== Generate test noise vectors with random coeffs and one completely out of bounds ===
        let mut testcase_bad_e1 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % d;
        // Generate a value between B + 1 and i64::MAX to make sure that it is out of bounds
        let bad_term = (rng.gen::<u64>() % (i64::MAX as u64 - (B + 1))) + (B + 1);
        let bad_term = bad_term as i64;

        testcase_bad_e1.e1[bad_idx] = if rng.gen() { bad_term } else { -bad_term };

        let mut testcase_bad_e2 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % k;

        testcase_bad_e2.e2[bad_idx] = if rng.gen() { bad_term } else { -bad_term };

        // ==== Generate test noise vectors with random coeffs and one just around the bound  ===

        // Check slightly out of bound noise
        let bad_term = (B + 1) as i64;

        let mut testcase_after_bound_e1 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % d;

        testcase_after_bound_e1.e1[bad_idx] = if rng.gen() { bad_term } else { -bad_term };

        let mut testcase_after_bound_e2 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % k;

        testcase_after_bound_e2.e2[bad_idx] = if rng.gen() { bad_term } else { -bad_term };

        // Check noise right on the bound
        let bad_term = B as i64;

        let mut testcase_on_bound_positive_e1 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % d;

        testcase_on_bound_positive_e1.e1[bad_idx] = bad_term;

        let mut testcase_on_bound_positive_e2 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % k;

        testcase_on_bound_positive_e2.e2[bad_idx] = bad_term;

        let mut testcase_on_bound_negative_e1 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % d;

        testcase_on_bound_negative_e1.e1[bad_idx] = -bad_term;

        let mut testcase_on_bound_negative_e2 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % k;

        testcase_on_bound_negative_e2.e2[bad_idx] = -bad_term;

        // Check just before the limit
        let bad_term = (B - 1) as i64;

        let mut testcase_before_bound_e1 = testcase.clone();
        let bad_idx = rng.gen::<usize>() % d;

        testcase_before_bound_e1.e1[bad_idx] = if rng.gen() { bad_term } else { -bad_term };

        let mut testcase_before_bound_e2 = testcase;
        let bad_idx = rng.gen::<usize>() % k;

        testcase_before_bound_e2.e2[bad_idx] = if rng.gen() { bad_term } else { -bad_term };

        for (testcase, name, expected_result) in [
            (
                testcase_bad_e1,
                stringify!(testcase_bad_e1),
                VerificationResult::Reject,
            ),
            (
                testcase_bad_e2,
                stringify!(testcase_bad_e2),
                VerificationResult::Reject,
            ),
            (
                testcase_after_bound_e1,
                stringify!(testcase_after_bound_e1),
                VerificationResult::Reject,
            ),
            (
                testcase_after_bound_e2,
                stringify!(testcase_after_bound_e2),
                VerificationResult::Reject,
            ),
            // Upper bound is refused and lower bound is accepted
            (
                testcase_on_bound_positive_e1,
                stringify!(testcase_on_bound_positive_e1),
                VerificationResult::Reject,
            ),
            (
                testcase_on_bound_positive_e2,
                stringify!(testcase_on_bound_positive_e2),
                VerificationResult::Reject,
            ),
            (
                testcase_on_bound_negative_e1,
                stringify!(testcase_on_bound_negative_e1),
                VerificationResult::Accept,
            ),
            (
                testcase_on_bound_negative_e2,
                stringify!(testcase_on_bound_negative_e2),
                VerificationResult::Accept,
            ),
            (
                testcase_before_bound_e1,
                stringify!(testcase_before_bound_e1),
                VerificationResult::Accept,
            ),
            (
                testcase_before_bound_e2,
                stringify!(testcase_before_bound_e2),
                VerificationResult::Accept,
            ),
        ] {
            let ct = testcase.encrypt_unchecked(PKEV1_TEST_PARAMS);
            assert_prove_and_verify(
                &testcase,
                &ct,
                name,
                &crs,
                &seed.to_le_bytes(),
                ProofSanityCheckMode::Ignore,
                expected_result,
            );
            assert_prove_and_verify(
                &testcase,
                &ct,
                name,
                &crs_bigger_k,
                &seed.to_le_bytes(),
                ProofSanityCheckMode::Ignore,
                expected_result,
            );
        }
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
        } = PKEV1_TEST_PARAMS;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

        let seed = thread_rng().gen();
        println!("pke_w_padding_fail_verify seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let mut testcase = PkeTestcase::gen(rng, PKEV1_TEST_PARAMS);

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

        let ct = testcase.encrypt(PKEV1_TEST_PARAMS);

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
        } = PKEV1_TEST_PARAMS;

        let seed = thread_rng().gen();
        println!("pke_wrong_pk_size seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV1_TEST_PARAMS);

        let ct = testcase.encrypt(PKEV1_TEST_PARAMS);
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
                assert!(verify(&proof, (&crs, &public_commit), &testcase.metadata).is_err())
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
        } = PKEV1_TEST_PARAMS;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

        let seed = thread_rng().gen();
        println!("pke_bad_ct seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV1_TEST_PARAMS_SINGLE);
        let ct = testcase.encrypt(PKEV1_TEST_PARAMS_SINGLE);

        let ct_zero = testcase.sk_encrypt_zero(PKEV1_TEST_PARAMS_SINGLE, rng);

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

        let m_plus_zero = testcase.decrypt(&ct_plus_zero, PKEV1_TEST_PARAMS_SINGLE);
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

        let m_plus_trivial = testcase.decrypt(&ct_plus_trivial, PKEV1_TEST_PARAMS_SINGLE);
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

            assert!(verify(
                &proof,
                (&crs, &public_commit_verify_zero),
                &testcase.metadata
            )
            .is_err());

            assert!(verify(
                &proof,
                (&crs, &public_commit_verify_trivial),
                &testcase.metadata
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
        } = PKEV1_TEST_PARAMS;

        let effective_cleartext_t = t >> msbs_zero_padding_bit_count;

        let seed = thread_rng().gen();
        println!("pke_bad_delta seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV1_TEST_PARAMS);
        let mut testcase_bad_delta = testcase.clone();

        // Make sure that the messages lower bit is set so the change of delta has an impact on the
        // validity of the ct
        testcase_bad_delta.m = (0..k)
            .map(|_| (rng.gen::<u64>() % effective_cleartext_t) as i64 | 1)
            .collect::<Vec<_>>();

        let mut params_bad_delta = PKEV1_TEST_PARAMS;
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
            ProofSanityCheckMode::Panic,
            VerificationResult::Reject,
        );
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
        } = PKEV1_TEST_PARAMS;

        let seed = thread_rng().gen();
        println!("pke_proof_compression seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV1_TEST_PARAMS);
        let ct = testcase.encrypt(PKEV1_TEST_PARAMS);

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

            let compressed_proof = bincode::serialize(&proof.clone().compress()).unwrap();
            let proof =
                Proof::uncompress(bincode::deserialize(&compressed_proof).unwrap()).unwrap();

            verify(&proof, (&public_param, &public_commit), &testcase.metadata).unwrap()
        }
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
        } = PKEV1_TEST_PARAMS;

        let seed = thread_rng().gen();
        println!("pke_proof_usable seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let testcase = PkeTestcase::gen(rng, PKEV1_TEST_PARAMS);
        let ct = testcase.encrypt(PKEV1_TEST_PARAMS);

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
                proof.c_hat = not_on_curve_g2;
                assert!(!proof.is_usable());
                proof.c_hat = not_in_group_g2;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.c_y = not_on_curve_g1;
                assert!(!proof.is_usable());
                proof.c_y = not_in_group_g1;
                assert!(!proof.is_usable());
            }

            {
                let mut proof = valid_proof.clone();
                proof.pi = not_on_curve_g1;
                assert!(!proof.is_usable());
                proof.pi = not_in_group_g1;
                assert!(!proof.is_usable());
            }

            if let Some(ref valid_compute_proof_fields) = valid_proof.compute_load_proof_fields {
                {
                    let mut proof = valid_proof.clone();
                    proof.compute_load_proof_fields = Some(ComputeLoadProofFields {
                        c_hat_t: not_on_curve_g2,
                        ..valid_compute_proof_fields.clone()
                    });

                    assert!(!proof.is_usable());
                    proof.compute_load_proof_fields = Some(ComputeLoadProofFields {
                        c_hat_t: not_in_group_g2,
                        ..valid_compute_proof_fields.clone()
                    });

                    assert!(!proof.is_usable());
                }

                {
                    let mut proof = valid_proof.clone();
                    proof.compute_load_proof_fields = Some(ComputeLoadProofFields {
                        c_h: not_on_curve_g1,
                        ..valid_compute_proof_fields.clone()
                    });

                    assert!(!proof.is_usable());

                    proof.compute_load_proof_fields = Some(ComputeLoadProofFields {
                        c_h: not_in_group_g1,
                        ..valid_compute_proof_fields.clone()
                    });

                    assert!(!proof.is_usable());
                }

                {
                    let mut proof = valid_proof.clone();
                    proof.compute_load_proof_fields = Some(ComputeLoadProofFields {
                        pi_kzg: not_on_curve_g1,
                        ..valid_compute_proof_fields.clone()
                    });

                    assert!(!proof.is_usable());
                    proof.compute_load_proof_fields = Some(ComputeLoadProofFields {
                        pi_kzg: not_in_group_g1,
                        ..valid_compute_proof_fields.clone()
                    });

                    assert!(!proof.is_usable());
                }
            }
        }
    }
}
