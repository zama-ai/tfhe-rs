// TODO: refactor copy-pasted code in proof/verify

use crate::backward_compatibility::{PKEv1CompressedProofVersions, PKEv1ProofVersions};
use crate::serialization::{
    try_vec_to_array, InvalidSerializedAffineError, InvalidSerializedPublicParamsError,
    SerializableGroupElements, SerializablePKEv1PublicParams,
};

use super::*;
use core::marker::PhantomData;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

fn bit_iter(x: u64, nbits: u32) -> impl Iterator<Item = bool> {
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
    pub(crate) hash: [u8; HASH_METADATA_LEN_BYTES],
    pub(crate) hash_t: [u8; HASH_METADATA_LEN_BYTES],
    pub(crate) hash_agg: [u8; HASH_METADATA_LEN_BYTES],
    pub(crate) hash_lmap: [u8; HASH_METADATA_LEN_BYTES],
    pub(crate) hash_z: [u8; HASH_METADATA_LEN_BYTES],
    pub(crate) hash_w: [u8; HASH_METADATA_LEN_BYTES],
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
            hash,
            hash_t,
            hash_agg,
            hash_lmap,
            hash_z,
            hash_w,
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
            hash: hash.to_vec(),
            hash_t: hash_t.to_vec(),
            hash_agg: hash_agg.to_vec(),
            hash_lmap: hash_lmap.to_vec(),
            hash_z: hash_z.to_vec(),
            hash_w: hash_w.to_vec(),
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
            hash,
            hash_t,
            hash_agg,
            hash_lmap,
            hash_z,
            hash_w,
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
            hash: try_vec_to_array(hash)?,
            hash_t: try_vec_to_array(hash_t)?,
            hash_agg: try_vec_to_array(hash_agg)?,
            hash_lmap: try_vec_to_array(hash_lmap)?,
            hash_z: try_vec_to_array(hash_z)?,
            hash_w: try_vec_to_array(hash_w)?,
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
        hash: [u8; HASH_METADATA_LEN_BYTES],
        hash_t: [u8; HASH_METADATA_LEN_BYTES],
        hash_agg: [u8; HASH_METADATA_LEN_BYTES],
        hash_lmap: [u8; HASH_METADATA_LEN_BYTES],
        hash_z: [u8; HASH_METADATA_LEN_BYTES],
        hash_w: [u8; HASH_METADATA_LEN_BYTES],
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
            hash,
            hash_t,
            hash_agg,
            hash_lmap,
            hash_z,
            hash_w,
        }
    }

    pub fn exclusive_max_noise(&self) -> u64 {
        self.b
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(
    deserialize = "G: Curve, G::G1: serde::Deserialize<'de>, G::G2: serde::Deserialize<'de>",
    serialize = "G: Curve, G::G1: serde::Serialize, G::G2: serde::Serialize"
))]
#[versionize(PKEv1ProofVersions)]
pub struct Proof<G: Curve> {
    c_hat: G::G2,
    c_y: G::G1,
    pi: G::G1,
    c_hat_t: Option<G::G2>,
    c_h: Option<G::G1>,
    pi_kzg: Option<G::G1>,
}

type CompressedG2<G> = <<G as Curve>::G2 as Compressible>::Compressed;
type CompressedG1<G> = <<G as Curve>::G1 as Compressible>::Compressed;

#[derive(Serialize, Deserialize, Versionize)]
#[serde(bound(
    deserialize = "G: Curve, CompressedG1<G>: serde::Deserialize<'de>, CompressedG2<G>: serde::Deserialize<'de>",
    serialize = "G: Curve, CompressedG1<G>: serde::Serialize, CompressedG2<G>: serde::Serialize"
))]
#[versionize(PKEv1CompressedProofVersions)]
pub struct CompressedProof<G: Curve>
where
    G::G1: Compressible,
    G::G2: Compressible,
{
    c_hat: CompressedG2<G>,
    c_y: CompressedG1<G>,
    pi: CompressedG1<G>,
    c_hat_t: Option<CompressedG2<G>>,
    c_h: Option<CompressedG1<G>>,
    pi_kzg: Option<CompressedG1<G>>,
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
            c_hat_t,
            c_h,
            pi_kzg,
        } = self;

        CompressedProof {
            c_hat: c_hat.compress(),
            c_y: c_y.compress(),
            pi: pi.compress(),
            c_hat_t: c_hat_t.map(|val| val.compress()),
            c_h: c_h.map(|val| val.compress()),
            pi_kzg: pi_kzg.map(|val| val.compress()),
        }
    }

    fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
        let CompressedProof {
            c_hat,
            c_y,
            pi,
            c_hat_t,
            c_h,
            pi_kzg,
        } = compressed;

        Ok(Proof {
            c_hat: G::G2::uncompress(c_hat)?,
            c_y: G::G1::uncompress(c_y)?,
            pi: G::G1::uncompress(pi)?,
            c_hat_t: c_hat_t.map(G::G2::uncompress).transpose()?,
            c_h: c_h.map(G::G1::uncompress).transpose()?,
            pi_kzg: pi_kzg.map(G::G1::uncompress).transpose()?,
        })
    }
}

impl<G: Curve> Proof<G> {
    pub fn content_is_usable(&self) -> bool {
        matches!(
            (self.c_hat_t, self.c_h, self.pi_kzg),
            (None, None, None) | (Some(_), Some(_), Some(_))
        )
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PublicCommit<G: Curve> {
    a: Vec<i64>,
    b: Vec<i64>,
    c1: Vec<i64>,
    c2: Vec<i64>,
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
    r: Vec<i64>,
    e1: Vec<i64>,
    m: Vec<i64>,
    e2: Vec<i64>,
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
        hash: core::array::from_fn(|_| rng.gen()),
        hash_t: core::array::from_fn(|_| rng.gen()),
        hash_agg: core::array::from_fn(|_| rng.gen()),
        hash_lmap: core::array::from_fn(|_| rng.gen()),
        hash_z: core::array::from_fn(|_| rng.gen()),
        hash_w: core::array::from_fn(|_| rng.gen()),
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
    rng: &mut dyn RngCore,
) -> (PublicCommit<G>, PrivateCommit<G>) {
    let _ = (public, rng);
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
    rng: &mut dyn RngCore,
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
        ref hash,
        ref hash_t,
        ref hash_agg,
        ref hash_lmap,
        ref hash_z,
        ref hash_w,
    } = public.0;
    let g_list = &g_lists.g_list;
    let g_hat_list = &g_lists.g_hat_list;

    let b_i = b;

    let PublicCommit { a, b, c1, c2, .. } = public.1;
    let PrivateCommit { r, e1, m, e2, .. } = private_commit;

    let k = c2.len();
    assert!(k <= k_max);

    let effective_t_for_decomposition = t >> msbs_zero_padding_bit_count;

    let big_d = d
        + k * effective_t_for_decomposition.ilog2() as usize
        + (d + k) * (2 + b_i.ilog2() as usize + b_r.ilog2() as usize);
    assert!(big_d <= big_d_max);

    // FIXME: div_round
    let delta = {
        let q = if q == 0 { 1i128 << 64 } else { q as i128 };
        // delta takes the encoding with the padding bit
        (q / t as i128) as u64
    };

    let g = G::G1::GENERATOR;
    let g_hat = G::G2::GENERATOR;
    let gamma = G::Zp::rand(rng);
    let gamma_y = G::Zp::rand(rng);

    // rot(a) phi(r)   + phi(e1) - q phi(r1) = phi(c1)
    // phi[d - i + 1](bar(b)).T phi(r) + delta m_i + e2_i - q r2_i = c2

    // phi(r1) = (rot(a) phi(r) + phi(e1) - phi(c1)) / q
    // r2_i    = (phi[d - i + 1](bar(b)).T phi(r) + delta m_i + e2_i - c2) / q

    let mut r1 = e1
        .iter()
        .zip(c1.iter())
        .map(|(&e1, &c1)| e1 as i128 - c1 as i128)
        .collect::<Box<_>>();

    for i in 0..d {
        for j in 0..d {
            if i + j < d {
                r1[i + j] += a[i] as i128 * r[d - j - 1] as i128;
            } else {
                r1[i + j - d] -= a[i] as i128 * r[d - j - 1] as i128;
            }
        }
    }

    {
        let q = if q == 0 { 1i128 << 64 } else { q as i128 };
        for r1 in &mut *r1 {
            *r1 /= q;
        }
    }

    let mut r2 = m
        .iter()
        .zip(e2)
        .zip(c2)
        .map(|((&m, &e2), &c2)| delta as i128 * m as i128 + e2 as i128 - c2 as i128)
        .collect::<Box<_>>();

    {
        let q = if q == 0 { 1i128 << 64 } else { q as i128 };
        for (i, r2) in r2.iter_mut().enumerate() {
            let mut dot = 0i128;
            for j in 0..d {
                let b = if i + j < d {
                    b[d - j - i - 1] as i128
                } else {
                    -(b[2 * d - j - i - 1] as i128)
                };

                dot += r[d - j - 1] as i128 * b;
            }

            *r2 += dot;
            *r2 /= q;
        }
    }

    let r1 = r1
        .into_vec()
        .into_iter()
        .map(|r1| r1 as i64)
        .collect::<Box<_>>();

    let r2 = r2
        .into_vec()
        .into_iter()
        .map(|r2| r2 as i64)
        .collect::<Box<_>>();

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
        d.to_le_bytes().as_slice(),
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
        &[hash, metadata, x_bytes, c_hat.to_le_bytes().as_ref()],
    );
    let y = OneBased(y);

    let scalars = (n + 1 - big_d..n + 1)
        .map(|j| (y[n + 1 - j] * G::Zp::from_u64(w[n + 1 - j] as u64)))
        .collect::<Vec<_>>();
    let c_y = g.mul_scalar(gamma_y) + G::G1::multi_mul_scalar(&g_list.0[n - big_d..n], &scalars);

    let mut theta = vec![G::Zp::ZERO; d + k + 1];
    G::Zp::hash(
        &mut theta,
        &[
            hash_lmap,
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
        q,
    );

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash_128bit(
        &mut t,
        &[
            hash_t,
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
            hash_agg,
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
                hash_z,
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
                hash_w,
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
            c_hat_t: Some(c_hat_t),
            c_h: Some(c_h),
            pi_kzg: Some(pi_kzg),
        }
    } else {
        Proof {
            c_hat,
            c_y,
            pi,
            c_hat_t: None,
            c_h: None,
            pi_kzg: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_a_theta<G: Curve>(
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
    q: u64,
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

    let q = if q == 0 {
        G::Zp::from_u128(1u128 << 64)
    } else {
        G::Zp::from_u64(q)
    };

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
        c_hat_t,
        c_h,
        pi_kzg,
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
        ref hash,
        ref hash_t,
        ref hash_agg,
        ref hash_lmap,
        ref hash_z,
        ref hash_w,
    } = public.0;
    let g_list = &g_lists.g_list;
    let g_hat_list = &g_lists.g_hat_list;

    let b_i = b;

    // FIXME: div_round
    let delta = {
        let q = if q == 0 { 1i128 << 64 } else { q as i128 };
        // delta takes the encoding with the padding bit
        (q / t as i128) as u64
    };

    let PublicCommit { a, b, c1, c2, .. } = public.1;
    let k = c2.len();
    if k > k_max {
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
        d.to_le_bytes().as_slice(),
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
        &[hash, metadata, x_bytes, c_hat.to_le_bytes().as_ref()],
    );
    let y = OneBased(y);

    let mut theta = vec![G::Zp::ZERO; d + k + 1];
    G::Zp::hash(
        &mut theta,
        &[
            hash_lmap,
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
        q,
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
            hash_t,
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
            hash_agg,
            metadata,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let [delta_eq, delta_y] = delta;
    let delta = [delta_eq, delta_y, delta_theta];

    if let (Some(pi_kzg), Some(c_hat_t), Some(c_h)) = (pi_kzg, c_hat_t, c_h) {
        let mut z = G::Zp::ZERO;
        G::Zp::hash(
            core::array::from_mut(&mut z),
            &[
                hash_z,
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
                hash_w,
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
mod tests {
    use super::super::test::*;
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    /// Compact key params used with pkev1
    pub(super) const PKEV1_TEST_PARAMS: PkeTestParameters = PkeTestParameters {
        d: 1024,
        k: 320,
        B: 4398046511104, // 2**42
        q: 0,
        t: 32, // 2b msg, 2b carry, 1b padding
        msbs_zero_padding_bit_count: 1,
    };

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

        let rng = &mut StdRng::seed_from_u64(0);

        let PkeTestProofInputs {
            a,
            e1,
            e2,
            r,
            m,
            b,
            c1,
            c2,
            metadata,
        } = PkeTestProofInputs::gen(rng, PKEV1_TEST_PARAMS);

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

        type Curve = crate::curve_api::Bls12_446;

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
                a.clone(),
                b.clone(),
                c1.clone(),
                c2.clone(),
                if use_fake_r {
                    fake_r.clone()
                } else {
                    r.clone()
                },
                if use_fake_e1 {
                    fake_e1.clone()
                } else {
                    e1.clone()
                },
                if use_fake_m {
                    fake_m.clone()
                } else {
                    m.clone()
                },
                if use_fake_e2 {
                    fake_e2.clone()
                } else {
                    e2.clone()
                },
                &public_param,
                rng,
            );

            for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
                let proof = prove(
                    (&public_param, &public_commit),
                    &private_commit,
                    &metadata,
                    load,
                    rng,
                );

                let verify_metadata = if use_fake_metadata_verify {
                    &fake_metadata
                } else {
                    &metadata
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

        let rng = &mut StdRng::seed_from_u64(0);

        let PkeTestProofInputs {
            a,
            e1,
            e2,
            r,
            m: _m,
            b,
            c1,
            c2,
            metadata,
        } = PkeTestProofInputs::gen(rng, PKEV1_TEST_PARAMS);

        // Generate messages with padding set to fail verification
        let m = {
            let mut tmp = (0..k)
                .map(|_| (rng.gen::<u64>() % t) as i64)
                .collect::<Vec<_>>();
            while tmp.iter().all(|&x| (x as u64) < effective_cleartext_t) {
                tmp.fill_with(|| (rng.gen::<u64>() % t) as i64);
            }

            tmp
        };

        type Curve = crate::curve_api::Bls12_446;

        // To check management of bigger k_max from CRS during test
        let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

        let original_public_param =
            crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);
        let public_param_that_was_compressed =
            serialize_then_deserialize(&original_public_param, Compress::Yes).unwrap();
        let public_param_that_was_not_compressed =
            serialize_then_deserialize(&original_public_param, Compress::No).unwrap();

        for public_param in [
            original_public_param,
            public_param_that_was_compressed,
            public_param_that_was_not_compressed,
        ] {
            let (public_commit, private_commit) = commit(
                a.clone(),
                b.clone(),
                c1.clone(),
                c2.clone(),
                r.clone(),
                e1.clone(),
                m.clone(),
                e2.clone(),
                &public_param,
                rng,
            );

            for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
                let proof = prove(
                    (&public_param, &public_commit),
                    &private_commit,
                    &metadata,
                    load,
                    rng,
                );

                assert!(verify(&proof, (&public_param, &public_commit), &metadata).is_err());
            }
        }
    }

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

        let rng = &mut StdRng::seed_from_u64(0);

        let PkeTestProofInputs {
            a,
            e1,
            e2,
            r,
            m,
            b,
            c1,
            c2,
            metadata,
        } = PkeTestProofInputs::gen(rng, PKEV1_TEST_PARAMS);

        type Curve = crate::curve_api::Bls12_446;

        let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

        let public_param = crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);

        let (public_commit, private_commit) = commit(
            a.clone(),
            b.clone(),
            c1.clone(),
            c2.clone(),
            r.clone(),
            e1.clone(),
            m.clone(),
            e2.clone(),
            &public_param,
            rng,
        );

        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let proof = prove(
                (&public_param, &public_commit),
                &private_commit,
                &metadata,
                load,
                rng,
            );

            let compressed_proof = bincode::serialize(&proof.clone().compress()).unwrap();
            let proof =
                Proof::uncompress(bincode::deserialize(&compressed_proof).unwrap()).unwrap();

            verify(&proof, (&public_param, &public_commit), &metadata).unwrap()
        }
    }
}
