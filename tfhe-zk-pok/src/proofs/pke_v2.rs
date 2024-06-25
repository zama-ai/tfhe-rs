// to follow the notation of the paper
#![allow(non_snake_case)]

use super::*;
use crate::four_squares::*;
use core::marker::PhantomData;
use rayon::prelude::*;

fn bit_iter(x: u64, nbits: u32) -> impl Iterator<Item = bool> {
    (0..nbits).map(move |idx| ((x >> idx) & 1) != 0)
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParams<G: Curve> {
    g_lists: GroupElements<G>,
    D: usize,
    pub n: usize,
    pub d: usize,
    pub k: usize,
    pub B: u64,
    pub B_r: u64,
    pub B_bound: u64,
    pub m_bound: usize,
    pub q: u64,
    pub t: u64,
    hash: [u8; HASH_METADATA_LEN_BYTES],
    hash_R: [u8; HASH_METADATA_LEN_BYTES],
    hash_t: [u8; HASH_METADATA_LEN_BYTES],
    hash_w: [u8; HASH_METADATA_LEN_BYTES],
    hash_agg: [u8; HASH_METADATA_LEN_BYTES],
    hash_lmap: [u8; HASH_METADATA_LEN_BYTES],
    hash_phi: [u8; HASH_METADATA_LEN_BYTES],
    hash_xi: [u8; HASH_METADATA_LEN_BYTES],
    hash_z: [u8; HASH_METADATA_LEN_BYTES],
    hash_chi: [u8; HASH_METADATA_LEN_BYTES],
}

impl<G: Curve> PublicParams<G> {
    #[allow(clippy::too_many_arguments)]
    pub fn from_vec(
        g_list: Vec<Affine<G::Zp, G::G1>>,
        g_hat_list: Vec<Affine<G::Zp, G::G2>>,
        d: usize,
        k: usize,
        B: u64,
        q: u64,
        t: u64,
        bound: Bound,
        hash: [u8; HASH_METADATA_LEN_BYTES],
        hash_R: [u8; HASH_METADATA_LEN_BYTES],
        hash_t: [u8; HASH_METADATA_LEN_BYTES],
        hash_w: [u8; HASH_METADATA_LEN_BYTES],
        hash_agg: [u8; HASH_METADATA_LEN_BYTES],
        hash_lmap: [u8; HASH_METADATA_LEN_BYTES],
        hash_phi: [u8; HASH_METADATA_LEN_BYTES],
        hash_xi: [u8; HASH_METADATA_LEN_BYTES],
        hash_z: [u8; HASH_METADATA_LEN_BYTES],
        hash_chi: [u8; HASH_METADATA_LEN_BYTES],
    ) -> Self {
        let (n, D, B_r, B_bound, m_bound) = compute_crs_params(d, k, B, q, t, bound);
        Self {
            g_lists: GroupElements::<G>::from_vec(g_list, g_hat_list),
            D,
            n,
            d,
            k,
            B,
            B_r,
            B_bound,
            m_bound,
            q,
            t,
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
        }
    }

    pub fn exclusive_max_noise(&self) -> u64 {
        self.B
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound(
    deserialize = "G: Curve, G::G1: serde::Deserialize<'de>, G::G2: serde::Deserialize<'de>",
    serialize = "G: Curve, G::G1: serde::Serialize, G::G2: serde::Serialize"
))]
pub struct Proof<G: Curve> {
    C_hat_e: G::G2,
    C_e: G::G1,
    C_r_tilde: G::G1,
    C_R: G::G1,
    C_hat_bin: G::G2,
    C_y: G::G1,
    C_h1: G::G1,
    C_h2: G::G1,
    C_hat_t: G::G2,
    pi: G::G1,
    pi_kzg: G::G1,

    C_hat_h3: Option<G::G2>,
    C_hat_w: Option<G::G2>,
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

#[derive(Copy, Clone, Debug)]
pub enum Bound {
    GHL,
    CS,
}

pub fn compute_crs_params(
    d: usize,
    k: usize,
    B: u64,
    _q: u64, // we keep q here to make sure the API is consistent with [crs_gen]
    t: u64,
    bound: Bound,
) -> (usize, usize, u64, u64, usize) {
    let B_r = d as u64 / 2 + 1;
    let B_bound = {
        let B = B as f64;
        let d = d as f64;
        let k = k as f64;

        (match bound {
            Bound::GHL => 9.75,
            Bound::CS => f64::sqrt(2.0 * (d + k) + 4.0),
        }) * f64::sqrt(sqr(B) + (sqr(d + 2.0) * (d + k)) / 4.0)
    }
    .ceil() as u64;

    let m_bound = 2 + B_bound.ilog2() as usize;

    let D = d + k * t.ilog2() as usize;
    let n = D + 128 * m_bound;

    (n, D, B_r, B_bound, m_bound)
}

pub fn crs_gen_ghl<G: Curve>(
    d: usize,
    k: usize,
    B: u64,
    q: u64,
    t: u64,
    rng: &mut dyn RngCore,
) -> PublicParams<G> {
    let alpha = G::Zp::rand(rng);
    let B = B * (isqrt((d + k) as _) as u64 + 1);
    let (n, D, B_r, B_bound, m_bound) = compute_crs_params(d, k, B, q, t, Bound::GHL);
    PublicParams {
        g_lists: GroupElements::<G>::new(n, alpha),
        D,
        n,
        d,
        k,
        B,
        B_r,
        B_bound,
        m_bound,
        q,
        t,
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
    }
}

pub fn crs_gen_cs<G: Curve>(
    d: usize,
    k: usize,
    B: u64,
    q: u64,
    t: u64,
    rng: &mut dyn RngCore,
) -> PublicParams<G> {
    let alpha = G::Zp::rand(rng);
    let B = B * (isqrt((d + k) as _) as u64 + 1);
    let (n, D, B_r, B_bound, m_bound) = compute_crs_params(d, k, B, q, t, Bound::CS);
    PublicParams {
        g_lists: GroupElements::<G>::new(n, alpha),
        D,
        n,
        d,
        k,
        B,
        B_r,
        B_bound,
        m_bound,
        q,
        t,
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
    }
}

pub fn crs_gen<G: Curve>(
    d: usize,
    k: usize,
    B: u64,
    q: u64,
    t: u64,
    rng: &mut dyn RngCore,
) -> PublicParams<G> {
    crs_gen_cs(d, k, B, q, t, rng)
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
    load: ComputeLoad,
    rng: &mut dyn RngCore,
) -> Proof<G> {
    _ = load;
    let (
        &PublicParams {
            ref g_lists,
            D,
            n,
            d,
            k,
            B,
            B_r: _,
            B_bound,
            m_bound,
            q,
            t: t_input,
            ref hash,
            ref hash_R,
            ref hash_t,
            ref hash_w,
            ref hash_agg,
            ref hash_lmap,
            ref hash_phi,
            ref hash_xi,
            ref hash_z,
            ref hash_chi,
        },
        PublicCommit { a, b, c1, c2, .. },
    ) = public;
    let g_list = &*g_lists.g_list.0;
    let g_hat_list = &*g_lists.g_hat_list.0;

    let PrivateCommit { r, e1, m, e2, .. } = private_commit;

    assert!(c2.len() <= k);
    let k = k.min(c2.len());

    // FIXME: div_round
    let delta = {
        let q = if q == 0 { 1i128 << 64 } else { q as i128 };
        (q / t_input as i128) as u64
    };

    let g = G::G1::GENERATOR;
    let g_hat = G::G2::GENERATOR;
    let gamma_e = G::Zp::rand(rng);
    let gamma_hat_e = G::Zp::rand(rng);
    let gamma_r = G::Zp::rand(rng);
    let gamma_R = G::Zp::rand(rng);
    let gamma_bin = G::Zp::rand(rng);
    let gamma_y = G::Zp::rand(rng);

    // eq (10)
    // rot(a) * phi(bar(r)) - q phi(r1) + phi(e1) = phi(c1)
    // phi_[d - i](b).T * phi(bar(r)) + delta * m_i - q r2_i + e2_i = c2_i

    // implies
    // phi(r1) = (rot(a) * phi(bar(r)) + phi(e1) - phi(c1)) / q
    // r2_i = (phi_[d - i](b).T * phi(bar(r)) + delta * m_i + e2_i - c2_i) / q

    let mut r1 = e1
        .iter()
        .zip(c1.iter())
        .map(|(&e1, &c1)| e1 as i128 - c1 as i128)
        .collect::<Box<[_]>>();

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
        .collect::<Box<[_]>>();

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

    let r1 = &*r1
        .into_vec()
        .into_iter()
        .map(|r1| r1 as i64)
        .collect::<Box<[_]>>();

    let r2 = &*r2
        .into_vec()
        .into_iter()
        .map(|r2| r2 as i64)
        .collect::<Box<[_]>>();

    let u64 = |x: i64| x as u64;

    let w_tilde = r
        .iter()
        .rev()
        .map(|&r| r != 0)
        .chain(m.iter().flat_map(|&m| bit_iter(u64(m), t_input.ilog2())))
        .collect::<Box<[_]>>();

    let e_sqr_norm = e1
        .iter()
        .chain(e2)
        .map(|x| sqr(x.unsigned_abs() as u128))
        .sum::<u128>();

    assert!(
        sqr(B as u128) >= e_sqr_norm,
        "squared norm of error ({e_sqr_norm}) exceeds threshold ({})",
        sqr(B as u128)
    );

    let v = four_squares(sqr(B as u128) - e_sqr_norm).map(|v| v as i64);

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

    let mut scalars = e1_zp
        .iter()
        .copied()
        .chain(e2_zp.iter().copied())
        .chain(v_zp)
        .collect::<Box<[_]>>();
    let C_hat_e =
        g_hat.mul_scalar(gamma_hat_e) + G::G2::multi_mul_scalar(&g_hat_list[..d + k + 4], &scalars);

    let (C_e, C_r_tilde) = rayon::join(
        || {
            scalars.reverse();
            g.mul_scalar(gamma_e) + G::G1::multi_mul_scalar(&g_list[n - (d + k + 4)..n], &scalars)
        },
        || {
            let scalars = r1_zp
                .iter()
                .chain(r2_zp.iter())
                .copied()
                .collect::<Box<[_]>>();
            g.mul_scalar(gamma_r) + G::G1::multi_mul_scalar(&g_list[..d + k], &scalars)
        },
    );

    let x_bytes = &*[
        q.to_le_bytes().as_slice(),
        d.to_le_bytes().as_slice(),
        B.to_le_bytes().as_slice(),
        t_input.to_le_bytes().as_slice(),
        &*a.iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect::<Box<[_]>>(),
        &*b.iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect::<Box<[_]>>(),
        &*c1.iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect::<Box<[_]>>(),
        &*c2.iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect::<Box<[_]>>(),
    ]
    .iter()
    .copied()
    .flatten()
    .copied()
    .collect::<Box<[_]>>();

    // make R_bar a random number generator from the given bytes
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut hasher = sha3::Shake256::default();
    for &data in &[
        hash_R,
        x_bytes,
        C_hat_e.to_bytes().as_ref(),
        C_e.to_bytes().as_ref(),
        C_r_tilde.to_bytes().as_ref(),
    ] {
        hasher.update(data);
    }
    let mut R_bar = hasher.finalize_xof();
    let R = (0..128 * (2 * (d + k) + 4))
        .map(|_| {
            let mut byte = 0u8;
            R_bar.read(core::slice::from_mut(&mut byte));

            // take two bits
            match byte & 0b11 {
                // probability 1/2
                0 | 1 => 0,
                // probability 1/4
                2 => 1,
                // probability 1/4
                3 => -1,
                _ => unreachable!(),
            }
        })
        .collect::<Box<[i8]>>();

    let R = |i: usize, j: usize| R[i + j * 128];
    let R_bytes = &*(0..128)
        .flat_map(|i| (0..(2 * (d + k) + 4)).map(move |j| R(i, j) as u8))
        .collect::<Box<[u8]>>();

    let w_R = (0..128)
        .map(|i| {
            let R = |j| R(i, j);

            let mut acc = 0i128;
            e1.iter()
                .chain(e2)
                .chain(&v)
                .chain(r1)
                .chain(r2)
                .copied()
                .enumerate()
                .for_each(|(j, x)| match R(j) {
                    0 => {}
                    1 => acc += x as i128,
                    -1 => acc -= x as i128,
                    _ => unreachable!(),
                });
            assert!(acc.unsigned_abs() <= B_bound as u128);
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

    let mut phi = vec![G::Zp::ZERO; 128];
    G::Zp::hash(
        &mut phi,
        &[
            hash_phi,
            x_bytes,
            R_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            C_R.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
        ],
    );
    let phi_bytes = &*phi
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

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

    let mut xi = vec![G::Zp::ZERO; 128];
    G::Zp::hash(
        &mut xi,
        &[
            hash_xi,
            x_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            phi_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
        ],
    );

    let xi_bytes = &*xi
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut y = vec![G::Zp::ZERO; D + 128 * m];
    G::Zp::hash(
        &mut y,
        &[
            hash,
            x_bytes,
            R_bytes,
            phi_bytes,
            xi_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
        ],
    );
    let y_bytes = &*y
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    assert_eq!(y.len(), w_bin.len());
    let scalars = y
        .iter()
        .zip(w_bin.iter())
        .rev()
        .map(|(&y, &w)| if w { y } else { G::Zp::ZERO })
        .collect::<Box<[_]>>();
    let C_y =
        g.mul_scalar(gamma_y) + G::G1::multi_mul_scalar(&g_list[n - (D + 128 * m)..n], &scalars);

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash_128bit(
        &mut t,
        &[
            hash_t,
            x_bytes,
            y_bytes,
            phi_bytes,
            xi_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
        ],
    );
    let t_bytes = &*t
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut theta = vec![G::Zp::ZERO; d + k];
    G::Zp::hash(
        &mut theta,
        &[
            hash_lmap,
            x_bytes,
            y_bytes,
            t_bytes,
            phi_bytes,
            xi_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
        ],
    );
    let theta_bytes = &*theta
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut a_theta = vec![G::Zp::ZERO; D];
    compute_a_theta::<G>(&mut a_theta, &theta, a, k, b, t_input, delta);

    let t_theta = theta
        .iter()
        .copied()
        .zip(c1.iter().chain(c2.iter()).copied().map(G::Zp::from_i64))
        .map(|(x, y)| x * y)
        .sum::<G::Zp>();

    let mut w = vec![G::Zp::ZERO; n];
    G::Zp::hash_128bit(
        &mut w,
        &[
            hash_w,
            x_bytes,
            y_bytes,
            t_bytes,
            phi_bytes,
            xi_bytes,
            theta_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
        ],
    );
    let w_bytes = &*w
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut delta = [G::Zp::ZERO; 7];
    G::Zp::hash(
        &mut delta,
        &[
            hash_agg,
            x_bytes,
            y_bytes,
            t_bytes,
            phi_bytes,
            xi_bytes,
            theta_bytes,
            w_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
        ],
    );
    let [delta_r, delta_dec, delta_eq, delta_y, delta_theta, delta_e, delta_l] = delta;
    let delta_bytes = &*delta
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut poly_0_lhs = vec![G::Zp::ZERO; 1 + n];
    let mut poly_0_rhs = vec![G::Zp::ZERO; 1 + D + 128 * m];
    let mut poly_1_lhs = vec![G::Zp::ZERO; 1 + n];
    let mut poly_1_rhs = vec![G::Zp::ZERO; 1 + d + k + 4];
    let mut poly_2_lhs = vec![G::Zp::ZERO; 1 + d + k];
    let mut poly_2_rhs = vec![G::Zp::ZERO; 1 + n];
    let mut poly_3_lhs = vec![G::Zp::ZERO; 1 + 128];
    let mut poly_3_rhs = vec![G::Zp::ZERO; 1 + n];
    let mut poly_4_lhs = vec![G::Zp::ZERO; 1 + n];
    let mut poly_4_rhs = vec![G::Zp::ZERO; 1 + d + k + 4];
    let mut poly_5_lhs = vec![G::Zp::ZERO; 1 + n];
    let mut poly_5_rhs = vec![G::Zp::ZERO; 1 + n];

    let mut xi_scaled = xi.clone();
    poly_0_lhs[0] = delta_y * gamma_y;
    for j in 0..D + 128 * m {
        let p = &mut poly_0_lhs[n - j];

        if !w_bin[j] {
            *p -= delta_y * y[j];
        }

        if j < D {
            *p += delta_theta * a_theta[j];
        }
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

    poly_0_rhs[0] = gamma_bin;
    for j in 0..D + 128 * m {
        let p = &mut poly_0_rhs[j + 1];

        if w_bin[j] {
            *p = G::Zp::ONE;
        }
    }

    poly_1_lhs[0] = delta_l * gamma_e;
    for j in 0..d {
        let p = &mut poly_1_lhs[n - j];
        *p = delta_l * e1_zp[j];
    }
    for j in 0..k {
        let p = &mut poly_1_lhs[n - (d + j)];
        *p = delta_l * e2_zp[j];
    }
    for j in 0..4 {
        let p = &mut poly_1_lhs[n - (d + k + j)];
        *p = delta_l * v_zp[j];
    }

    for j in 0..n {
        let p = &mut poly_1_lhs[n - j];
        let mut acc = delta_e * w[j];
        if j < d + k {
            acc += delta_theta * theta[j];
        }

        if j < d + k + 4 {
            let mut acc2 = G::Zp::ZERO;
            for (i, &phi) in phi.iter().enumerate() {
                match R(i, j) {
                    0 => {}
                    1 => acc2 += phi,
                    -1 => acc2 -= phi,
                    _ => unreachable!(),
                }
            }
            acc += delta_r * acc2;
        }
        *p += acc;
    }

    poly_1_rhs[0] = gamma_hat_e;
    for j in 0..d {
        let p = &mut poly_1_rhs[1 + j];
        *p = e1_zp[j];
    }
    for j in 0..k {
        let p = &mut poly_1_rhs[1 + (d + j)];
        *p = e2_zp[j];
    }
    for j in 0..4 {
        let p = &mut poly_1_rhs[1 + (d + k + j)];
        *p = v_zp[j];
    }

    poly_2_lhs[0] = gamma_r;
    for j in 0..d {
        let p = &mut poly_2_lhs[1 + j];
        *p = r1_zp[j];
    }
    for j in 0..k {
        let p = &mut poly_2_lhs[1 + (d + j)];
        *p = r2_zp[j];
    }

    let delta_theta_q =
        delta_theta * G::Zp::from_u128(if q == 0 { 1u128 << 64 } else { q as u128 });
    for j in 0..d + k {
        let p = &mut poly_2_rhs[n - j];

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

    poly_3_lhs[0] = gamma_R;
    for j in 0..128 {
        let p = &mut poly_3_lhs[1 + j];
        *p = G::Zp::from_i64(w_R[j]);
    }

    for j in 0..128 {
        let p = &mut poly_3_rhs[n - j];
        *p = delta_r * phi[j] + delta_dec * xi[j];
    }

    poly_4_lhs[0] = delta_e * gamma_e;
    for j in 0..d {
        let p = &mut poly_4_lhs[n - j];
        *p = delta_e * e1_zp[j];
    }
    for j in 0..k {
        let p = &mut poly_4_lhs[n - (d + j)];
        *p = delta_e * e2_zp[j];
    }
    for j in 0..4 {
        let p = &mut poly_4_lhs[n - (d + k + j)];
        *p = delta_e * v_zp[j];
    }

    for j in 0..d + k + 4 {
        let p = &mut poly_4_rhs[1 + j];
        *p = w[j];
    }

    poly_5_lhs[0] = delta_eq * gamma_y;
    for j in 0..D + 128 * m {
        let p = &mut poly_5_lhs[n - j];

        if w_bin[j] {
            *p = delta_eq * y[j];
        }
    }

    for j in 0..n {
        let p = &mut poly_5_rhs[1 + j];
        *p = t[j];
    }

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
        P_pi[n + 1] -= delta_theta * t_theta + delta_l * sqr(G::Zp::from_u64(B));
    }

    let pi = if P_pi.is_empty() {
        G::G1::ZERO
    } else {
        g.mul_scalar(P_pi[0]) + G::G1::multi_mul_scalar(&g_list[..P_pi.len() - 1], &P_pi[1..])
    };

    let mut xi_scaled = xi.clone();
    let mut scalars = (0..D + 128 * m)
        .map(|j| {
            let mut acc = G::Zp::ZERO;
            if j < D {
                acc += delta_theta * a_theta[j];
            }
            acc -= delta_y * y[j];
            acc += delta_eq * t[j] * y[j];

            if j >= D {
                let j = j - D;
                let xi = &mut xi_scaled[j / m];
                let H_xi = *xi;
                *xi = *xi + *xi;

                let r = delta_dec * H_xi;

                if j % m < m - 1 {
                    acc += r;
                } else {
                    acc -= r;
                }
            }

            acc
        })
        .collect::<Box<[_]>>();
    scalars.reverse();
    let C_h1 = G::G1::multi_mul_scalar(&g_list[n - (D + 128 * m)..n], &scalars);

    let mut scalars = (0..n)
        .map(|j| {
            let mut acc = G::Zp::ZERO;
            if j < d + k {
                acc += delta_theta * theta[j];
            }

            acc += delta_e * w[j];

            if j < d + k + 4 {
                let mut acc2 = G::Zp::ZERO;
                for (i, &phi) in phi.iter().enumerate() {
                    match R(i, j) {
                        0 => {}
                        1 => acc2 += phi,
                        -1 => acc2 -= phi,
                        _ => unreachable!(),
                    }
                }
                acc += delta_r * acc2;
            }
            acc
        })
        .collect::<Box<[_]>>();
    scalars.reverse();
    let C_h2 = G::G1::multi_mul_scalar(&g_list[..n], &scalars);
    let (C_hat_h3, C_hat_w) = match load {
        ComputeLoad::Proof => rayon::join(
            || {
                Some(G::G2::multi_mul_scalar(
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
                ))
            },
            || {
                Some(G::G2::multi_mul_scalar(
                    &g_hat_list[..d + k + 4],
                    &w[..d + k + 4],
                ))
            },
        ),
        ComputeLoad::Verify => (None, None),
    };

    let C_hat_h3_bytes = C_hat_h3.map(G::G2::to_bytes);
    let C_hat_w_bytes = C_hat_w.map(G::G2::to_bytes);
    let C_hat_h3_bytes = C_hat_h3_bytes.as_ref().map(|x| x.as_ref()).unwrap_or(&[]);
    let C_hat_w_bytes = C_hat_w_bytes.as_ref().map(|x| x.as_ref()).unwrap_or(&[]);

    let C_hat_t = G::G2::multi_mul_scalar(g_hat_list, &t);

    let mut z = G::Zp::ZERO;
    G::Zp::hash(
        core::slice::from_mut(&mut z),
        &[
            hash_z,
            x_bytes,
            y_bytes,
            t_bytes,
            phi_bytes,
            x_bytes,
            theta_bytes,
            delta_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
            C_h1.to_bytes().as_ref(),
            C_h2.to_bytes().as_ref(),
            C_hat_t.to_bytes().as_ref(),
            C_hat_h3_bytes,
            C_hat_w_bytes,
        ],
    );

    let mut P_h1 = vec![G::Zp::ZERO; 1 + n];
    let mut P_h2 = vec![G::Zp::ZERO; 1 + n];
    let mut P_t = vec![G::Zp::ZERO; 1 + n];
    let mut P_h3 = match load {
        ComputeLoad::Proof => vec![G::Zp::ZERO; 1 + n],
        ComputeLoad::Verify => vec![],
    };
    let mut P_w = match load {
        ComputeLoad::Proof => vec![G::Zp::ZERO; 1 + d + k + 4],
        ComputeLoad::Verify => vec![],
    };

    let mut xi_scaled = xi.clone();
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

        *p += delta_e * w[j];

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

    if !P_w.is_empty() {
        P_w[1..].copy_from_slice(&w[..d + k + 4]);
    }

    let mut p_h1 = G::Zp::ZERO;
    let mut p_h2 = G::Zp::ZERO;
    let mut p_t = G::Zp::ZERO;
    let mut p_h3 = G::Zp::ZERO;
    let mut p_w = G::Zp::ZERO;

    let mut pow = G::Zp::ONE;
    for j in 0..n + 1 {
        p_h1 += P_h1[j] * pow;
        p_h2 += P_h2[j] * pow;
        p_t += P_t[j] * pow;

        if j < P_h3.len() {
            p_h3 += P_h3[j] * pow;
        }
        if j < P_w.len() {
            p_w += P_w[j] * pow;
        }

        pow = pow * z;
    }

    let mut chi = G::Zp::ZERO;
    G::Zp::hash(
        core::slice::from_mut(&mut chi),
        &[
            hash_chi,
            x_bytes,
            y_bytes,
            t_bytes,
            phi_bytes,
            xi_bytes,
            theta_bytes,
            delta_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
            C_h1.to_bytes().as_ref(),
            C_h2.to_bytes().as_ref(),
            C_hat_t.to_bytes().as_ref(),
            C_hat_h3_bytes,
            C_hat_w_bytes,
            z.to_bytes().as_ref(),
            p_h1.to_bytes().as_ref(),
            p_h2.to_bytes().as_ref(),
            p_t.to_bytes().as_ref(),
        ],
    );

    let mut Q_kzg = vec![G::Zp::ZERO; 1 + n];
    let chi2 = chi * chi;
    let chi3 = chi2 * chi;
    let chi4 = chi3 * chi;
    for j in 1..n + 1 {
        Q_kzg[j] = P_h1[j] + chi * P_h2[j] + chi2 * P_t[j];
        if j < P_h3.len() {
            Q_kzg[j] += chi3 * P_h3[j];
        }
        if j < P_w.len() {
            Q_kzg[j] += chi4 * P_w[j];
        }
    }
    Q_kzg[0] -= p_h1 + chi * p_h2 + chi2 * p_t + chi3 * p_h3 + chi4 * p_w;

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
        C_hat_h3,
        C_hat_w,
        pi,
        pi_kzg,
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_a_theta<G: Curve>(
    a_theta: &mut [G::Zp],
    theta: &[G::Zp],
    a: &[i64],
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

    let d = a.len();

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

#[allow(clippy::result_unit_err)]
pub fn verify<G: Curve>(
    proof: &Proof<G>,
    public: (&PublicParams<G>, &PublicCommit<G>),
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
        C_hat_h3,
        C_hat_w,
        pi,
        pi_kzg,
    } = proof;
    let pairing = G::Gt::pairing;

    let &PublicParams {
        ref g_lists,
        D,
        n,
        d,
        k,
        B,
        B_r: _,
        B_bound: _,
        m_bound: m,
        q,
        t: t_input,
        ref hash,
        ref hash_R,
        ref hash_t,
        ref hash_w,
        ref hash_agg,
        ref hash_lmap,
        ref hash_phi,
        ref hash_xi,
        ref hash_z,
        ref hash_chi,
    } = public.0;
    let g_list = &*g_lists.g_list.0;
    let g_hat_list = &*g_lists.g_hat_list.0;

    // FIXME: div_round
    let delta = {
        let q = if q == 0 { 1i128 << 64 } else { q as i128 };
        (q / t_input as i128) as u64
    };

    let PublicCommit { a, b, c1, c2, .. } = public.1;
    if c2.len() > k {
        return Err(());
    }
    let k = k.min(c2.len());

    let C_hat_h3_bytes = C_hat_h3.map(G::G2::to_bytes);
    let C_hat_w_bytes = C_hat_w.map(G::G2::to_bytes);
    let C_hat_h3_bytes = C_hat_h3_bytes.as_ref().map(|x| x.as_ref()).unwrap_or(&[]);
    let C_hat_w_bytes = C_hat_w_bytes.as_ref().map(|x| x.as_ref()).unwrap_or(&[]);

    let x_bytes = &*[
        q.to_le_bytes().as_slice(),
        d.to_le_bytes().as_slice(),
        B.to_le_bytes().as_slice(),
        t_input.to_le_bytes().as_slice(),
        &*a.iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect::<Box<[_]>>(),
        &*b.iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect::<Box<[_]>>(),
        &*c1.iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect::<Box<[_]>>(),
        &*c2.iter()
            .flat_map(|&x| x.to_le_bytes())
            .collect::<Box<[_]>>(),
    ]
    .iter()
    .copied()
    .flatten()
    .copied()
    .collect::<Box<[_]>>();

    // make R_bar a random number generator from the given bytes
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut hasher = sha3::Shake256::default();
    for &data in &[
        hash_R,
        x_bytes,
        C_hat_e.to_bytes().as_ref(),
        C_e.to_bytes().as_ref(),
        C_r_tilde.to_bytes().as_ref(),
    ] {
        hasher.update(data);
    }
    let mut R_bar = hasher.finalize_xof();
    let R = (0..128 * (2 * (d + k) + 4))
        .map(|_| {
            let mut byte = 0u8;
            R_bar.read(core::slice::from_mut(&mut byte));

            // take two bits
            match byte & 0b11 {
                // probability 1/2
                0 | 1 => 0,
                // probability 1/4
                2 => 1,
                // probability 1/4
                3 => -1,
                _ => unreachable!(),
            }
        })
        .collect::<Box<[i8]>>();

    let R = |i: usize, j: usize| R[i + j * 128];
    let R_bytes = &*(0..128)
        .flat_map(|i| (0..(2 * (d + k) + 4)).map(move |j| R(i, j) as u8))
        .collect::<Box<[u8]>>();

    let mut phi = vec![G::Zp::ZERO; 128];
    G::Zp::hash(
        &mut phi,
        &[
            hash_phi,
            x_bytes,
            R_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            C_R.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
        ],
    );
    let phi_bytes = &*phi
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut xi = vec![G::Zp::ZERO; 128];
    G::Zp::hash(
        &mut xi,
        &[
            hash_xi,
            x_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            phi_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
        ],
    );
    let xi_bytes = &*xi
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut y = vec![G::Zp::ZERO; D + 128 * m];
    G::Zp::hash(
        &mut y,
        &[
            hash,
            x_bytes,
            R_bytes,
            phi_bytes,
            xi_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
        ],
    );
    let y_bytes = &*y
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash_128bit(
        &mut t,
        &[
            hash_t,
            x_bytes,
            y_bytes,
            phi_bytes,
            xi_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
        ],
    );
    let t_bytes = &*t
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut theta = vec![G::Zp::ZERO; d + k];
    G::Zp::hash(
        &mut theta,
        &[
            hash_lmap,
            x_bytes,
            y_bytes,
            t_bytes,
            phi_bytes,
            xi_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
        ],
    );
    let theta_bytes = &*theta
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut w = vec![G::Zp::ZERO; n];
    G::Zp::hash_128bit(
        &mut w,
        &[
            hash_w,
            x_bytes,
            y_bytes,
            t_bytes,
            phi_bytes,
            xi_bytes,
            theta_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
        ],
    );
    let w_bytes = &*w
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let mut a_theta = vec![G::Zp::ZERO; D];
    compute_a_theta::<G>(&mut a_theta, &theta, a, k, b, t_input, delta);

    let t_theta = theta
        .iter()
        .copied()
        .zip(c1.iter().chain(c2.iter()).copied().map(G::Zp::from_i64))
        .map(|(x, y)| x * y)
        .sum::<G::Zp>();

    let mut delta = [G::Zp::ZERO; 7];
    G::Zp::hash(
        &mut delta,
        &[
            hash_agg,
            x_bytes,
            y_bytes,
            t_bytes,
            phi_bytes,
            xi_bytes,
            theta_bytes,
            w_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
        ],
    );
    let [delta_r, delta_dec, delta_eq, delta_y, delta_theta, delta_e, delta_l] = delta;
    let delta_bytes = &*delta
        .iter()
        .flat_map(|x| x.to_bytes().as_ref().to_vec())
        .collect::<Box<[_]>>();

    let g = G::G1::GENERATOR;
    let g_hat = G::G2::GENERATOR;

    let delta_theta_q =
        delta_theta * G::Zp::from_u128(if q == 0 { 1u128 << 64 } else { q as u128 });

    let rhs = pairing(pi, g_hat);
    let lhs = {
        let lhs0 = pairing(C_y.mul_scalar(delta_y) + C_h1, C_hat_bin);
        let lhs1 = pairing(C_e.mul_scalar(delta_l) + C_h2, C_hat_e);

        let lhs2 = pairing(
            C_r_tilde,
            match C_hat_h3 {
                Some(C_hat_h3) => C_hat_h3,
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
        );
        let lhs3 = pairing(
            C_R,
            G::G2::multi_mul_scalar(
                &g_hat_list[n - 128..n],
                &(0..128)
                    .rev()
                    .map(|j| delta_r * phi[j] + delta_dec * xi[j])
                    .collect::<Box<[_]>>(),
            ),
        );
        let lhs4 = pairing(
            C_e.mul_scalar(delta_e),
            match C_hat_w {
                Some(C_hat_w) => C_hat_w,
                None => G::G2::multi_mul_scalar(&g_hat_list[..d + k + 4], &w[..d + k + 4]),
            },
        );
        let lhs5 = pairing(C_y.mul_scalar(delta_eq), C_hat_t);
        let lhs6 = pairing(
            G::G1::projective(g_list[0]),
            G::G2::projective(g_hat_list[n - 1]),
        )
        .mul_scalar(delta_theta * t_theta + delta_l * sqr(G::Zp::from_u64(B)));

        lhs0 + lhs1 + lhs2 - lhs3 - lhs4 - lhs5 - lhs6
    };

    if lhs != rhs {
        return Err(());
    }

    let mut z = G::Zp::ZERO;
    G::Zp::hash(
        core::slice::from_mut(&mut z),
        &[
            hash_z,
            x_bytes,
            y_bytes,
            t_bytes,
            phi_bytes,
            x_bytes,
            theta_bytes,
            delta_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
            C_h1.to_bytes().as_ref(),
            C_h2.to_bytes().as_ref(),
            C_hat_t.to_bytes().as_ref(),
            C_hat_h3_bytes,
            C_hat_w_bytes,
        ],
    );

    let load = if C_hat_h3.is_some() && C_hat_w.is_some() {
        ComputeLoad::Proof
    } else {
        ComputeLoad::Verify
    };

    let mut P_h1 = vec![G::Zp::ZERO; 1 + n];
    let mut P_h2 = vec![G::Zp::ZERO; 1 + n];
    let mut P_t = vec![G::Zp::ZERO; 1 + n];
    let mut P_h3 = match load {
        ComputeLoad::Proof => vec![G::Zp::ZERO; 1 + n],
        ComputeLoad::Verify => vec![],
    };
    let mut P_w = match load {
        ComputeLoad::Proof => vec![G::Zp::ZERO; 1 + d + k + 4],
        ComputeLoad::Verify => vec![],
    };

    let mut xi_scaled = xi.clone();
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

        *p += delta_e * w[j];

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

    if !P_w.is_empty() {
        P_w[1..].copy_from_slice(&w[..d + k + 4]);
    }

    let mut p_h1 = G::Zp::ZERO;
    let mut p_h2 = G::Zp::ZERO;
    let mut p_t = G::Zp::ZERO;
    let mut p_h3 = G::Zp::ZERO;
    let mut p_w = G::Zp::ZERO;

    let mut pow = G::Zp::ONE;
    for j in 0..n + 1 {
        p_h1 += P_h1[j] * pow;
        p_h2 += P_h2[j] * pow;
        p_t += P_t[j] * pow;

        if j < P_h3.len() {
            p_h3 += P_h3[j] * pow;
        }
        if j < P_w.len() {
            p_w += P_w[j] * pow;
        }

        pow = pow * z;
    }

    let mut chi = G::Zp::ZERO;
    G::Zp::hash(
        core::slice::from_mut(&mut chi),
        &[
            hash_chi,
            x_bytes,
            y_bytes,
            t_bytes,
            phi_bytes,
            xi_bytes,
            theta_bytes,
            delta_bytes,
            C_hat_e.to_bytes().as_ref(),
            C_e.to_bytes().as_ref(),
            R_bytes,
            C_R.to_bytes().as_ref(),
            C_hat_bin.to_bytes().as_ref(),
            C_r_tilde.to_bytes().as_ref(),
            C_y.to_bytes().as_ref(),
            C_h1.to_bytes().as_ref(),
            C_h2.to_bytes().as_ref(),
            C_hat_t.to_bytes().as_ref(),
            C_hat_h3_bytes,
            C_hat_w_bytes,
            z.to_bytes().as_ref(),
            p_h1.to_bytes().as_ref(),
            p_h2.to_bytes().as_ref(),
            p_t.to_bytes().as_ref(),
        ],
    );
    let chi2 = chi * chi;
    let chi3 = chi2 * chi;
    let chi4 = chi3 * chi;

    let lhs = pairing(
        C_h1 + C_h2.mul_scalar(chi) - g.mul_scalar(p_h1 + chi * p_h2),
        g_hat,
    ) + pairing(
        g,
        {
            let mut C_hat = C_hat_t.mul_scalar(chi2);
            if let Some(C_hat_h3) = C_hat_h3 {
                C_hat += C_hat_h3.mul_scalar(chi3);
            }
            if let Some(C_hat_w) = C_hat_w {
                C_hat += C_hat_w.mul_scalar(chi4);
            }
            C_hat
        } - g_hat.mul_scalar(p_t * chi2 + p_h3 * chi3 + p_w * chi4),
    );
    let rhs = pairing(
        pi_kzg,
        G::G2::projective(g_hat_list[0]) - g_hat.mul_scalar(z),
    );
    if lhs != rhs {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_pke() {
        let d = 2048;
        let k = 320;
        let B = 1048576;
        let q = 0;
        let t = 1024;

        let delta = {
            let q = if q == 0 { 1i128 << 64 } else { q as i128 };
            (q / t as i128) as u64
        };

        let rng = &mut StdRng::seed_from_u64(0);

        let polymul_rev = |a: &[i64], b: &[i64]| -> Vec<i64> {
            assert_eq!(a.len(), b.len());
            let d = a.len();
            let mut c = vec![0i64; d];

            for i in 0..d {
                for j in 0..d {
                    if i + j < d {
                        c[i + j] = c[i + j].wrapping_add(a[i].wrapping_mul(b[d - j - 1]));
                    } else {
                        c[i + j - d] = c[i + j - d].wrapping_sub(a[i].wrapping_mul(b[d - j - 1]));
                    }
                }
            }

            c
        };

        let a = (0..d).map(|_| rng.gen::<i64>()).collect::<Vec<_>>();
        let s = (0..d)
            .map(|_| (rng.gen::<u64>() % 2) as i64)
            .collect::<Vec<_>>();
        let e = (0..d)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();
        let e1 = (0..d)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();
        let fake_e1 = (0..d)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();
        let e2 = (0..k)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();
        let fake_e2 = (0..k)
            .map(|_| (rng.gen::<u64>() % (2 * B)) as i64 - B as i64)
            .collect::<Vec<_>>();

        let r = (0..d)
            .map(|_| (rng.gen::<u64>() % 2) as i64)
            .collect::<Vec<_>>();
        let fake_r = (0..d)
            .map(|_| (rng.gen::<u64>() % 2) as i64)
            .collect::<Vec<_>>();

        let m = (0..k)
            .map(|_| (rng.gen::<u64>() % t) as i64)
            .collect::<Vec<_>>();
        let fake_m = (0..k)
            .map(|_| (rng.gen::<u64>() % t) as i64)
            .collect::<Vec<_>>();

        let b = polymul_rev(&a, &s)
            .into_iter()
            .zip(e.iter())
            .map(|(x, e)| x.wrapping_add(*e))
            .collect::<Vec<_>>();
        let c1 = polymul_rev(&a, &r)
            .into_iter()
            .zip(e1.iter())
            .map(|(x, e1)| x.wrapping_add(*e1))
            .collect::<Vec<_>>();

        let mut c2 = vec![0i64; k];

        for i in 0..k {
            let mut dot = 0i64;
            for j in 0..d {
                let b = if i + j < d {
                    b[d - j - i - 1]
                } else {
                    b[2 * d - j - i - 1].wrapping_neg()
                };

                dot = dot.wrapping_add(r[d - j - 1].wrapping_mul(b));
            }

            c2[i] = dot
                .wrapping_add(e2[i])
                .wrapping_add((delta * m[i] as u64) as i64);
        }

        let mut m_roundtrip = vec![0i64; k];
        for i in 0..k {
            let mut dot = 0i128;
            for j in 0..d {
                let c = if i + j < d {
                    c1[d - j - i - 1]
                } else {
                    c1[2 * d - j - i - 1].wrapping_neg()
                };

                dot += s[d - j - 1] as i128 * c as i128;
            }

            let q = if q == 0 { 1i128 << 64 } else { q as i128 };
            let val = ((c2[i] as i128).wrapping_sub(dot)) * t as i128;
            let div = val.div_euclid(q);
            let rem = val.rem_euclid(q);
            let result = div as i64 + (rem > (q / 2)) as i64;
            let result = result.rem_euclid(t as i64);
            m_roundtrip[i] = result;
        }

        type Curve = crate::curve_api::Bls12_446;

        let serialize_then_deserialize =
            |public_param: &PublicParams<Curve>,
             compress: Compress|
             -> Result<PublicParams<Curve>, SerializationError> {
                let mut data = Vec::new();
                public_param.serialize_with_mode(&mut data, compress)?;

                PublicParams::deserialize_with_mode(data.as_slice(), compress, Validate::No)
            };

        let original_public_param = crs_gen_ghl::<Curve>(d, k, B, q, t, rng);
        let public_param_that_was_compressed =
            serialize_then_deserialize(&original_public_param, Compress::No).unwrap();
        let public_param_that_was_not_compressed =
            serialize_then_deserialize(&original_public_param, Compress::Yes).unwrap();

        for public_param in [
            original_public_param,
            public_param_that_was_compressed,
            public_param_that_was_not_compressed,
        ] {
            for use_fake_e1 in [false, true] {
                for use_fake_e2 in [false, true] {
                    for use_fake_m in [false, true] {
                        for use_fake_r in [false, true] {
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
                                    load,
                                    rng,
                                );

                                assert_eq!(
                                    verify(&proof, (&public_param, &public_commit)).is_err(),
                                    use_fake_e1 || use_fake_e2 || use_fake_r || use_fake_m
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
