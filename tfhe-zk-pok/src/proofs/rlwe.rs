use super::*;
use core::iter::zip;
use core::marker::PhantomData;
use rayon::prelude::*;

fn bit_iter(x: u64, nbits: u32) -> impl Iterator<Item = bool> {
    (0..nbits).map(move |idx| ((x >> idx) & 1) == 1)
}

#[derive(Clone, Debug)]
pub struct PublicParams<G: Curve> {
    g_lists: GroupElements<G>,
    d: usize,
    big_n: usize,
    big_m: usize,
    b_i: u64,
    q: u64,
    hash: [u8; LEGACY_HASH_DS_LEN_BYTES],
    hash_t: [u8; LEGACY_HASH_DS_LEN_BYTES],
    hash_agg: [u8; LEGACY_HASH_DS_LEN_BYTES],
    hash_lmap: [u8; LEGACY_HASH_DS_LEN_BYTES],
    hash_z: [u8; LEGACY_HASH_DS_LEN_BYTES],
    hash_w: [u8; LEGACY_HASH_DS_LEN_BYTES],
}

impl<G: Curve> PublicParams<G> {
    #[allow(clippy::too_many_arguments)]
    pub fn from_vec(
        g_list: Vec<Affine<G::Zp, G::G1>>,
        g_hat_list: Vec<Affine<G::Zp, G::G2>>,
        d: usize,
        big_n: usize,
        big_m: usize,
        b_i: u64,
        q: u64,
        hash: [u8; LEGACY_HASH_DS_LEN_BYTES],
        hash_t: [u8; LEGACY_HASH_DS_LEN_BYTES],
        hash_agg: [u8; LEGACY_HASH_DS_LEN_BYTES],
        hash_lmap: [u8; LEGACY_HASH_DS_LEN_BYTES],
        hash_z: [u8; LEGACY_HASH_DS_LEN_BYTES],
        hash_w: [u8; LEGACY_HASH_DS_LEN_BYTES],
    ) -> Self {
        Self {
            g_lists: GroupElements::from_vec(g_list, g_hat_list),
            d,
            big_n,
            big_m,
            b_i,
            q,
            hash,
            hash_t,
            hash_agg,
            hash_lmap,
            hash_z,
            hash_w,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct PrivateParams<G: Curve> {
    alpha: G::Zp,
}

#[derive(Clone, Debug)]
pub struct PublicCommit<G: Curve> {
    a: Matrix<i64>,
    c: Vector<i64>,
    __marker: PhantomData<G>,
}

#[derive(Clone, Debug)]
pub struct PrivateCommit<G: Curve> {
    s: Vector<i64>,
    __marker: PhantomData<G>,
}

#[derive(Clone, Debug)]
pub struct Proof<G: Curve> {
    c_hat: G::G2,
    c_y: G::G1,
    pi: G::G1,
    compute_load_proof_fields: Option<ComputeLoadProofFields<G>>,
}

#[derive(Clone, Debug)]
struct ComputeLoadProofFields<G: Curve> {
    c_hat_t: G::G2,
    c_h: G::G1,
    pi_kzg: G::G1,
}

pub fn crs_gen<G: Curve>(
    d: usize,
    big_n: usize,
    big_m: usize,
    b_i: u64,
    q: u64,
    rng: &mut impl RngExt,
) -> PublicParams<G> {
    let alpha = G::Zp::rand(rng);
    let b_r = ((d * big_m) as u64 * b_i) / 2;
    let big_d = d * (big_m * (1 + b_i.ilog2() as usize) + (big_n * (1 + b_r.ilog2() as usize)));
    let n = big_d + 1;
    PublicParams {
        g_lists: GroupElements::new(n, alpha),
        d,
        big_n,
        big_m,
        b_i,
        q,
        hash: core::array::from_fn(|_| rng.random()),
        hash_t: core::array::from_fn(|_| rng.random()),
        hash_agg: core::array::from_fn(|_| rng.random()),
        hash_lmap: core::array::from_fn(|_| rng.random()),
        hash_z: core::array::from_fn(|_| rng.random()),
        hash_w: core::array::from_fn(|_| rng.random()),
    }
}

#[derive(Clone, Debug)]
pub struct Vector<T> {
    pub data: Vec<T>,
    pub polynomial_size: usize,
    pub nrows: usize,
}
#[derive(Clone, Debug)]
pub struct Matrix<T> {
    pub data: Vec<T>,
    pub polynomial_size: usize,
    pub nrows: usize,
    pub ncols: usize,
}

impl<T: Copy> Matrix<T> {
    pub fn new(polynomial_size: usize, nrows: usize, ncols: usize, value: T) -> Self {
        Self {
            data: vec![value; polynomial_size * nrows * ncols],
            polynomial_size,
            nrows,
            ncols,
        }
    }
}
impl<T: Copy> Vector<T> {
    pub fn new(polynomial_size: usize, nrows: usize, value: T) -> Self {
        Self {
            data: vec![value; polynomial_size * nrows],
            polynomial_size,
            nrows,
        }
    }
}

impl<T> Index<usize> for Vector<T> {
    type Output = [T];

    fn index(&self, row: usize) -> &Self::Output {
        let row = row - 1;
        &self.data[self.polynomial_size * row..][..self.polynomial_size]
    }
}
impl<T> IndexMut<usize> for Vector<T> {
    fn index_mut(&mut self, row: usize) -> &mut Self::Output {
        let row = row - 1;
        &mut self.data[self.polynomial_size * row..][..self.polynomial_size]
    }
}

impl<T> Index<(usize, usize)> for Matrix<T> {
    type Output = [T];

    fn index(&self, (row, col): (usize, usize)) -> &Self::Output {
        let row = row - 1;
        let col = col - 1;
        &self.data[self.polynomial_size * (row * self.ncols + col)..][..self.polynomial_size]
    }
}
impl<T> IndexMut<(usize, usize)> for Matrix<T> {
    fn index_mut(&mut self, (row, col): (usize, usize)) -> &mut Self::Output {
        let row = row - 1;
        let col = col - 1;
        &mut self.data[self.polynomial_size * (row * self.ncols + col)..][..self.polynomial_size]
    }
}

pub fn commit<G: Curve>(
    a: Matrix<i64>,
    c: Vector<i64>,
    s: Vector<i64>,
    public: &PublicParams<G>,
    rng: &mut impl RngExt,
) -> (PublicCommit<G>, PrivateCommit<G>) {
    let _ = (public, rng);
    (
        PublicCommit {
            a,
            c,
            __marker: PhantomData,
        },
        PrivateCommit {
            s,
            __marker: PhantomData,
        },
    )
}

pub fn prove<G: Curve>(
    public: (&PublicParams<G>, &PublicCommit<G>),
    private_commit: &PrivateCommit<G>,
    load: ComputeLoad,
    rng: &mut impl RngExt,
) -> Proof<G> {
    let &PublicParams {
        ref g_lists,
        d,
        big_n,
        big_m,
        b_i,
        q,
        ref hash,
        ref hash_t,
        ref hash_agg,
        ref hash_lmap,
        ref hash_z,
        ref hash_w,
    } = public.0;
    let g_list = &g_lists.g_list;
    let g_hat_list = &g_lists.g_hat_list;
    let s = &private_commit.s;
    let a = &public.1.a;

    let b_r = ((d * big_m) as u64 * b_i) / 2;
    let big_d = d * (big_m * (1 + b_i.ilog2() as usize) + (big_n * (1 + b_r.ilog2() as usize)));
    let n = big_d + 1;

    let g = G::G1::GENERATOR;
    let g_hat = G::G2::GENERATOR;
    let gamma = G::Zp::rand(rng);
    let gamma_y = G::Zp::rand(rng);

    let mut c = Vector {
        data: vec![0i64; d],
        polynomial_size: d,
        nrows: big_n,
    };
    let mut r = Vector {
        data: vec![0i64; d],
        polynomial_size: d,
        nrows: big_n,
    };

    for j in 1..big_n + 1 {
        let c = &mut c[j];
        let r = &mut r[j];

        let mut polymul = vec![0i128; d];
        for i in 1..big_m + 1 {
            let si = &s[i];
            let aij = &a[(i, j)];

            for ii in 0..d {
                for jj in 0..d {
                    let p = (aij[ii] as i128) * si[jj] as i128;
                    if ii + jj < d {
                        polymul[ii + jj] += p;
                    } else {
                        polymul[ii + jj - d] -= p;
                    }
                }
            }
        }

        for ((ck, rk), old_ck) in zip(zip(c, r), &polymul) {
            let q = if q == 0 { q as i128 } else { 1i128 << 64 };
            let mut new_ck = old_ck.rem_euclid(q);
            if new_ck >= q / 2 {
                new_ck -= q;
            }
            assert!((old_ck - new_ck) % q == 0);
            assert!((*rk).unsigned_abs() < b_r);

            *ck = new_ck as i64;
            *rk = ((old_ck - new_ck) / q) as i64;
        }
    }
    let w_tilde = Iterator::chain(
        (1..big_m + 1).flat_map(|i| {
            s[i].iter()
                .copied()
                .flat_map(|x| bit_iter(x as u64, b_i.ilog2() + 1))
        }),
        (1..big_n + 1).flat_map(|i| {
            r[i].iter()
                .copied()
                .flat_map(|x| bit_iter(x as u64, b_r.ilog2() + 1))
        }),
    )
    .collect::<Box<_>>();
    let mut w = vec![false; n].into_boxed_slice();
    w[..big_d].copy_from_slice(&w_tilde);
    let w = OneBased::new_ref(&*w);

    let mut c_hat = g_hat.mul_scalar(gamma);
    for j in 1..big_d + 1 {
        let term = if w[j] {
            G::G2::projective(g_hat_list[j])
        } else {
            G::G2::ZERO
        };
        c_hat += term;
    }

    let x_bytes = &*[
        &q.to_le_bytes(),
        &(d as u64).to_le_bytes(),
        &(big_m as u64).to_le_bytes(),
        &(big_n as u64).to_le_bytes(),
        &b_i.to_le_bytes(),
        &*(1..big_m + 1)
            .flat_map(|i| {
                (1..big_n + 1).flat_map(move |j| a[(i, j)].iter().flat_map(|ai| ai.to_le_bytes()))
            })
            .collect::<Box<_>>(),
        &(1..big_n + 1)
            .flat_map(|j| c[j].iter().flat_map(|ci| ci.to_le_bytes()))
            .collect::<Box<_>>(),
    ]
    .iter()
    .copied()
    .flatten()
    .copied()
    .collect::<Box<_>>();

    let mut y = vec![G::Zp::ZERO; n];
    G::Zp::hash(&mut y, &[hash, x_bytes, c_hat.to_le_bytes().as_ref()]);
    let y = OneBased(y);

    let scalars = (n + 1 - big_d..n + 1)
        .map(|j| y[n + 1 - j] * G::Zp::from_u64(w[n + 1 - j] as u64))
        .collect::<Vec<_>>();
    let c_y = g.mul_scalar(gamma_y) + G::G1::multi_mul_scalar(&g_list.0[n - big_d..n], &scalars);

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash(
        &mut t,
        &[
            hash_t,
            &(1..n + 1)
                .flat_map(|i| y[i].to_le_bytes().as_ref().to_vec())
                .collect::<Box<_>>(),
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let t = OneBased(t);

    let mut theta_bar = vec![G::Zp::ZERO; big_n * d + 1];
    G::Zp::hash(
        &mut theta_bar,
        &[
            hash_lmap,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let theta = (0..big_n * d + 1).map(|k| theta_bar[k]).collect::<Box<_>>();
    let theta0 = theta[..big_n * d].to_vec().into_boxed_slice();
    let delta_theta = theta[big_n * d];

    let mut t_theta = G::Zp::ZERO;
    for j in 0..big_n {
        let cj = &c[j + 1];
        let theta0j = &theta0[j * d..][..d];
        for k in 0..d {
            t_theta += theta0j[k] * G::Zp::from_i64(cj[k]);
        }
    }

    let mut a_theta = vec![G::Zp::ZERO; big_d];
    let b_step = 1 + b_i.ilog2() as usize;
    let step = d * b_step;
    for i in 0..big_m {
        // a_theta_i = A_tilde_{i + 1}.T × theta0
        let a_theta_i = &mut a_theta[step * i..][..step];

        for j in 0..big_n {
            let aij = &a[(i + 1, j + 1)];
            let theta0_j = &theta0[d * j..][..d];

            let mut rot_aij_theta0_j = vec![G::Zp::ZERO; d];
            for p in 0..d {
                let mut dot = G::Zp::ZERO;

                for q in 0..d {
                    let a = if p <= q {
                        G::Zp::from_i64(aij[q - p])
                    } else {
                        -G::Zp::from_i64(aij[d + q - p])
                    };
                    dot += a * theta0_j[q];
                }

                rot_aij_theta0_j[p] = dot;
            }

            for k in 0..b_step {
                let a_theta_ik = &mut a_theta_i[k..];
                let mut c = G::Zp::from_u64(1 << k);
                if k + 1 == b_step {
                    c = -c;
                }

                for (dst, src) in zip(a_theta_ik.iter_mut().step_by(b_step), &rot_aij_theta0_j) {
                    *dst = c * *src;
                }
            }
        }
    }

    let offset_m = step * big_m;
    let b_step = 1 + b_r.ilog2() as usize;
    let step = d * b_step;
    for j in 0..big_n {
        // a_theta_j -= q G.T theta0_j
        let a_theta_j = &mut a_theta[offset_m + step * j..][..step];
        let theta0_j = &theta0[d * j..][..d];

        for k in 0..b_step {
            let a_theta_jk = &mut a_theta_j[k..];
            let mut c = -G::Zp::from_u64(1 << k) * G::Zp::from_u64(q);
            if k + 1 == b_step {
                c = -c;
            }
            for (dst, src) in zip(a_theta_jk.iter_mut().step_by(b_step), theta0_j) {
                *dst = c * *src;
            }
        }
    }

    let mut delta = [G::Zp::ZERO; 2];
    G::Zp::hash(
        &mut delta,
        &[
            hash_agg,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let [delta_eq, delta_y] = delta;
    let mut poly_0 = vec![G::Zp::ZERO; n + 1];
    let mut poly_1 = vec![G::Zp::ZERO; n + 1];
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

    let mut poly = G::Zp::poly_sub(
        &G::Zp::poly_mul(&poly_0, &poly_1),
        &G::Zp::poly_mul(&poly_2, &poly_3),
    );

    if poly.len() > n + 1 {
        poly[n + 1] -= t_theta * delta_theta;
    }

    let pi =
        g.mul_scalar(poly[0]) + G::G1::multi_mul_scalar(&g_list.0[..poly.len() - 1], &poly[1..]);

    if load == ComputeLoad::Proof {
        let c_hat_t = G::G2::multi_mul_scalar(&g_hat_list.0, &t.0);
        let scalars = (1..n + 1)
            .into_par_iter()
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

#[allow(clippy::result_unit_err)]
pub fn verify<G: Curve>(
    proof: &Proof<G>,
    public: (&PublicParams<G>, &PublicCommit<G>),
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
        d,
        big_n,
        big_m,
        b_i,
        q,
        ref hash,
        ref hash_t,
        ref hash_agg,
        ref hash_lmap,
        ref hash_z,
        ref hash_w,
    } = public.0;
    let g_list = &g_lists.g_list;
    let g_hat_list = &g_lists.g_hat_list;

    let b_r = ((d * big_m) as u64 * b_i) / 2;
    let big_d = d * (big_m * (1 + b_i.ilog2() as usize) + (big_n * (1 + b_r.ilog2() as usize)));
    let n = big_d + 1;

    let a = &public.1.a;
    let c = &public.1.c;

    let x_bytes = &*[
        &q.to_le_bytes(),
        &(d as u64).to_le_bytes(),
        &(big_m as u64).to_le_bytes(),
        &(big_n as u64).to_le_bytes(),
        &b_i.to_le_bytes(),
        &*(1..big_m + 1)
            .flat_map(|i| {
                (1..big_n + 1).flat_map(move |j| a[(i, j)].iter().flat_map(|ai| ai.to_le_bytes()))
            })
            .collect::<Box<_>>(),
        &(1..big_n + 1)
            .flat_map(|j| c[j].iter().flat_map(|ci| ci.to_le_bytes()))
            .collect::<Box<_>>(),
    ]
    .iter()
    .copied()
    .flatten()
    .copied()
    .collect::<Box<_>>();

    let mut delta = [G::Zp::ZERO; 2];
    G::Zp::hash(
        &mut delta,
        &[
            hash_agg,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let [delta_eq, delta_y] = delta;

    let mut y = vec![G::Zp::ZERO; n];
    G::Zp::hash(&mut y, &[hash, x_bytes, c_hat.to_le_bytes().as_ref()]);
    let y = OneBased(y);

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash(
        &mut t,
        &[
            hash_t,
            &(1..n + 1)
                .flat_map(|i| y[i].to_le_bytes().as_ref().to_vec())
                .collect::<Box<_>>(),
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let t = OneBased(t);

    let mut theta_bar = vec![G::Zp::ZERO; big_n * d + 1];
    G::Zp::hash(
        &mut theta_bar,
        &[
            hash_lmap,
            x_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let theta = (0..big_n * d + 1).map(|k| theta_bar[k]).collect::<Box<_>>();
    let theta0 = theta[..big_n * d].to_vec().into_boxed_slice();
    let delta_theta = theta[big_n * d];

    let mut t_theta = G::Zp::ZERO;
    for j in 0..big_n {
        let cj = &c[j + 1];
        let theta0j = &theta0[j * d..][..d];
        for k in 0..d {
            t_theta += theta0j[k] * G::Zp::from_i64(cj[k]);
        }
    }

    let mut a_theta = vec![G::Zp::ZERO; big_d];
    let b_step = 1 + b_i.ilog2() as usize;
    let step = d * b_step;
    for i in 0..big_m {
        // a_theta_i = A_tilde_{i + 1}.T × theta0
        let a_theta_i = &mut a_theta[step * i..][..step];

        for j in 0..big_n {
            let aij = &a[(i + 1, j + 1)];
            let theta0_j = &theta0[d * j..][..d];

            let mut rot_aij_theta0_j = vec![G::Zp::ZERO; d];
            for p in 0..d {
                let mut dot = G::Zp::ZERO;

                for q in 0..d {
                    let a = if p <= q {
                        G::Zp::from_i64(aij[q - p])
                    } else {
                        -G::Zp::from_i64(aij[d + q - p])
                    };
                    dot += a * theta0_j[q];
                }

                rot_aij_theta0_j[p] = dot;
            }

            for k in 0..b_step {
                let a_theta_ik = &mut a_theta_i[k..];
                let mut c = G::Zp::from_u64(1 << k);
                if k + 1 == b_step {
                    c = -c;
                }

                for (dst, src) in zip(a_theta_ik.iter_mut().step_by(b_step), &rot_aij_theta0_j) {
                    *dst = c * *src;
                }
            }
        }
    }

    let offset_m = step * big_m;
    let b_step = 1 + b_r.ilog2() as usize;
    let step = d * b_step;
    for j in 0..big_n {
        // a_theta_j -= q G.T theta0_j
        let a_theta_j = &mut a_theta[offset_m + step * j..][..step];
        let theta0_j = &theta0[d * j..][..d];

        for k in 0..b_step {
            let a_theta_jk = &mut a_theta_j[k..];
            let mut c = -G::Zp::from_u64(1 << k) * G::Zp::from_u64(q);
            if k + 1 == b_step {
                c = -c;
            }
            for (dst, src) in zip(a_theta_jk.iter_mut().step_by(b_step), theta0_j) {
                *dst = c * *src;
            }
        }
    }

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
                hash_z,
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
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    fn time<R>(f: impl FnOnce() -> R) -> R {
        let time = std::time::Instant::now();
        let r = f();
        println!("{:?}", time.elapsed());
        r
    }

    #[test]
    fn test_rlwe() {
        let rng = &mut StdRng::seed_from_u64(0);
        let d: usize = 2048;
        let big_m: usize = 1;
        let big_n: usize = 1;

        let q = 1217;
        let b_i: u64 = 512;

        let mut a = Matrix::new(d, big_m, big_n, 0i64);
        let mut c = Vector::new(d, big_n, 0i64);
        let mut s = Vector::new(d, big_m, 0i64);

        for i in 0..big_m {
            for k in 0..d {
                s[i + 1][k] = (rng.random::<u64>() % (2 * b_i)) as i64 - b_i as i64;
            }
        }

        for i in 0..big_m {
            for j in 0..big_n {
                for k in 0..d {
                    let mut x = (rng.random::<u64>() % q) as i64;
                    if x >= q as i64 / 2 {
                        x -= q as i64;
                    }
                    a[(i + 1, j + 1)][k] = x;
                }
            }
        }

        for j in 1..big_n + 1 {
            let c = &mut c[j];

            let mut polymul = vec![0i128; d];
            for i in 1..big_m + 1 {
                let si = &s[i];
                let aij = &a[(i, j)];

                for ii in 0..d {
                    for jj in 0..d {
                        let p = (aij[ii] as i128) * si[jj] as i128;
                        if ii + jj < d {
                            polymul[ii + jj] += p;
                        } else {
                            polymul[ii + jj - d] -= p;
                        }
                    }
                }
            }

            for (ck, old_ck) in core::iter::zip(c, &polymul) {
                let q = if q == 0 { q as i128 } else { 1i128 << 64 };
                let mut new_ck = old_ck.rem_euclid(q);
                if new_ck >= q / 2 {
                    new_ck -= q;
                }
                *ck = new_ck as i64;
            }
        }

        let public_params = crs_gen::<crate::curve_api::Bls12_446>(d, big_n, big_m, b_i, q, rng);
        let (public_commit, private_commit) = commit(a, c, s, &public_params, rng);
        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let proof =
                time(|| prove((&public_params, &public_commit), &private_commit, load, rng));
            let verify = time(|| verify(&proof, (&public_params, &public_commit)));
            assert!(verify.is_ok());
        }
    }
}
