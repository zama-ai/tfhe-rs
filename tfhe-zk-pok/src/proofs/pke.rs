use super::*;
use core::marker::PhantomData;
use rayon::prelude::*;

fn bit_iter(x: u64, nbits: u32) -> impl Iterator<Item = bool> {
    (0..nbits).map(move |idx| ((x >> idx) & 1) != 0)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PublicParams<G: Curve> {
    g_lists: GroupElements<G>,
    big_d: usize,
    pub n: usize,
    pub d: usize,
    pub k: usize,
    pub b: u64,
    pub b_r: u64,
    pub q: u64,
    pub t: u64,
}

impl<G: Curve> PublicParams<G> {
    #[allow(clippy::too_many_arguments)]
    pub fn from_vec(
        g_list: Vec<G::G1>,
        g_hat_list: Vec<G::G2>,
        big_d: usize,
        n: usize,
        d: usize,
        k: usize,
        b: u64,
        b_r: u64,
        q: u64,
        t: u64,
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
        }
    }

    pub fn exclusive_max_noise(&self) -> u64 {
        self.b
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Proof<G: Curve> {
    c_hat: G::G2,
    c_y: G::G1,
    pi: G::G1,
    c_hat_t: Option<G::G2>,
    c_h: Option<G::G1>,
    pi_kzg: Option<G::G1>,
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
            __marker: Default::default(),
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
) -> (usize, usize, u64) {
    let b_r = d as u64 / 2 + 1;

    let big_d =
        d + k * t.ilog2() as usize + (d + k) * (2 + b.ilog2() as usize + b_r.ilog2() as usize);
    let n = big_d + 1;
    (n, big_d, b_r)
}

pub fn crs_gen<G: Curve>(
    d: usize,
    k: usize,
    b: u64,
    q: u64,
    t: u64,
    rng: &mut dyn RngCore,
) -> PublicParams<G> {
    let alpha = G::Zp::rand(rng);
    let (n, big_d, b_r) = compute_crs_params(d, k, b, q, t);
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
    load: ComputeLoad,
    rng: &mut dyn RngCore,
) -> Proof<G> {
    let &PublicParams {
        ref g_lists,
        big_d,
        n,
        d,
        b,
        b_r,
        q,
        t,
        k,
    } = public.0;
    let g_list = &g_lists.g_list;
    let g_hat_list = &g_lists.g_hat_list;

    let b_i = b;

    let PublicCommit { a, b, c1, c2, .. } = public.1;
    let PrivateCommit { r, e1, m, e2, .. } = private_commit;

    assert!(c2.len() <= k);
    let k = k.min(c2.len());

    // FIXME: div_round
    let delta = {
        let q = if q == 0 { 1i128 << 64 } else { q as i128 };
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
                    b[d - j - i - 1]
                } else {
                    b[2 * d - j - i - 1].wrapping_neg()
                };

                dot += r[d - j - 1] as i128 * b as i128;
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
                .chain(m.iter().flat_map(|&m| bit_iter(u64(m), t.ilog2())))
                .chain(e1.iter().flat_map(|&e1| bit_iter(u64(e1), 1 + b_i.ilog2())))
                .chain(e2.iter().flat_map(|&e2| bit_iter(u64(e2), 1 + b_i.ilog2())))
                .chain(r1.iter().flat_map(|&r1| bit_iter(u64(r1), 1 + b_r.ilog2())))
                .chain(r2.iter().flat_map(|&r2| bit_iter(u64(r2), 1 + b_r.ilog2()))),
        )
        .for_each(|(dst, src)| *dst = src);

    let w = OneBased(w);

    let mut c_hat = g_hat.mul_scalar(gamma);
    for j in 1..big_d + 1 {
        let term = if w[j] { g_hat_list[j] } else { G::G2::ZERO };
        c_hat += term;
    }

    let x_bytes = &*[
        q.to_le_bytes().as_slice(),
        d.to_le_bytes().as_slice(),
        b_i.to_le_bytes().as_slice(),
        t.to_le_bytes().as_slice(),
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
    G::Zp::hash(&mut y, &[x_bytes, c_hat.to_bytes().as_ref()]);
    let y = OneBased(y);

    let scalars = (n + 1 - big_d..n + 1)
        .map(|j| (y[n + 1 - j] * G::Zp::from_u64(w[n + 1 - j] as u64)))
        .collect::<Vec<_>>();
    let c_y = g.mul_scalar(gamma_y) + G::G1::multi_mul_scalar(&g_list.0[n - big_d..n], &scalars);

    let mut theta = vec![G::Zp::ZERO; d + k + 1];
    G::Zp::hash(
        &mut theta,
        &[x_bytes, c_hat.to_bytes().as_ref(), c_y.to_bytes().as_ref()],
    );

    let theta0 = &theta[..d + k];

    let delta_theta = theta[d + k];

    let mut a_theta = vec![G::Zp::ZERO; big_d];

    compute_a_theta::<G>(theta0, d, a, k, b, &mut a_theta, t, delta, b_i, b_r, q);

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash(
        &mut t,
        &[
            &(1..n + 1)
                .flat_map(|i| y[i].to_bytes().as_ref().to_vec())
                .collect::<Box<_>>(),
            x_bytes,
            c_hat.to_bytes().as_ref(),
            c_y.to_bytes().as_ref(),
        ],
    );
    let t = OneBased(t);

    let mut delta = [G::Zp::ZERO; 2];
    G::Zp::hash(
        &mut delta,
        &[x_bytes, c_hat.to_bytes().as_ref(), c_y.to_bytes().as_ref()],
    );
    let [delta_eq, delta_y] = delta;

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
                x_bytes,
                c_hat.to_bytes().as_ref(),
                c_y.to_bytes().as_ref(),
                pi.to_bytes().as_ref(),
                c_h.to_bytes().as_ref(),
                c_hat_t.to_bytes().as_ref(),
                &y.0.iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &t.0.iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &delta
                    .iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
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
                x_bytes,
                c_hat.to_bytes().as_ref(),
                c_y.to_bytes().as_ref(),
                pi.to_bytes().as_ref(),
                c_h.to_bytes().as_ref(),
                c_hat_t.to_bytes().as_ref(),
                &y.0.iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &t.0.iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &delta
                    .iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                z.to_bytes().as_ref(),
                p_h.to_bytes().as_ref(),
                p_t.to_bytes().as_ref(),
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
    {
        let a_theta = &mut a_theta[..d];
        a_theta
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, a_theta_i)| {
                let mut dot = G::Zp::ZERO;

                for j in 0..d {
                    let a = if i <= j {
                        a[j - i]
                    } else {
                        a[d + j - i].wrapping_neg()
                    };

                    dot += G::Zp::from_i64(a) * theta1[j];
                }

                for j in 0..k {
                    let b = if i + j < d {
                        b[d - i - j - 1]
                    } else {
                        b[2 * d - i - j - 1].wrapping_neg()
                    };

                    dot += G::Zp::from_i64(b) * theta2[j];
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
        big_d,
        n,
        d,
        b,
        b_r,
        q,
        t,
        k,
    } = public.0;
    let g_list = &g_lists.g_list;
    let g_hat_list = &g_lists.g_hat_list;

    let b_i = b;

    // FIXME: div_round
    let delta = {
        let q = if q == 0 { 1i128 << 64 } else { q as i128 };
        (q / t as i128) as u64
    };

    let PublicCommit { a, b, c1, c2, .. } = public.1;
    if c2.len() > k {
        return Err(());
    }
    let k = k.min(c2.len());

    let x_bytes = &*[
        q.to_le_bytes().as_slice(),
        d.to_le_bytes().as_slice(),
        b_i.to_le_bytes().as_slice(),
        t.to_le_bytes().as_slice(),
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
    G::Zp::hash(&mut y, &[x_bytes, c_hat.to_bytes().as_ref()]);
    let y = OneBased(y);

    let mut theta = vec![G::Zp::ZERO; d + k + 1];
    G::Zp::hash(
        &mut theta,
        &[x_bytes, c_hat.to_bytes().as_ref(), c_y.to_bytes().as_ref()],
    );
    let theta0 = &theta[..d + k];
    let delta_theta = theta[d + k];

    let mut a_theta = vec![G::Zp::ZERO; big_d];
    compute_a_theta::<G>(theta0, d, a, k, b, &mut a_theta, t, delta, b_i, b_r, q);

    let mut t_theta = G::Zp::ZERO;
    for i in 0..d {
        t_theta += theta0[i] * G::Zp::from_i64(c1[i]);
    }
    for i in 0..k {
        t_theta += theta0[d + i] * G::Zp::from_i64(c2[i]);
    }

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash(
        &mut t,
        &[
            &(1..n + 1)
                .flat_map(|i| y[i].to_bytes().as_ref().to_vec())
                .collect::<Box<_>>(),
            x_bytes,
            c_hat.to_bytes().as_ref(),
            c_y.to_bytes().as_ref(),
        ],
    );
    let t = OneBased(t);

    let mut delta = [G::Zp::ZERO; 2];
    G::Zp::hash(
        &mut delta,
        &[x_bytes, c_hat.to_bytes().as_ref(), c_y.to_bytes().as_ref()],
    );
    let [delta_eq, delta_y] = delta;

    if let (Some(pi_kzg), Some(c_hat_t), Some(c_h)) = (pi_kzg, c_hat_t, c_h) {
        let mut z = G::Zp::ZERO;
        G::Zp::hash(
            core::array::from_mut(&mut z),
            &[
                x_bytes,
                c_hat.to_bytes().as_ref(),
                c_y.to_bytes().as_ref(),
                pi.to_bytes().as_ref(),
                c_h.to_bytes().as_ref(),
                c_hat_t.to_bytes().as_ref(),
                &y.0.iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &t.0.iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &delta
                    .iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
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
                - e(g_list[1], g_hat_list[n]).mul_scalar(t_theta * delta_theta)
        {
            return Err(());
        }

        let mut w = G::Zp::ZERO;
        G::Zp::hash(
            core::array::from_mut(&mut w),
            &[
                x_bytes,
                c_hat.to_bytes().as_ref(),
                c_y.to_bytes().as_ref(),
                pi.to_bytes().as_ref(),
                c_h.to_bytes().as_ref(),
                c_hat_t.to_bytes().as_ref(),
                &y.0.iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &t.0.iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                &delta
                    .iter()
                    .flat_map(|x| x.to_bytes().as_ref().to_vec())
                    .collect::<Box<[_]>>(),
                z.to_bytes().as_ref(),
                p_h.to_bytes().as_ref(),
                p_t.to_bytes().as_ref(),
            ],
        );

        if e(c_h - G::G1::GENERATOR.mul_scalar(p_h), G::G2::GENERATOR)
            + e(G::G1::GENERATOR, c_hat_t - G::G2::GENERATOR.mul_scalar(p_t)).mul_scalar(w)
            == e(pi_kzg, g_hat_list[1] - G::G2::GENERATOR.mul_scalar(z))
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
                            g_list[n + 1 - i].mul_scalar(factor)
                        })
                        .sum::<G::G1>();
                let q = c_hat;
                e(p, q)
            },
            || {
                let p = c_y;
                let q = (1..n + 1)
                    .into_par_iter()
                    .map(|i| g_hat_list[i].mul_scalar(delta_eq * t[i]))
                    .sum::<G::G2>();
                e(p, q)
            },
        );
        let term2 = {
            let p = g_list[1];
            let q = g_hat_list[n];
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
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_pke() {
        let d = 2048;
        let k = 320;
        let b_i = 512;
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
            .map(|_| (rng.gen::<u64>() % (2 * b_i)) as i64 - b_i as i64)
            .collect::<Vec<_>>();
        let e1 = (0..d)
            .map(|_| (rng.gen::<u64>() % (2 * b_i)) as i64 - b_i as i64)
            .collect::<Vec<_>>();
        let fake_e1 = (0..d)
            .map(|_| (rng.gen::<u64>() % (2 * b_i)) as i64 - b_i as i64)
            .collect::<Vec<_>>();
        let e2 = (0..k)
            .map(|_| (rng.gen::<u64>() % (2 * b_i)) as i64 - b_i as i64)
            .collect::<Vec<_>>();
        let fake_e2 = (0..k)
            .map(|_| (rng.gen::<u64>() % (2 * b_i)) as i64 - b_i as i64)
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

        let public_param = crs_gen::<crate::curve_api::Bls12_446>(d, k, b_i, q, t, rng);

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
                            let proof =
                                prove((&public_param, &public_commit), &private_commit, load, rng);

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
