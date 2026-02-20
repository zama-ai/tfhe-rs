//! GPU-accelerated prove/verify for PKE v1.
//!
//! `prove` duplicates the logic of [`super::prove_impl`] but replaces every
//! `multi_mul_scalar` call with the GPU-accelerated [`crate::gpu::g1_msm_gpu`]
//! / [`crate::gpu::g2_msm_gpu`].  `verify` simply delegates to the CPU
//! verifier since v1 verification contains no MSM calls.

use crate::curve_api::bls12_446::{Zp, G1, G2};
use crate::curve_api::{Bls12_446, CurveGroupOps, FieldOps};
use crate::gpu::select_gpu_for_msm;
use crate::proofs::{
    assert_pke_proof_preconditions, compute_r1, compute_r2, decode_q, ComputeLoad, OneBased,
    ProofSanityCheckMode,
};

use super::{
    bit_iter, compute_a_theta, ComputeLoadProofFields, PrivateCommit, Proof, PublicCommit,
    PublicParams,
};

/// GPU-accelerated proof generation for PKE v1.
///
/// Identical to [`super::prove`] but dispatches MSM to the GPU via
/// [`crate::gpu::g1_msm_gpu`] / [`crate::gpu::g2_msm_gpu`].
pub fn prove(
    public: (&PublicParams<Bls12_446>, &PublicCommit<Bls12_446>),
    private_commit: &PrivateCommit<Bls12_446>,
    metadata: &[u8],
    load: ComputeLoad,
    seed: &[u8],
) -> Proof<Bls12_446> {
    prove_impl(
        public,
        private_commit,
        metadata,
        load,
        seed,
        ProofSanityCheckMode::Panic,
    )
}

/// GPU-accelerated verification for PKE v1.
///
/// PKE v1 verification has no MSM calls, so this delegates directly to the CPU
/// verifier.
#[allow(clippy::result_unit_err)]
pub fn verify(
    proof: &Proof<Bls12_446>,
    public: (&PublicParams<Bls12_446>, &PublicCommit<Bls12_446>),
    metadata: &[u8],
) -> Result<(), ()> {
    super::verify(proof, public, metadata)
}

// ---------------------------------------------------------------------------
// prove_impl – GPU variant of super::prove_impl
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn prove_impl(
    public: (&PublicParams<Bls12_446>, &PublicCommit<Bls12_446>),
    private_commit: &PrivateCommit<Bls12_446>,
    metadata: &[u8],
    load: ComputeLoad,
    seed: &[u8],
    sanity_check_mode: ProofSanityCheckMode,
) -> Proof<Bls12_446> {
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
        // decoded_q <= 2^64 and t >= 1, so the quotient always fits in u64
        (decoded_q / t as u128) as u64
    };

    let g = G1::GENERATOR;
    let g_hat = G2::GENERATOR;
    let mut gamma_list = [Zp::ZERO; 2];
    Zp::hash(&mut gamma_list, &[ds.hash_gamma(), seed]);
    let [gamma, gamma_y] = gamma_list;

    let r1 = compute_r1(e1, c1, a, r, d, decoded_q);
    let r2 = compute_r2(e2, c2, m, b, r, d, delta, decoded_q);

    let mut w = vec![false; n];

    // Reinterpret as unsigned for bit decomposition; bit pattern is preserved,
    // which is correct for torus arithmetic
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
            c_hat += G2::projective(g_hat_list[j]);
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

    let mut y = vec![Zp::ZERO; n];
    Zp::hash(
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

    // GPU MSM: c_y commitment
    let scalars = (n + 1 - big_d..n + 1)
        .map(|j| y[n + 1 - j] * Zp::from_u64(w[n + 1 - j] as u64))
        .collect::<Vec<_>>();
    let c_y = g.mul_scalar(gamma_y)
        + crate::gpu::g1_msm_gpu(&g_list.0[n - big_d..n], &scalars, select_gpu_for_msm());

    let mut theta = vec![Zp::ZERO; d + k + 1];
    Zp::hash(
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

    let mut a_theta = vec![Zp::ZERO; big_d];

    compute_a_theta::<Bls12_446>(
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

    let mut t = vec![Zp::ZERO; n];
    Zp::hash_128bit(
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

    let mut delta = [Zp::ZERO; 2];
    Zp::hash(
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

    let mut poly_0 = vec![Zp::ZERO; n + 1];
    let mut poly_1 = vec![Zp::ZERO; big_d + 1];
    let mut poly_2 = vec![Zp::ZERO; n + 1];
    let mut poly_3 = vec![Zp::ZERO; n + 1];

    poly_0[0] = delta_y * gamma_y;
    for i in 1..n + 1 {
        poly_0[n + 1 - i] =
            delta_y * (y[i] * Zp::from_u64(w[i] as u64)) + (delta_eq * t[i] - delta_y) * y[i];

        if i < big_d + 1 {
            poly_0[n + 1 - i] += delta_theta * a_theta[i - 1];
        }
    }

    poly_1[0] = gamma;
    for i in 1..big_d + 1 {
        poly_1[i] = Zp::from_u64(w[i] as u64);
    }

    poly_2[0] = gamma_y;
    for i in 1..big_d + 1 {
        poly_2[n + 1 - i] = y[i] * Zp::from_u64(w[i] as u64);
    }

    for i in 1..n + 1 {
        poly_3[i] = delta_eq * t[i];
    }

    let mut t_theta = Zp::ZERO;
    for i in 0..d {
        t_theta += theta0[i] * Zp::from_i64(c1[i]);
    }
    for i in 0..k {
        t_theta += theta0[d + i] * Zp::from_i64(c2[i]);
    }

    let mul = rayon::join(
        || Zp::poly_mul(&poly_0, &poly_1),
        || Zp::poly_mul(&poly_2, &poly_3),
    );
    let mut poly = Zp::poly_sub(&mul.0, &mul.1);
    if poly.len() > n + 1 {
        poly[n + 1] -= t_theta * delta_theta;
    }

    // GPU MSM: pi commitment
    let pi = g.mul_scalar(poly[0])
        + crate::gpu::g1_msm_gpu(
            &g_list.0[..poly.len() - 1],
            &poly[1..],
            select_gpu_for_msm(),
        );

    if load == ComputeLoad::Proof {
        // GPU MSM: c_hat_t commitment
        let c_hat_t = crate::gpu::g2_msm_gpu(&g_hat_list.0, &t.0, select_gpu_for_msm());
        let scalars = (1..n + 1)
            .map(|i| {
                let i = n + 1 - i;
                (delta_eq * t[i] - delta_y) * y[i]
                    + if i < big_d + 1 {
                        delta_theta * a_theta[i - 1]
                    } else {
                        Zp::ZERO
                    }
            })
            .collect::<Vec<_>>();

        // GPU MSM: c_h commitment
        let c_h = crate::gpu::g1_msm_gpu(&g_list.0[..n], &scalars, select_gpu_for_msm());

        let mut z = Zp::ZERO;
        Zp::hash(
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
        let mut p_t = Zp::ZERO;
        let mut p_h = Zp::ZERO;

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

        let mut w = Zp::ZERO;
        Zp::hash(
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

        let mut poly = vec![Zp::ZERO; n + 1];
        for i in 1..n + 1 {
            poly[i] += w * t[i];
            if i < big_d + 1 {
                poly[n + 1 - i] +=
                    (delta_eq * t[i] - delta_y) * y[i] + delta_theta * a_theta[i - 1];
            } else {
                poly[n + 1 - i] += (delta_eq * t[i] - delta_y) * y[i];
            }
        }

        let mut q = vec![Zp::ZERO; n];
        // Polynomial long division by (X - z)
        for i in (0..n).rev() {
            poly[i] = poly[i] + z * poly[i + 1];
            q[i] = poly[i + 1];
            poly[i + 1] = Zp::ZERO;
        }

        // GPU MSM: pi_kzg commitment
        let pi_kzg = g.mul_scalar(q[0])
            + crate::gpu::g1_msm_gpu(&g_list.0[..n - 1], &q[1..n], select_gpu_for_msm());

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
