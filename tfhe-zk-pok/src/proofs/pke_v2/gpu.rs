//! GPU-accelerated prove/verify for PKE v2.
//!
//! `prove` duplicates the logic of [`super::prove_impl`] but replaces every
//! `multi_mul_scalar` call with the GPU-accelerated [`crate::gpu::g1_msm_gpu`]
//! / [`crate::gpu::g2_msm_gpu`].  `verify` duplicates [`super::verify_impl`]
//! and the two pairing-check helpers (`pairing_check_two_steps`,
//! `pairing_check_batched`) with MSM sites similarly replaced.

// Follow the notation of the paper
#![allow(non_snake_case)]

use crate::curve_api::bls12_446::{Gt, Zp, G1, G2};
use crate::curve_api::{Bls12_446, CurveGroupOps, FieldOps};
use crate::four_squares::*;
use crate::gpu::select_gpu_for_msm;
use crate::proofs::{
    assert_pke_proof_preconditions, compute_r1, compute_r2, decode_q, run_in_pool, ComputeLoad,
    GroupElements, ProofSanityCheckMode,
};

use super::hashes::RHash;
use super::{
    bit_iter, compute_a_theta, compute_crs_params, inf_norm_bound_to_euclidean_squared,
    ComputeLoadProofFields, EvaluationPoints, GeneratedScalars, PkeV2SupportedHashConfig,
    PrivateCommit, Proof, PublicCommit, PublicParams, VerificationPairingMode,
};

use rayon::prelude::*;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// GPU-accelerated proof generation for PKE v2.
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
        PkeV2SupportedHashConfig::default(),
        ProofSanityCheckMode::Panic,
    )
}

/// GPU-accelerated verification for PKE v2.
///
/// Identical to [`super::verify`] but dispatches MSM to the GPU via
/// [`crate::gpu::g1_msm_gpu`] / [`crate::gpu::g2_msm_gpu`].
#[allow(clippy::result_unit_err)]
pub fn verify(
    proof: &Proof<Bls12_446>,
    public: (&PublicParams<Bls12_446>, &PublicCommit<Bls12_446>),
    metadata: &[u8],
    pairing_mode: VerificationPairingMode,
) -> Result<(), ()> {
    run_in_pool(|| verify_impl(proof, public, metadata, pairing_mode))
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
    hash_config: PkeV2SupportedHashConfig,
    sanity_check_mode: ProofSanityCheckMode,
) -> Proof<Bls12_446> {
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
        assert_eq!(G1::projective(g_list[n]), G1::ZERO);
    }

    // FIXME: div_round
    let delta = {
        // delta takes the encoding with the padding bit
        (decoded_q / t_input as u128) as u64
    };

    let g = G1::GENERATOR;
    let g_hat = G2::GENERATOR;
    let mut gamma_list = [Zp::ZERO; 6];
    Zp::hash(&mut gamma_list, &[ds.hash_gamma(), seed]);
    let [gamma_e, gamma_hat_e, gamma_r, gamma_R, gamma_bin, gamma_y] = gamma_list;

    let r1 = compute_r1(e1, c1, a, r, d, decoded_q);
    let r2 = compute_r2(e2, c2, m, b, r, d, delta, decoded_q);

    // Reinterpret as unsigned for bit decomposition; bit pattern is preserved,
    // which is correct for torus arithmetic
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

    let e1_zp = &*e1.iter().copied().map(Zp::from_i64).collect::<Box<[_]>>();
    let e2_zp = &*e2.iter().copied().map(Zp::from_i64).collect::<Box<[_]>>();
    let v_zp = v.map(Zp::from_i64);

    let r1_zp = &*r1.iter().copied().map(Zp::from_i64).collect::<Box<[_]>>();
    let r2_zp = &*r2.iter().copied().map(Zp::from_i64).collect::<Box<[_]>>();

    // GPU MSM: C_hat_e commitment
    let mut scalars = e1_zp
        .iter()
        .copied()
        .chain(e2_zp.iter().copied())
        .chain(v_zp)
        .collect::<Box<[_]>>();
    let C_hat_e = g_hat.mul_scalar(gamma_hat_e)
        + crate::gpu::g2_msm_gpu(&g_hat_list[..d + k + 4], &scalars, select_gpu_for_msm());

    // GPU MSM: C_e and C_r_tilde commitments (parallelised)
    let (C_e, C_r_tilde) = rayon::join(
        || {
            scalars.reverse();
            g.mul_scalar(gamma_e)
                + crate::gpu::g1_msm_gpu(
                    &g_list[n - (d + k + 4)..n],
                    &scalars,
                    select_gpu_for_msm(),
                )
        },
        || {
            let scalars = r1_zp
                .iter()
                .chain(r2_zp.iter())
                .copied()
                .collect::<Box<[_]>>();
            g.mul_scalar(gamma_r)
                + crate::gpu::g1_msm_gpu(&g_list[..d + k], &scalars, select_gpu_for_msm())
        },
    );

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
            i64::try_from(acc).expect("w_R element must fit in i64")
        })
        .collect::<Box<[_]>>();

    // GPU MSM: C_R commitment
    let C_R = g.mul_scalar(gamma_R)
        + crate::gpu::g1_msm_gpu(
            &g_list[..128],
            &w_R.iter().copied().map(Zp::from_i64).collect::<Box<[_]>>(),
            select_gpu_for_msm(),
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
            .map(G2::projective)
            .sum::<G2>();

    let C_hat_bin_bytes = C_hat_bin.to_le_bytes();
    let (xi, xi_hash) = phi_hash.gen_xi::<Zp>(C_hat_bin_bytes.as_ref());

    let (y, y_hash) = xi_hash.gen_y::<Zp>();

    if sanity_check_mode == ProofSanityCheckMode::Panic {
        assert_eq!(y.len(), w_bin.len());
    }
    let scalars = y
        .iter()
        .zip(w_bin.iter())
        .rev()
        .map(|(&y, &w)| if w { y } else { Zp::ZERO })
        .collect::<Box<[_]>>();

    // GPU MSM: C_y commitment
    let C_y = g.mul_scalar(gamma_y)
        + crate::gpu::g1_msm_gpu(
            &g_list[n - (D + 128 * m)..n],
            &scalars,
            select_gpu_for_msm(),
        );

    let C_y_bytes = C_y.to_le_bytes();
    let (t, t_hash) = y_hash.gen_t(C_y_bytes.as_ref());

    let (theta, theta_hash) = t_hash.gen_theta();

    let mut a_theta = vec![Zp::ZERO; D];
    compute_a_theta::<Bls12_446>(
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
        .zip(c1.iter().chain(c2.iter()).copied().map(Zp::from_i64))
        .map(|(x, y)| x * y)
        .sum::<Zp>();

    let (omega, omega_hash) = theta_hash.gen_omega();

    let (delta, delta_hash) = omega_hash.gen_delta::<Zp>();
    let [delta_r, delta_dec, delta_eq, delta_y, delta_theta, delta_e, delta_l] = delta;

    let mut poly_0_lhs = vec![Zp::ZERO; 1 + n];
    let mut poly_0_rhs = vec![Zp::ZERO; 1 + D + 128 * m];
    let mut poly_1_lhs = vec![Zp::ZERO; 1 + n];
    let mut poly_1_rhs = vec![Zp::ZERO; 1 + d + k + 4];
    let mut poly_2_lhs = vec![Zp::ZERO; 1 + d + k];
    let mut poly_2_rhs = vec![Zp::ZERO; 1 + n];
    let mut poly_3_lhs = vec![Zp::ZERO; 1 + 128];
    let mut poly_3_rhs = vec![Zp::ZERO; 1 + n];
    let mut poly_4_lhs = vec![Zp::ZERO; 1 + n];
    let mut poly_4_rhs = vec![Zp::ZERO; 1 + d + k + 4];
    let mut poly_5_lhs = vec![Zp::ZERO; 1 + n];
    let mut poly_5_rhs = vec![Zp::ZERO; 1 + n];

    let mut xi_scaled = xi;
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
            *p = Zp::ONE;
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
        let mut acc = delta_e * omega[j];
        if j < d + k {
            acc += delta_theta * theta[j];
        }

        if j < d + k + 4 {
            let mut acc2 = Zp::ZERO;
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

    let delta_theta_q = delta_theta * Zp::from_u128(decoded_q);
    for j in 0..d + k {
        let p = &mut poly_2_rhs[n - j];

        let mut acc = Zp::ZERO;
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
        *p = Zp::from_i64(w_R[j]);
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
        *p = omega[j];
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
        let tmp: Box<[Vec<Zp>; 6]> = poly
            .into_par_iter()
            .map(|(lhs, rhs)| Zp::poly_mul(lhs, rhs))
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

    poly_0.resize(len, Zp::ZERO);

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
        P_pi[n + 1] -= delta_theta * t_theta + delta_l * Zp::from_u128(B_squared);
    }

    // GPU MSM: pi commitment
    let pi = if P_pi.is_empty() {
        G1::ZERO
    } else {
        g.mul_scalar(P_pi[0])
            + crate::gpu::g1_msm_gpu(&g_list[..P_pi.len() - 1], &P_pi[1..], select_gpu_for_msm())
    };

    // GPU MSM: C_h1 commitment
    let mut xi_scaled = xi;
    let mut scalars = (0..D + 128 * m)
        .map(|j| {
            let mut acc = Zp::ZERO;
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
    let C_h1 = crate::gpu::g1_msm_gpu(
        &g_list[n - (D + 128 * m)..n],
        &scalars,
        select_gpu_for_msm(),
    );

    // GPU MSM: C_h2 commitment
    let mut scalars = (0..n)
        .map(|j| {
            let mut acc = Zp::ZERO;
            if j < d + k {
                acc += delta_theta * theta[j];
            }

            acc += delta_e * omega[j];

            if j < d + k + 4 {
                let mut acc2 = Zp::ZERO;
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
    let C_h2 = crate::gpu::g1_msm_gpu(&g_list[..n], &scalars, select_gpu_for_msm());

    let compute_load_proof_fields = match load {
        ComputeLoad::Proof => {
            // GPU MSM: C_hat_h3 and C_hat_w commitments (parallelised)
            let (C_hat_h3, C_hat_w) = rayon::join(
                || {
                    crate::gpu::g2_msm_gpu(
                        &g_hat_list[n - (d + k)..n],
                        &(0..d + k)
                            .rev()
                            .map(|j| {
                                let mut acc = Zp::ZERO;
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
                        select_gpu_for_msm(),
                    )
                },
                || {
                    crate::gpu::g2_msm_gpu(
                        &g_hat_list[..d + k + 4],
                        &omega[..d + k + 4],
                        select_gpu_for_msm(),
                    )
                },
            );

            Some(ComputeLoadProofFields { C_hat_h3, C_hat_w })
        }
        ComputeLoad::Verify => None,
    };

    // GPU MSM: C_hat_t commitment
    let C_hat_t = crate::gpu::g2_msm_gpu(g_hat_list, &t, select_gpu_for_msm());

    let (C_hat_h3_bytes, C_hat_w_bytes) =
        ComputeLoadProofFields::to_le_bytes(&compute_load_proof_fields);

    let C_h1_bytes = C_h1.to_le_bytes();
    let C_h2_bytes = C_h2.to_le_bytes();
    let C_hat_t_bytes = C_hat_t.to_le_bytes();

    let (z, z_hash) = delta_hash.gen_z::<Zp>(
        C_h1_bytes.as_ref(),
        C_h2_bytes.as_ref(),
        C_hat_t_bytes.as_ref(),
        &C_hat_h3_bytes,
        &C_hat_w_bytes,
    );

    let mut P_h1 = vec![Zp::ZERO; 1 + n];
    let mut P_h2 = vec![Zp::ZERO; 1 + n];
    let mut P_t = vec![Zp::ZERO; 1 + n];
    let mut P_h3 = match load {
        ComputeLoad::Proof => vec![Zp::ZERO; 1 + n],
        ComputeLoad::Verify => vec![],
    };
    let mut P_omega = match load {
        ComputeLoad::Proof => vec![Zp::ZERO; 1 + d + k + 4],
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
            let mut acc = Zp::ZERO;
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

            let mut acc = Zp::ZERO;
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

    let mut p_h1 = Zp::ZERO;
    let mut p_h2 = Zp::ZERO;
    let mut p_t = Zp::ZERO;
    let mut p_h3 = Zp::ZERO;
    let mut p_omega = Zp::ZERO;

    let mut pow = Zp::ONE;
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

    let mut Q_kzg = vec![Zp::ZERO; 1 + n];
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

    // Polynomial long division by (X - z)
    let mut q = vec![Zp::ZERO; n];
    for j in (0..n).rev() {
        Q_kzg[j] = Q_kzg[j] + z * Q_kzg[j + 1];
        q[j] = Q_kzg[j + 1];
        Q_kzg[j + 1] = Zp::ZERO;
    }

    // GPU MSM: pi_kzg commitment
    let pi_kzg = g.mul_scalar(q[0])
        + crate::gpu::g1_msm_gpu(&g_list[..n - 1], &q[1..n], select_gpu_for_msm());

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

// ---------------------------------------------------------------------------
// verify_impl – GPU variant of super::verify_impl
// ---------------------------------------------------------------------------

#[allow(clippy::result_unit_err)]
fn verify_impl(
    proof: &Proof<Bls12_446>,
    public: (&PublicParams<Bls12_446>, &PublicCommit<Bls12_446>),
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
    let (xi, xi_hash) = phi_hash.gen_xi::<Zp>(C_hat_bin_bytes.as_ref());

    let (y, y_hash) = xi_hash.gen_y::<Zp>();

    let C_y_bytes = C_y.to_le_bytes();
    let (t, t_hash) = y_hash.gen_t(C_y_bytes.as_ref());

    let (theta, theta_hash) = t_hash.gen_theta();

    let t_theta = theta
        .iter()
        .copied()
        .zip(c1.iter().chain(c2.iter()).copied().map(Zp::from_i64))
        .map(|(x, y)| x * y)
        .sum::<Zp>();

    let (omega, omega_hash) = theta_hash.gen_omega();

    let (delta, delta_hash) = omega_hash.gen_delta::<Zp>();
    let [delta_r, delta_dec, delta_eq, delta_y, delta_theta, delta_e, _delta_l] = delta;

    let delta_theta_q = delta_theta * Zp::from_u128(decoded_q);

    let mut a_theta = vec![Zp::ZERO; D];
    compute_a_theta::<Bls12_446>(
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

    let (z, z_hash) = delta_hash.gen_z::<Zp>(
        C_h1_bytes.as_ref(),
        C_h2_bytes.as_ref(),
        C_hat_t_bytes.as_ref(),
        &C_hat_h3_bytes,
        &C_hat_w_bytes,
    );

    let mut P_h1 = vec![Zp::ZERO; 1 + n];
    let mut P_h2 = vec![Zp::ZERO; 1 + n];
    let mut P_t = vec![Zp::ZERO; 1 + n];
    let mut P_h3 = match load {
        ComputeLoad::Proof => vec![Zp::ZERO; 1 + n],
        ComputeLoad::Verify => vec![],
    };
    let mut P_omega = match load {
        ComputeLoad::Proof => vec![Zp::ZERO; 1 + d + k + 4],
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
            let mut acc = Zp::ZERO;
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

            let mut acc = Zp::ZERO;
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

    let mut p_h1 = Zp::ZERO;
    let mut p_h2 = Zp::ZERO;
    let mut p_t = Zp::ZERO;
    let mut p_h3 = Zp::ZERO;
    let mut p_omega = Zp::ZERO;

    let mut pow = Zp::ONE;
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

// ---------------------------------------------------------------------------
// pairing_check_two_steps
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn pairing_check_two_steps(
    proof: &Proof<Bls12_446>,
    g_lists: &GroupElements<Bls12_446>,
    n: usize,
    d: usize,
    B_squared: u128,
    decoded_q: u128,
    k: usize,
    R: impl Fn(usize, usize) -> i8 + Sync,
    scalars: GeneratedScalars<Bls12_446>,
    eval_points: EvaluationPoints<Bls12_446>,
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

    let delta_theta_q = delta_theta * Zp::from_u128(decoded_q);

    let pairing = Gt::pairing;
    let g = G1::GENERATOR;
    let g_hat = G2::GENERATOR;

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
                    // GPU MSM: C_hat_h3 on-the-fly during verify
                    None => crate::gpu::g2_msm_gpu(
                        &g_hat_list[n - (d + k)..n],
                        &(0..d + k)
                            .rev()
                            .map(|j| {
                                let mut acc = Zp::ZERO;
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
                        select_gpu_for_msm(),
                    ),
                },
            ))
        });
        s.spawn(|_| {
            // GPU MSM: pairing argument for C_R
            lhs3 = Some(pairing(
                C_R,
                crate::gpu::g2_msm_gpu(
                    &g_hat_list[n - 128..n],
                    &(0..128)
                        .rev()
                        .map(|j| delta_r * phi[j] + delta_dec * xi[j])
                        .collect::<Box<[_]>>(),
                    select_gpu_for_msm(),
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
                    // GPU MSM: C_hat_w on-the-fly during verify
                    None => crate::gpu::g2_msm_gpu(
                        &g_hat_list[..d + k + 4],
                        &omega[..d + k + 4],
                        select_gpu_for_msm(),
                    ),
                },
            ))
        });
        s.spawn(|_| lhs5 = Some(pairing(C_y.mul_scalar(delta_eq), C_hat_t)));
        s.spawn(|_| {
            lhs6 = Some(
                pairing(G1::projective(g_list[0]), G2::projective(g_hat_list[n - 1]))
                    .mul_scalar(delta_theta * t_theta + delta_l * Zp::from_u128(B_squared)),
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
                G2::projective(g_hat_list[0]) - g_hat.mul_scalar(z),
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

// ---------------------------------------------------------------------------
// pairing_check_batched
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn pairing_check_batched(
    proof: &Proof<Bls12_446>,
    g_lists: &GroupElements<Bls12_446>,
    n: usize,
    d: usize,
    B_squared: u128,
    decoded_q: u128,
    k: usize,
    R: impl Fn(usize, usize) -> i8 + Sync,
    scalars: GeneratedScalars<Bls12_446>,
    eval_points: EvaluationPoints<Bls12_446>,
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

    let delta_theta_q = delta_theta * Zp::from_u128(decoded_q);

    let pairing = Gt::pairing;
    let g = G1::GENERATOR;
    let g_hat = G2::GENERATOR;

    let mut rhs = None;
    let mut lhs0 = None;
    let mut lhs1 = None;
    let mut lhs2 = None;
    let mut lhs3 = None;
    let mut lhs4 = None;
    let mut lhs5 = None;
    let mut lhs6 = None;

    // TODO: should the user be able to control the randomness source here?
    let eta = Zp::rand(&mut rand::thread_rng());

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
                // GPU MSM: C_hat_h3 on-the-fly during verify (batched)
                lhs2 = Some(pairing(
                    C_r_tilde,
                    crate::gpu::g2_msm_gpu(
                        &g_hat_list[n - (d + k)..n],
                        &(0..d + k)
                            .rev()
                            .map(|j| {
                                let mut acc = Zp::ZERO;
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
                        select_gpu_for_msm(),
                    ),
                ))
            }
        });
        s.spawn(|_| {
            // GPU MSM: pairing argument for C_R (batched)
            lhs3 = Some(pairing(
                C_R,
                crate::gpu::g2_msm_gpu(
                    &g_hat_list[n - 128..n],
                    &(0..128)
                        .rev()
                        .map(|j| delta_r * phi[j] + delta_dec * xi[j])
                        .collect::<Box<[_]>>(),
                    select_gpu_for_msm(),
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
                // GPU MSM: C_hat_w on-the-fly during verify (batched)
                lhs4 = Some(pairing(
                    C_e.mul_scalar(delta_e),
                    crate::gpu::g2_msm_gpu(
                        &g_hat_list[..d + k + 4],
                        &omega[..d + k + 4],
                        select_gpu_for_msm(),
                    ),
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
                -G1::projective(g_list[n - 1])
                    .mul_scalar(delta_theta * t_theta + delta_l * Zp::from_u128(B_squared))
                    - pi_kzg.mul_scalar(eta),
                G2::projective(g_hat_list[0]),
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
