//! GPU-accelerated prove/verify for PKE v2.
//!
//! `prove` duplicates the logic of [`crate::proofs::pke_v2::prove_impl`] but replaces every
//! `multi_mul_scalar` call with GPU-accelerated cached MSMs that keep the CRS
//! base points resident on device across calls.  `verify` duplicates
//! [`crate::proofs::pke_v2::verify_impl`] and the two pairing-check helpers
//! (`pairing_check_two_steps`, `pairing_check_batched`) with MSM sites
//! similarly replaced.

// Follow the notation of the paper
#![allow(non_snake_case)]

use crate::curve_api::bls12_446::{Gt, Zp, G1, G2};
use crate::curve_api::{Bls12_446, CurveGroupOps, FieldOps};
use crate::four_squares::*;
use crate::proofs::{
    assert_pke_proof_preconditions, compute_r1, compute_r2, decode_q, run_in_pool, ComputeLoad,
    GroupElements, ProofSanityCheckMode,
};

use crate::proofs::pke_v2::hashes::RHash;
use crate::proofs::pke_v2::{
    bit_iter, compute_a_theta, compute_crs_params, inf_norm_bound_to_euclidean_squared,
    precompute_xi_powers, ComputeLoadProofFields, EvaluationPoints, GeneratedScalars,
    PkeV2SupportedHashConfig, PrivateCommit, Proof, PublicCommit, PublicParams,
    VerificationPairingMode,
};

use rayon::prelude::*;
use tfhe_cuda_backend::cuda_bind::{cuda_create_stream, cuda_destroy_stream};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// GPU-accelerated proof generation for PKE v2.
///
/// Identical to [`crate::proofs::pke_v2::prove`] but dispatches MSM to the GPU via
/// cached device-resident CRS base points.
pub fn prove(
    public: (&PublicParams<Bls12_446>, &PublicCommit<Bls12_446>),
    private_commit: &PrivateCommit<Bls12_446>,
    metadata: &[u8],
    load: ComputeLoad,
    seed: &[u8],
) -> Proof<Bls12_446> {
    run_in_pool(|| {
        prove_impl(
            public,
            private_commit,
            metadata,
            load,
            seed,
            PkeV2SupportedHashConfig::default(),
            ProofSanityCheckMode::Panic,
        )
    })
}

/// GPU-accelerated verification for PKE v2.
///
/// Identical to [`crate::proofs::pke_v2::verify`] but dispatches MSM to the GPU via
/// cached device-resident CRS base points.
// TODO: `run_in_pool` was introduced for the CPU path because benchmarks showed better
// performance with fewer threads (likely due to arkworks MSM parallelization overhead).
// This may not hold for the GPU implementation and should be revisited.
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
// prove_impl – GPU variant of crate::proofs::pke_v2::prove_impl
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
    _ = load;
    let timing = std::env::var("ZK_VERIFY_TIMING").is_ok();
    let prove_start = std::time::Instant::now();
    let mut t_phase = std::time::Instant::now();

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

    // Acquire persistent device cache for both G1 and G2 base points.
    // Only immutable base-point pointers are cached; streams and scratch
    // buffers are created per-call to avoid races under concurrency.
    let cache = super::acquire_cached_msm_resources(g_list, g_hat_list);
    let cache = &cache;

    // Distribute 3 MSM slots across available GPUs via round-robin.
    // For 1 GPU: [0, 0, 0]. For 3+ GPUs: [0, 1, 2].
    let num_gpus = cache.num_gpus;
    let gpu_indices: [u32; 3] = [0, 1 % num_gpus, 2 % num_gpus];
    // SAFETY: gpu_indices[i] < num_gpus, which is always valid (get_num_gpus asserts >= 1)
    let streams: [super::SendPtr; 3] = [
        super::SendPtr(unsafe { cuda_create_stream(gpu_indices[0]) }),
        super::SendPtr(unsafe { cuda_create_stream(gpu_indices[1]) }),
        super::SendPtr(unsafe { cuda_create_stream(gpu_indices[2]) }),
    ];

    let g1_max_n = u32::try_from(g_list.len()).expect("g_list length fits in u32");
    let g2_max_n = u32::try_from(g_hat_list.len()).expect("g_hat_list length fits in u32");

    let mut g1_msm_raw: [*mut std::ffi::c_void; 3] = [std::ptr::null_mut(); 3];
    let mut g2_msm_raw: [*mut std::ffi::c_void; 3] = [std::ptr::null_mut(); 3];
    for i in 0..3 {
        let mut tracker: u64 = 0;
        let mut g1_typed: *mut zk_cuda_backend::bindings::zk_g1_msm_mem = std::ptr::null_mut();
        // SAFETY: streams[i] is valid. g1_typed receives the allocation.
        unsafe {
            zk_cuda_backend::bindings::scratch_zk_g1_msm(
                streams[i].0 as zk_cuda_backend::bindings::cudaStream_t,
                gpu_indices[i],
                &mut g1_typed,
                g1_max_n,
                &mut tracker,
                true,
            );
        }
        g1_msm_raw[i] = g1_typed as *mut std::ffi::c_void;
        let mut tracker: u64 = 0;
        let mut g2_typed: *mut zk_cuda_backend::bindings::zk_g2_msm_mem = std::ptr::null_mut();
        // SAFETY: streams[i] is valid. g2_typed receives the allocation.
        unsafe {
            zk_cuda_backend::bindings::scratch_zk_g2_msm(
                streams[i].0 as zk_cuda_backend::bindings::cudaStream_t,
                gpu_indices[i],
                &mut g2_typed,
                g2_max_n,
                &mut tracker,
                true,
            );
        }
        g2_msm_raw[i] = g2_typed as *mut std::ffi::c_void;
    }
    // Wrap in SendPtr so the arrays can be borrowed across rayon scopes
    // (each slot is used by exactly one thread).
    let g1_msm_mems = g1_msm_raw.map(super::SendPtr);
    let g2_msm_mems = g2_msm_raw.map(super::SendPtr);

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

    let scalars_e = e1_zp
        .iter()
        .copied()
        .chain(e2_zp.iter().copied())
        .chain(v_zp)
        .collect::<Box<[_]>>();
    let scalars_e_rev: Box<[_]> = scalars_e.iter().copied().rev().collect();
    let scalars_r: Box<[_]> = r1_zp.iter().chain(r2_zp.iter()).copied().collect();

    if timing {
        eprintln!(
            "[ZK_PROVE_TIMING] setup+scalars: {:.1}ms",
            t_phase.elapsed().as_secs_f64() * 1000.0
        );
        t_phase = std::time::Instant::now();
    }

    let mut C_hat_e = None;
    let mut C_e = None;
    let mut C_r_tilde = None;

    rayon::scope(|s| {
        s.spawn(|_| {
            // GPU MSM: C_hat_e commitment (G2, offset 0, n=d+k+4)
            C_hat_e = Some(
                g_hat.mul_scalar(gamma_hat_e)
                    + super::g2_msm_cached_on_stream(
                        g2_msm_mems[0].0,
                        cache.cached_g2[gpu_indices[0] as usize],
                        0,
                        &scalars_e,
                        streams[0].0,
                        gpu_indices[0],
                    ),
            );
        });

        s.spawn(|_| {
            // GPU MSM: C_e commitment (G1, offset n-(d+k+4))
            C_e = Some(
                g.mul_scalar(gamma_e)
                    + super::g1_msm_cached_on_stream(
                        g1_msm_mems[1].0,
                        cache.cached_g1[gpu_indices[1] as usize],
                        u32::try_from(n - (d + k + 4)).expect("point offset fits in u32"),
                        &scalars_e_rev,
                        streams[1].0,
                        gpu_indices[1],
                    ),
            );
        });

        s.spawn(|_| {
            // GPU MSM: C_r_tilde commitment (G1, offset 0, n=d+k)
            C_r_tilde = Some(
                g.mul_scalar(gamma_r)
                    + super::g1_msm_cached_on_stream(
                        g1_msm_mems[2].0,
                        cache.cached_g1[gpu_indices[2] as usize],
                        0,
                        &scalars_r,
                        streams[2].0,
                        gpu_indices[2],
                    ),
            );
        });
    });

    let C_hat_e = C_hat_e.unwrap();
    let C_e = C_e.unwrap();
    let C_r_tilde = C_r_tilde.unwrap();

    if timing {
        eprintln!(
            "[ZK_PROVE_TIMING] initial_commitments: {:.1}ms",
            t_phase.elapsed().as_secs_f64() * 1000.0
        );
        t_phase = std::time::Instant::now();
    }

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
                i64::try_from(acc).expect("w_R element must fit in i64")
            } else {
                acc as i64
            }
        })
        .collect::<Box<[_]>>();

    // GPU MSM: C_R commitment (G1, offset 0, n=128)
    let C_R = g.mul_scalar(gamma_R)
        + super::g1_msm_cached_on_stream(
            g1_msm_mems[0].0,
            cache.cached_g1[gpu_indices[0] as usize],
            0,
            &w_R.iter().copied().map(Zp::from_i64).collect::<Box<[_]>>(),
            streams[0].0,
            gpu_indices[0],
        );

    let C_R_bytes = C_R.to_le_bytes();
    let (phi, phi_hash) = R_hash.gen_phi(C_R_bytes.as_ref());

    let mut t_sub = std::time::Instant::now();

    // Precompute R^T * phi: for each column j of R, compute sum_i(phi[i] * R(i,j)).
    // The full vector has 2*(d+k)+4 entries covering both the poly_1/C_h2/P_h2 range
    // (first d+k+4 columns) and the poly_2/C_hat_h3/P_h3 range (next d+k columns).
    // Each column is independent, so we parallelize across columns with rayon.
    let r_transpose_phi: Vec<Zp> = (0..2 * (d + k) + 4)
        .into_par_iter()
        .map(|j| {
            let mut acc = Zp::ZERO;
            for (i, &phi_val) in phi.iter().enumerate() {
                match R(i, j) {
                    0 => {}
                    1 => acc += phi_val,
                    -1 => acc -= phi_val,
                    _ => unreachable!(),
                }
            }
            acc
        })
        .collect();

    if timing {
        eprintln!(
            "[ZK_PROVE_TIMING]   r_transpose_phi: {:.1}ms (2*(d+k)+4={} cols)",
            t_sub.elapsed().as_secs_f64() * 1000.0,
            2 * (d + k) + 4,
        );
    }

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

    // Sparse point sum: add g_hat_list[i] for each bit set in w_bin.
    // Parallelized via chunked partial sums to use multiple cores.
    let C_hat_bin = {
        const CHUNK: usize = 1024;
        let partial_sums: Vec<G2> = g_hat_list
            .par_chunks(CHUNK)
            .zip(w_bin.par_chunks(CHUNK))
            .map(|(bases, flags)| {
                bases
                    .iter()
                    .zip(flags)
                    .filter(|&(_, &w)| w)
                    .map(|(&x, _)| G2::projective(x))
                    .sum::<G2>()
            })
            .collect();
        g_hat.mul_scalar(gamma_bin) + partial_sums.into_iter().sum::<G2>()
    };

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

    // GPU MSM: C_y commitment (G1, offset n-(D+128*m))
    let C_y = g.mul_scalar(gamma_y)
        + super::g1_msm_cached_on_stream(
            g1_msm_mems[0].0,
            cache.cached_g1[gpu_indices[0] as usize],
            u32::try_from(n - (D + 128 * m)).expect("point offset fits in u32"),
            &scalars,
            streams[0].0,
            gpu_indices[0],
        );

    let C_y_bytes = C_y.to_le_bytes();
    let (t, t_hash) = y_hash.gen_t(C_y_bytes.as_ref());

    if timing {
        eprintln!(
            "[ZK_PROVE_TIMING] hash_chain_1: {:.1}ms",
            t_phase.elapsed().as_secs_f64() * 1000.0
        );
        t_phase = std::time::Instant::now();
    }

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

    // Precompute xi powers to enable parallel polynomial construction
    let xi_powers = precompute_xi_powers(&xi, m);
    let delta_theta_q = delta_theta * Zp::from_u128(decoded_q);

    if timing {
        eprintln!(
            "[ZK_PROVE_TIMING] hash_chain_2: {:.1}ms",
            t_phase.elapsed().as_secs_f64() * 1000.0
        );
        t_phase = std::time::Instant::now();
    }

    // Overlap polynomial construction (CPU-heavy) with independent commitment
    // MSMs (GPU-heavy). 5 of the 6 commitment MSMs depend only on values
    // already available after hash_chain_2 (delta_*, theta, omega, a_theta, y,
    // t, xi_powers, r_transpose_phi). Only the pi MSM needs P_pi, which comes
    // from poly construction, so pi runs at the end of the poly spawn.
    //
    // 6 MSMs distributed across 3 streams:
    //   G1 side: pi (stream 0), C_h1 (stream 1), C_h2 (stream 2)
    //   G2 side: C_hat_h3 (stream 0), C_hat_w (stream 1), C_hat_t (stream 2)
    // G1 and G2 scratch buffers are independent, so a stream can run one G1
    // and one G2 MSM concurrently without contention.
    let mut pi = None;
    let mut C_h1 = None;
    let mut C_h2 = None;
    let mut compute_load_proof_fields = None;
    let mut C_hat_t = None;

    rayon::scope(|s| {
        // --- Independent MSMs: launch GPU work immediately ---

        s.spawn(|_| {
            // GPU MSM: C_h1 commitment (G1, stream 1, offset n-(D+128*m))
            let scalars_h1: Box<[_]> = (0..D + 128 * m)
                .rev()
                .map(|j| {
                    let mut acc = Zp::ZERO;
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
            C_h1 = Some(super::g1_msm_cached_on_stream(
                g1_msm_mems[1].0,
                cache.cached_g1[gpu_indices[1] as usize],
                u32::try_from(n - (D + 128 * m)).expect("point offset fits in u32"),
                &scalars_h1,
                streams[1].0,
                gpu_indices[1],
            ));
        });

        s.spawn(|_| {
            // GPU MSM: C_h2 commitment (G1, stream 2, offset 0, n=n)
            let scalars_h2: Box<[_]> = (0..n)
                .rev()
                .map(|j| {
                    let mut acc = Zp::ZERO;
                    if j < d + k {
                        acc += delta_theta * theta[j];
                    }

                    acc += delta_e * omega[j];

                    if j < d + k + 4 {
                        acc += delta_r * r_transpose_phi[j];
                    }
                    acc
                })
                .collect();
            C_h2 = Some(super::g1_msm_cached_on_stream(
                g1_msm_mems[2].0,
                cache.cached_g1[gpu_indices[2] as usize],
                0,
                &scalars_h2,
                streams[2].0,
                gpu_indices[2],
            ));
        });

        s.spawn(|_| {
            // GPU MSMs: C_hat_h3 (G2, stream 0) + C_hat_w (G2, stream 1)
            compute_load_proof_fields = Some(match load {
                ComputeLoad::Proof => {
                    let mut C_hat_h3 = None;
                    let mut C_hat_w = None;

                    rayon::scope(|s_inner| {
                        s_inner.spawn(|_| {
                            C_hat_h3 = Some(super::g2_msm_cached_on_stream(
                                g2_msm_mems[0].0,
                                cache.cached_g2[gpu_indices[0] as usize],
                                u32::try_from(n - (d + k)).expect("point offset fits in u32"),
                                &(0..d + k)
                                    .rev()
                                    .map(|j| {
                                        delta_r * r_transpose_phi[d + k + 4 + j]
                                            - delta_theta_q * theta[j]
                                    })
                                    .collect::<Box<[_]>>(),
                                streams[0].0,
                                gpu_indices[0],
                            ));
                        });

                        s_inner.spawn(|_| {
                            C_hat_w = Some(super::g2_msm_cached_on_stream(
                                g2_msm_mems[1].0,
                                cache.cached_g2[gpu_indices[1] as usize],
                                0,
                                &omega[..d + k + 4],
                                streams[1].0,
                                gpu_indices[1],
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
            // GPU MSM: C_hat_t (G2, stream 2, offset 0, n=full g_hat_list)
            C_hat_t = Some(super::g2_msm_cached_on_stream(
                g2_msm_mems[2].0,
                cache.cached_g2[gpu_indices[2] as usize],
                0,
                &t,
                streams[2].0,
                gpu_indices[2],
            ));
        });

        // --- Polynomial construction + pi MSM (depends on P_pi) ---

        s.spawn(|_| {
            if timing {
                t_sub = std::time::Instant::now();
            }

            // Build all 6 polynomial pairs in parallel
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

            rayon::scope(|s_poly| {
                s_poly.spawn(|_| {
                    let mut lhs = vec![Zp::ZERO; 1 + n];
                    let mut rhs = vec![Zp::ZERO; 1 + D + 128 * m];

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
                            *p = Zp::ONE;
                        }
                    }

                    poly_0_lhs = Some(lhs);
                    poly_0_rhs = Some(rhs);
                });

                s_poly.spawn(|_| {
                    let mut lhs = vec![Zp::ZERO; 1 + n];
                    let mut rhs = vec![Zp::ZERO; 1 + d + k + 4];

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
                            acc += delta_r * r_transpose_phi[j];
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

                s_poly.spawn(|_| {
                    let mut lhs = vec![Zp::ZERO; 1 + d + k];
                    let mut rhs = vec![Zp::ZERO; 1 + n];

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
                        *p = delta_r * r_transpose_phi[d + k + 4 + j] - delta_theta_q * theta[j];
                    }

                    poly_2_lhs = Some(lhs);
                    poly_2_rhs = Some(rhs);
                });

                s_poly.spawn(|_| {
                    let mut lhs = vec![Zp::ZERO; 1 + 128];
                    let mut rhs = vec![Zp::ZERO; 1 + n];

                    lhs[0] = gamma_R;
                    for j in 0..128 {
                        let p = &mut lhs[1 + j];
                        *p = Zp::from_i64(w_R[j]);
                    }

                    for j in 0..128 {
                        let p = &mut rhs[n - j];
                        *p = delta_r * phi[j] + delta_dec * xi_powers[j * m];
                    }

                    poly_3_lhs = Some(lhs);
                    poly_3_rhs = Some(rhs);
                });

                s_poly.spawn(|_| {
                    let mut lhs = vec![Zp::ZERO; 1 + n];
                    let mut rhs = vec![Zp::ZERO; 1 + d + k + 4];

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

                s_poly.spawn(|_| {
                    let mut lhs = vec![Zp::ZERO; 1 + n];
                    let mut rhs = vec![Zp::ZERO; 1 + n];

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

            if timing {
                eprintln!(
                    "[ZK_PROVE_TIMING]   poly_pairs: {:.1}ms",
                    t_sub.elapsed().as_secs_f64() * 1000.0,
                );
                t_sub = std::time::Instant::now();
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

            if timing {
                eprintln!(
                    "[ZK_PROVE_TIMING]   poly_mul: {:.1}ms",
                    t_sub.elapsed().as_secs_f64() * 1000.0,
                );
                t_sub = std::time::Instant::now();
            }

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

            if timing {
                eprintln!(
                    "[ZK_PROVE_TIMING]   poly_accumulate: {:.1}ms",
                    t_sub.elapsed().as_secs_f64() * 1000.0,
                );
            }

            let mut P_pi = poly_0;
            if P_pi.len() > n + 1 {
                P_pi[n + 1] -= delta_theta * t_theta + delta_l * Zp::from_u128(B_squared);
            }

            // GPU MSM: pi commitment (G1, stream 0, offset 0)
            // This is the only MSM that depends on poly construction results.
            pi = Some(if P_pi.is_empty() {
                G1::ZERO
            } else {
                g.mul_scalar(P_pi[0])
                    + super::g1_msm_cached_on_stream(
                        g1_msm_mems[0].0,
                        cache.cached_g1[gpu_indices[0] as usize],
                        0,
                        &P_pi[1..],
                        streams[0].0,
                        gpu_indices[0],
                    )
            });
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

    if timing {
        eprintln!(
            "[ZK_PROVE_TIMING] poly+msms_overlapped: {:.1}ms",
            t_phase.elapsed().as_secs_f64() * 1000.0
        );
        t_phase = std::time::Instant::now();
    }

    let (z, z_hash) = delta_hash.gen_z::<Zp>(
        C_h1_bytes.as_ref(),
        C_h2_bytes.as_ref(),
        C_hat_t_bytes.as_ref(),
        &C_hat_h3_bytes,
        &C_hat_w_bytes,
    );

    // Compute P_t and P_omega inline (too cheap to justify a rayon task)
    let P_t = {
        let mut poly = vec![Zp::ZERO; 1 + n];
        poly[1..].copy_from_slice(&t);
        poly
    };
    let P_omega = match load {
        ComputeLoad::Proof => {
            let mut poly = vec![Zp::ZERO; 1 + d + k + 4];
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
            let mut poly = vec![Zp::ZERO; 1 + n];
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
            let mut poly = vec![Zp::ZERO; 1 + n];
            for j in 0..n {
                let p = &mut poly[n - j];

                if j < d + k {
                    *p += delta_theta * theta[j];
                }

                *p += delta_e * omega[j];

                if j < d + k + 4 {
                    *p += delta_r * r_transpose_phi[j];
                }
            }
            P_h2 = Some(poly);
        });

        s.spawn(|_| {
            P_h3 = Some(match load {
                ComputeLoad::Proof => {
                    let mut poly = vec![Zp::ZERO; 1 + n];
                    for j in 0..d + k {
                        let p = &mut poly[n - j];
                        *p = delta_r * r_transpose_phi[d + k + 4 + j] - delta_theta_q * theta[j];
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
        let mut pow = Zp::ONE;
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
                    .sum::<Zp>(),
            );
        });

        s.spawn(|_| {
            p_h2 = Some(
                P_h2.iter()
                    .zip(z_powers.iter())
                    .map(|(&p, &pow)| p * pow)
                    .sum::<Zp>(),
            );
        });

        s.spawn(|_| {
            p_t = Some(
                P_t.iter()
                    .zip(z_powers.iter())
                    .map(|(&p, &pow)| p * pow)
                    .sum::<Zp>(),
            );
        });

        s.spawn(|_| {
            p_h3 = Some(if P_h3.is_empty() {
                Zp::ZERO
            } else {
                P_h3.iter()
                    .zip(z_powers.iter())
                    .map(|(&p, &pow)| p * pow)
                    .sum::<Zp>()
            });
        });

        s.spawn(|_| {
            p_omega = Some(if P_omega.is_empty() {
                Zp::ZERO
            } else {
                P_omega
                    .iter()
                    .zip(z_powers.iter())
                    .map(|(&p, &pow)| p * pow)
                    .sum::<Zp>()
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

    // GPU MSM: pi_kzg commitment (G1, offset 0, n=n-1)
    let pi_kzg = g.mul_scalar(q[0])
        + super::g1_msm_cached_on_stream(
            g1_msm_mems[0].0,
            cache.cached_g1[gpu_indices[0] as usize],
            0,
            &q[1..n],
            streams[0].0,
            gpu_indices[0],
        );

    if timing {
        eprintln!(
            "[ZK_PROVE_TIMING] kzg_phase: {:.1}ms",
            t_phase.elapsed().as_secs_f64() * 1000.0
        );
        eprintln!(
            "[ZK_PROVE_TIMING] prove_total: {:.1}ms",
            prove_start.elapsed().as_secs_f64() * 1000.0
        );
    }

    // Cleanup per-call scratch buffers and destroy streams.
    // Extract raw pointers back from SendPtr wrappers for the cleanup FFI calls.
    for i in 0..3 {
        let mut g1_typed = g1_msm_mems[i].0 as *mut zk_cuda_backend::bindings::zk_g1_msm_mem;
        let mut g2_typed = g2_msm_mems[i].0 as *mut zk_cuda_backend::bindings::zk_g2_msm_mem;
        // SAFETY: g1/g2_typed were allocated by their respective scratch functions
        // on streams[i]. All MSM work has completed.
        unsafe {
            zk_cuda_backend::bindings::cleanup_zk_g1_msm(
                streams[i].0 as zk_cuda_backend::bindings::cudaStream_t,
                gpu_indices[i],
                &mut g1_typed,
                true,
            );
            zk_cuda_backend::bindings::cleanup_zk_g2_msm(
                streams[i].0 as zk_cuda_backend::bindings::cudaStream_t,
                gpu_indices[i],
                &mut g2_typed,
                true,
            );
            cuda_destroy_stream(streams[i].0, gpu_indices[i]);
        }
    }

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
// verify_impl – GPU variant of crate::proofs::pke_v2::verify_impl
// ---------------------------------------------------------------------------

#[allow(clippy::result_unit_err)]
fn verify_impl(
    proof: &Proof<Bls12_446>,
    public: (&PublicParams<Bls12_446>, &PublicCommit<Bls12_446>),
    metadata: &[u8],
    pairing_mode: VerificationPairingMode,
) -> Result<(), ()> {
    let timing = std::env::var("ZK_VERIFY_TIMING").is_ok();
    let verify_start = std::time::Instant::now();

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
        ref g_lists,
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

    let _hash_chain_start = std::time::Instant::now();
    let mut t_sub = std::time::Instant::now();

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

    if timing {
        eprintln!(
            "[ZK_VERIFY_TIMING]   RHash::new: {:.1}ms",
            t_sub.elapsed().as_secs_f64() * 1000.0
        );
        t_sub = std::time::Instant::now();
    }

    let C_R_bytes = C_R.to_le_bytes();
    let (phi, phi_hash) = R_hash.gen_phi(C_R_bytes.as_ref());

    let C_hat_bin_bytes = C_hat_bin.to_le_bytes();
    let (xi, xi_hash) = phi_hash.gen_xi::<Zp>(C_hat_bin_bytes.as_ref());

    let (y, y_hash) = xi_hash.gen_y::<Zp>();

    if timing {
        eprintln!(
            "[ZK_VERIFY_TIMING]   phi+xi+y: {:.1}ms",
            t_sub.elapsed().as_secs_f64() * 1000.0
        );
        t_sub = std::time::Instant::now();
    }

    // Precompute R^T * phi: for each column j of R, compute sum_i(phi[i] * R(i,j)).
    // The full vector has 2*(d+k)+4 entries covering both the P_h2 range (first d+k+4
    // columns) and the P_h3 / MSM-scalar range (next d+k columns). Each column is
    // independent, so we parallelize across columns with rayon.
    let r_transpose_phi: Vec<Zp> = (0..2 * (d + k) + 4)
        .into_par_iter()
        .map(|j| {
            let mut acc = Zp::ZERO;
            for (i, &phi_val) in phi.iter().enumerate() {
                match R(i, j) {
                    0 => {}
                    1 => acc += phi_val,
                    -1 => acc -= phi_val,
                    _ => unreachable!(),
                }
            }
            acc
        })
        .collect();

    if timing {
        eprintln!(
            "[ZK_VERIFY_TIMING]   r_transpose_phi: {:.1}ms (2*(d+k)+4={} cols)",
            t_sub.elapsed().as_secs_f64() * 1000.0,
            2 * (d + k) + 4,
        );
        t_sub = std::time::Instant::now();
    }

    let C_y_bytes = C_y.to_le_bytes();
    let (t, t_hash) = y_hash.gen_t::<Zp>(C_y_bytes.as_ref());

    let (theta, theta_hash) = t_hash.gen_theta();

    let t_theta = theta
        .iter()
        .copied()
        .zip(c1.iter().chain(c2.iter()).copied().map(Zp::from_i64))
        .map(|(x, y)| x * y)
        .sum::<Zp>();

    // --- Start compute_a_theta on a dedicated rayon pool ---
    // compute_a_theta is the single most expensive CPU operation (~18ms).
    // It only needs theta (available now), not omega or delta. By starting
    // it here, it overlaps with gen_omega, gen_delta, cache acquisition,
    // MSM scratch allocation, and MSM launch.
    let a_theta_handle = {
        let theta = theta.clone();
        let a = a.to_vec();
        let b = b.to_vec();
        // Use a small dedicated pool to avoid saturating all cores.
        // compute_a_theta uses rayon internally (poly_mul), and the
        // global pool (128 threads) would starve concurrent pairing threads.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("failed to build compute_a_theta thread pool");
        std::thread::spawn(move || {
            pool.install(|| {
                let mut a_theta = vec![Zp::ZERO; D];
                compute_a_theta::<Bls12_446>(
                    &mut a_theta,
                    &theta,
                    &a,
                    d,
                    k,
                    &b,
                    effective_cleartext_t,
                    delta_encoding,
                );
                a_theta
            })
        })
    };

    let (omega, omega_hash) = theta_hash.gen_omega();

    let load = if compute_load_proof_fields.is_some() {
        ComputeLoad::Proof
    } else {
        ComputeLoad::Verify
    };

    let (delta, delta_hash) = omega_hash.gen_delta::<Zp>();
    let [delta_r, delta_dec, delta_eq, delta_y, delta_theta, delta_e, delta_l] = delta;

    let delta_theta_q = delta_theta * Zp::from_u128(decoded_q);

    if timing {
        eprintln!(
            "[ZK_VERIFY_TIMING]   t+theta+omega+delta: {:.1}ms",
            t_sub.elapsed().as_secs_f64() * 1000.0
        );
        t_sub = std::time::Instant::now();
    }

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

    // Precompute doubling powers of xi so the P_h1 loop has no sequential
    // dependency on xi_scaled.  xi_powers[i*m + k] = 2^k * xi[i].
    let xi_powers = precompute_xi_powers(&xi, m);

    if timing {
        eprintln!(
            "[ZK_VERIFY_TIMING]   gen_z+xi_powers: {:.1}ms",
            t_sub.elapsed().as_secs_f64() * 1000.0
        );
    }

    match pairing_mode {
        VerificationPairingMode::TwoSteps => {
            // =================================================================
            // Two-phase pairing optimization
            // =================================================================
            // Phase 1 (rayon::scope): 9 chi-independent pairings on the
            //   verify rayon pool + polynomial evaluation on a spawned task.
            // Phase 2 (rayon::join): 2 chi-dependent pairings.
            // =================================================================

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

            let g_list = &*g_lists.g_list.0;
            let g_hat_list = &*g_lists.g_hat_list.0;

            let pairing = Gt::pairing;
            let g = G1::GENERATOR;
            let g_hat = G2::GENERATOR;

            let phase1_start = std::time::Instant::now();

            // Phase 1: 9 pairings + poly work on the verify rayon pool.
            let mut rhs = None;
            let mut lhs0 = None;
            let mut lhs1 = None;
            let mut lhs2 = None;
            let mut lhs3 = None;
            let mut lhs4 = None;
            let mut lhs5 = None;
            let mut lhs6 = None;
            let mut rhs_eq2 = None;
            let mut poly_results: Option<(Zp, Zp, Zp, Zp, Zp, Zp)> = None;

            rayon::scope(|s| {
                // --- 9 chi-independent pairings ---
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
                            None => super::g2_msm_gpu(
                                &g_hat_list[n - (d + k)..n],
                                &(0..d + k)
                                    .rev()
                                    .map(|j| {
                                        delta_r * r_transpose_phi[d + k + 4 + j]
                                            - delta_theta_q * theta[j]
                                    })
                                    .collect::<Box<[_]>>(),
                                super::select_gpu_for_msm(),
                            ),
                        },
                    ))
                });
                s.spawn(|_| {
                    lhs3 = Some(pairing(
                        C_R,
                        super::g2_msm_gpu(
                            &g_hat_list[n - 128..n],
                            &(0..128)
                                .rev()
                                .map(|j| delta_r * phi[j] + delta_dec * xi[j])
                                .collect::<Box<[_]>>(),
                            super::select_gpu_for_msm(),
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
                            None => super::g2_msm_gpu(
                                &g_hat_list[..d + k + 4],
                                &omega[..d + k + 4],
                                super::select_gpu_for_msm(),
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
                    rhs_eq2 = Some(pairing(
                        pi_kzg,
                        G2::projective(g_hat_list[0]) - g_hat.mul_scalar(z),
                    ))
                });

                // --- Poly work task: z_powers + fused polynomial evaluation ---
                s.spawn(|_| {
                    let z_powers = {
                        let mut powers = Vec::with_capacity(n + 1);
                        let mut pow = Zp::ONE;
                        for _ in 0..=n {
                            powers.push(pow);
                            pow = pow * z;
                        }
                        powers
                    };

                    // Fused P_h2(z) evaluation (no array allocation).
                    let mut p_h2 = Zp::ZERO;
                    for j in 0..n {
                        let mut coeff = delta_e * omega[j];
                        if j < d + k {
                            coeff += delta_theta * theta[j];
                        }
                        if j < d + k + 4 {
                            coeff += delta_r * r_transpose_phi[j];
                        }
                        p_h2 += coeff * z_powers[n - j];
                    }

                    // Fused P_t(z) evaluation.
                    let mut p_t = Zp::ZERO;
                    for j in 0..n {
                        p_t += t[j] * z_powers[j + 1];
                    }

                    // Fused P_h3(z) evaluation (Verify mode only, else zero).
                    let p_h3 = match load {
                        ComputeLoad::Proof => {
                            let mut val = Zp::ZERO;
                            for j in 0..d + k {
                                let coeff = delta_r * r_transpose_phi[d + k + 4 + j]
                                    - delta_theta_q * theta[j];
                                val += coeff * z_powers[n - j];
                            }
                            val
                        }
                        ComputeLoad::Verify => Zp::ZERO,
                    };

                    // Fused P_omega(z) evaluation (Proof mode only, else zero).
                    let p_omega = match load {
                        ComputeLoad::Proof => {
                            let mut val = Zp::ZERO;
                            for j in 0..d + k + 4 {
                                val += omega[j] * z_powers[j + 1];
                            }
                            val
                        }
                        ComputeLoad::Verify => Zp::ZERO,
                    };

                    // Join compute_a_theta (was running in parallel).
                    let a_theta = a_theta_handle
                        .join()
                        .expect("compute_a_theta thread panicked");

                    // Fused P_h1(z) evaluation.
                    let mut p_h1 = Zp::ZERO;
                    for j in 0..D + 128 * m {
                        let mut coeff = Zp::ZERO;
                        if j < D {
                            coeff += delta_theta * a_theta[j];
                        }
                        coeff -= delta_y * y[j];
                        coeff += delta_eq * t[j] * y[j];

                        if j >= D {
                            let idx = j - D;
                            let r = delta_dec * xi_powers[idx];
                            if idx % m < m - 1 {
                                coeff += r;
                            } else {
                                coeff -= r;
                            }
                        }
                        p_h1 += coeff * z_powers[n - j];
                    }

                    // Generate chi (needs p_h1, p_h2, p_t and optional p_h3/p_omega).
                    let p_h3_opt = match load {
                        ComputeLoad::Proof => Some(p_h3),
                        ComputeLoad::Verify => None,
                    };
                    let p_omega_opt = match load {
                        ComputeLoad::Proof => Some(p_omega),
                        ComputeLoad::Verify => None,
                    };
                    let chi = z_hash.gen_chi(p_h1, p_h2, p_t, p_h3_opt, p_omega_opt);

                    poly_results = Some((p_h1, p_h2, p_t, p_h3, p_omega, chi));
                });
            });

            let (p_h1, p_h2, p_t, p_h3, p_omega, chi) = poly_results.unwrap();

            if timing {
                eprintln!(
                    "[ZK_VERIFY_TIMING] phase1 (9 pairings + poly): {:.1}ms",
                    phase1_start.elapsed().as_secs_f64() * 1000.0,
                );
            }

            let rhs = rhs.unwrap();
            let lhs0 = lhs0.unwrap();
            let lhs1 = lhs1.unwrap();
            let lhs2 = lhs2.unwrap();
            let lhs3 = lhs3.unwrap();
            let lhs4 = lhs4.unwrap();
            let lhs5 = lhs5.unwrap();
            let lhs6 = lhs6.unwrap();
            let rhs_eq2 = rhs_eq2.unwrap();

            let chi2 = chi * chi;
            let chi3 = chi2 * chi;
            let chi4 = chi3 * chi;

            // Phase 2: 2 chi-dependent pairings.
            let phase2_start = std::time::Instant::now();

            let (lhs0_eq2, lhs1_eq2) = rayon::join(
                || {
                    pairing(
                        C_h1 + C_h2.mul_scalar(chi) - g.mul_scalar(p_h1 + chi * p_h2),
                        g_hat,
                    )
                },
                || {
                    pairing(
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
                    )
                },
            );

            if timing {
                eprintln!(
                    "[ZK_VERIFY_TIMING] phase2 (2 pairings): {:.1}ms",
                    phase2_start.elapsed().as_secs_f64() * 1000.0,
                );
                eprintln!(
                    "[ZK_VERIFY_TIMING] verify_total: {:.1}ms",
                    verify_start.elapsed().as_secs_f64() * 1000.0,
                );
            }

            // Check equation 1.
            let lhs = lhs0 + lhs1 + lhs2 - lhs3 - lhs4 - lhs5 - lhs6;
            if lhs != rhs {
                return Err(());
            }

            // Check equation 2.
            let lhs = lhs0_eq2 + lhs1_eq2;
            if lhs != rhs_eq2 {
                Err(())
            } else {
                Ok(())
            }
        }
        VerificationPairingMode::Batched => {
            // =================================================================
            // Batched pairing mode – keep existing sequential approach.
            // =================================================================

            // Join compute_a_theta.
            let a_theta = a_theta_handle
                .join()
                .expect("compute_a_theta thread panicked");

            // Build polynomial arrays.
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

            rayon::join(
                || {
                    for j in 0..D + 128 * m {
                        let p = &mut P_h1[n - j];
                        if j < D {
                            *p += delta_theta * a_theta[j];
                        }
                        *p -= delta_y * y[j];
                        *p += delta_eq * t[j] * y[j];

                        if j >= D {
                            let idx = j - D;
                            let r = delta_dec * xi_powers[idx];
                            if idx % m < m - 1 {
                                *p += r;
                            } else {
                                *p -= r;
                            }
                        }
                    }
                },
                || {
                    for j in 0..n {
                        let p = &mut P_h2[n - j];
                        if j < d + k {
                            *p += delta_theta * theta[j];
                        }
                        *p += delta_e * omega[j];
                        if j < d + k + 4 {
                            *p += delta_r * r_transpose_phi[j];
                        }
                    }
                },
            );

            P_t[1..].copy_from_slice(&t);

            if !P_h3.is_empty() {
                for j in 0..d + k {
                    let p = &mut P_h3[n - j];
                    *p = delta_r * r_transpose_phi[d + k + 4 + j] - delta_theta_q * theta[j];
                }
            }

            if !P_omega.is_empty() {
                P_omega[1..].copy_from_slice(&omega[..d + k + 4]);
            }

            // Precompute z^0..z^n for parallel evaluation.
            let z_powers = {
                let mut powers = Vec::with_capacity(n + 1);
                let mut pow = Zp::ONE;
                for _ in 0..=n {
                    powers.push(pow);
                    pow = pow * z;
                }
                powers
            };

            let (p_h1, p_h2, p_t, p_h3, p_omega) = {
                let ((p_h1, p_h2), (p_t, (p_h3, p_omega))) = rayon::join(
                    || {
                        rayon::join(
                            || P_h1.iter().zip(&z_powers).map(|(&c, &p)| c * p).sum::<Zp>(),
                            || P_h2.iter().zip(&z_powers).map(|(&c, &p)| c * p).sum::<Zp>(),
                        )
                    },
                    || {
                        rayon::join(
                            || P_t.iter().zip(&z_powers).map(|(&c, &p)| c * p).sum::<Zp>(),
                            || {
                                rayon::join(
                                    || {
                                        if P_h3.is_empty() {
                                            Zp::ZERO
                                        } else {
                                            P_h3.iter()
                                                .zip(&z_powers)
                                                .map(|(&c, &p)| c * p)
                                                .sum::<Zp>()
                                        }
                                    },
                                    || {
                                        if P_omega.is_empty() {
                                            Zp::ZERO
                                        } else {
                                            P_omega
                                                .iter()
                                                .zip(&z_powers)
                                                .map(|(&c, &p)| c * p)
                                                .sum::<Zp>()
                                        }
                                    },
                                )
                            },
                        )
                    },
                );
                (p_h1, p_h2, p_t, p_h3, p_omega)
            };

            let p_h3_opt = if P_h3.is_empty() { None } else { Some(p_h3) };
            let p_omega_opt = if P_omega.is_empty() {
                None
            } else {
                Some(p_omega)
            };

            let chi = z_hash.gen_chi(p_h1, p_h2, p_t, p_h3_opt, p_omega_opt);

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
                r_transpose_phi,
            };

            let eval_points = EvaluationPoints {
                p_h1,
                p_h2,
                p_h3,
                p_t,
                p_omega,
            };

            let result = pairing_check_batched(
                proof,
                g_lists,
                n,
                d,
                B_squared,
                decoded_q,
                k,
                scalars,
                eval_points,
            );

            if timing {
                eprintln!(
                    "[ZK_VERIFY_TIMING] verify_total: {:.1}ms",
                    verify_start.elapsed().as_secs_f64() * 1000.0,
                );
            }

            result
        }
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
        r_transpose_phi,
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
                    super::g2_msm_gpu(
                        &g_hat_list[n - (d + k)..n],
                        &(0..d + k)
                            .rev()
                            .map(|j| {
                                delta_r * r_transpose_phi[d + k + 4 + j] - delta_theta_q * theta[j]
                            })
                            .collect::<Box<[_]>>(),
                        super::select_gpu_for_msm(),
                    ),
                ))
            }
        });
        s.spawn(|_| {
            // GPU MSM: pairing argument for C_R (batched)
            lhs3 = Some(pairing(
                C_R,
                super::g2_msm_gpu(
                    &g_hat_list[n - 128..n],
                    &(0..128)
                        .rev()
                        .map(|j| delta_r * phi[j] + delta_dec * xi[j])
                        .collect::<Box<[_]>>(),
                    super::select_gpu_for_msm(),
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
                    super::g2_msm_gpu(
                        &g_hat_list[..d + k + 4],
                        &omega[..d + k + 4],
                        super::select_gpu_for_msm(),
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
