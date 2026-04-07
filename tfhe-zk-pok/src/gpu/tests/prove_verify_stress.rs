//! Stress tests comparing GPU and CPU prove/verify for PKE v2.

#![allow(non_snake_case)]

use crate::curve_api::Bls12_446;
use crate::gpu::pke_v2 as gpu_pke_v2;
use crate::proofs::pke_v2::VerificationPairingMode;
use crate::proofs::test::*;
use crate::proofs::{pke_v2, ComputeLoad};
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, SeedableRng};

type Curve = Bls12_446;

const NB_ZK_PKE_V2_EQ_ROUNDS: usize = 20;
const NB_ZK_PKE_V2_EQ_ROUNDS_MINIMAL: usize = 3;

fn get_zk_long_run_rounds() -> usize {
    if let Ok(val) = std::env::var("TFHE_RS_ZK_GPU_LONGRUN_ROUNDS") {
        return val.parse::<usize>().unwrap_or_else(|e| {
            panic!("TFHE_RS_ZK_GPU_LONGRUN_ROUNDS={val:?} is not a valid usize: {e}")
        });
    }

    let is_minimal =
        std::env::var("TFHE_RS_TEST_LONG_TESTS_MINIMAL").is_ok_and(|v| v.to_uppercase() == "TRUE");

    if is_minimal {
        NB_ZK_PKE_V2_EQ_ROUNDS_MINIMAL
    } else {
        NB_ZK_PKE_V2_EQ_ROUNDS
    }
}

fn get_zk_long_run_base_seed() -> u64 {
    if let Ok(val) = std::env::var("TFHE_RS_LONGRUN_TESTS_SEED") {
        if let Ok(s) = val.parse::<u128>() {
            return s as u64;
        }
    }
    thread_rng().gen()
}

fn run_pke_v2_gpu_cpu_equivalence_round(seed: u64) {
    let params = crate::proofs::pke_v2::tests::PKEV2_TEST_PARAMS;
    let PkeTestParameters {
        d,
        k,
        B,
        q,
        t,
        msbs_zero_padding_bit_count,
    } = params;

    let rng = &mut StdRng::seed_from_u64(seed);

    let testcase = PkeTestcase::gen(rng, params);
    let ct = testcase.encrypt(params);

    let invalid_testcase = PkeTestcase::gen(rng, params);

    // Mirrors production where CRS is larger than message count.
    let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

    let original_public_param =
        pke_v2::crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);
    let public_param_that_was_compressed =
        serialize_then_deserialize(&original_public_param, Compress::Yes).unwrap();
    let public_param_that_was_not_compressed =
        serialize_then_deserialize(&original_public_param, Compress::No).unwrap();

    let cases = itertools::iproduct!(
        [
            original_public_param,
            public_param_that_was_compressed,
            public_param_that_was_not_compressed
        ],
        [false, true], // r
        [false, true], // e1
        [false, true], // e2
        [false, true], // m
        [false, true]  // metadata
    );

    for (
        public_param,
        use_invalid_r,
        use_invalid_e1,
        use_invalid_e2,
        use_invalid_m,
        use_invalid_metadata,
    ) in cases
    {
        let (public_commit, private_commit) = pke_v2::commit(
            testcase.a.clone(),
            testcase.b.clone(),
            ct.c1.clone(),
            ct.c2.clone(),
            (if use_invalid_r {
                &invalid_testcase.r
            } else {
                &testcase.r
            })
            .clone(),
            (if use_invalid_e1 {
                &invalid_testcase.e1
            } else {
                &testcase.e1
            })
            .clone(),
            (if use_invalid_m {
                &invalid_testcase.m
            } else {
                &testcase.m
            })
            .clone(),
            (if use_invalid_e2 {
                &invalid_testcase.e2
            } else {
                &testcase.e2
            })
            .clone(),
            &public_param,
        );

        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let cpu_proof = pke_v2::prove(
                (&public_param, &public_commit),
                &private_commit,
                &testcase.metadata,
                load,
                &seed.to_le_bytes(),
            );

            let gpu_proof = gpu_pke_v2::prove(
                (&public_param, &public_commit),
                &private_commit,
                &testcase.metadata,
                load,
                &seed.to_le_bytes(),
            );

            // GPU MSM is exact, so proofs must be byte-identical.
            assert_eq!(
                bincode::serialize(&cpu_proof).unwrap(),
                bincode::serialize(&gpu_proof).unwrap(),
                "v2 proof mismatch: seed={seed:#x}, load={load}, \
                 invalid_r={use_invalid_r}, invalid_e1={use_invalid_e1}, \
                 invalid_e2={use_invalid_e2}, invalid_m={use_invalid_m}",
            );

            let verify_metadata = if use_invalid_metadata {
                &invalid_testcase.metadata
            } else {
                &testcase.metadata
            };

            let should_fail = use_invalid_e1
                || use_invalid_e2
                || use_invalid_r
                || use_invalid_m
                || use_invalid_metadata;

            for pairing_mode in [
                VerificationPairingMode::TwoSteps,
                VerificationPairingMode::Batched,
            ] {
                let cpu_verify_result = pke_v2::verify(
                    &gpu_proof,
                    (&public_param, &public_commit),
                    verify_metadata,
                    pairing_mode,
                );
                assert_eq!(
                    cpu_verify_result.is_err(),
                    should_fail,
                    "v2 CPU verify mismatch: seed={seed:#x}, load={load}, \
                     mode={pairing_mode:?}, should_fail={should_fail}",
                );

                let gpu_verify_result = gpu_pke_v2::verify(
                    &gpu_proof,
                    (&public_param, &public_commit),
                    verify_metadata,
                    pairing_mode,
                );
                assert_eq!(
                    gpu_verify_result.is_err(),
                    should_fail,
                    "v2 GPU verify mismatch: seed={seed:#x}, load={load}, \
                     mode={pairing_mode:?}, should_fail={should_fail}",
                );

                assert_eq!(
                    cpu_verify_result, gpu_verify_result,
                    "v2 CPU/GPU verify disagree: seed={seed:#x}, load={load}, \
                     mode={pairing_mode:?}",
                );

                // Exercises GPU verifier with a CPU-constructed proof object.
                let gpu_verify_cpu_proof = gpu_pke_v2::verify(
                    &cpu_proof,
                    (&public_param, &public_commit),
                    verify_metadata,
                    pairing_mode,
                );
                assert_eq!(
                    gpu_verify_cpu_proof, cpu_verify_result,
                    "v2 GPU-verify-of-CPU-proof disagrees with CPU-verify: \
                     seed={seed:#x}, load={load}, mode={pairing_mode:?}",
                );
            }
        }
    }
}

#[test]
fn test_pke_v2_gpu_cpu_equivalence() {
    let seed: u64 = thread_rng().gen();
    println!("test_pke_v2_gpu_cpu_equivalence seed: {seed:#x}");
    run_pke_v2_gpu_cpu_equivalence_round(seed);
}

#[test]
fn test_pke_v2_gpu_cpu_equivalence_long_run() {
    let base_seed = get_zk_long_run_base_seed();
    let rounds = get_zk_long_run_rounds();

    println!("test_pke_v2_gpu_cpu_equivalence_long_run: base_seed={base_seed:#x}, rounds={rounds}");

    // PRNG-derived seeds avoid collisions that wrapping_add would produce for close base seeds.
    let mut seed_rng = StdRng::seed_from_u64(base_seed);
    for round in 0..rounds {
        let round_seed: u64 = seed_rng.gen();
        println!("  round {round}/{rounds}: seed={round_seed:#x}");
        run_pke_v2_gpu_cpu_equivalence_round(round_seed);
    }
}
