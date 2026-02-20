//! Stress tests comparing GPU and CPU prove/verify for PKE v1 and v2.
//!
//! These tests mirror the `test_pke()` functions in `proofs/pke.rs` (v1) and
//! `proofs/pke_v2/mod.rs` (v2), running GPU prove/verify alongside CPU to
//! verify that:
//!   - Serialized proofs are byte-identical between CPU and GPU.
//!   - CPU and GPU verifiers agree on accept/reject for every input.
//!   - Both directions are covered: GPU-prove→GPU-verify and CPU-prove→GPU-verify.
//!
//! Each test iterates over 3 CRS variants (original, compressed, not-compressed)
//! × 32 combinations of invalid inputs (e1, e2, r, m, metadata) × 2 compute
//! loads (Proof, Verify), yielding 192 iterations per test. The v2 test doubles
//! that by also sweeping both pairing modes (TwoSteps, Batched).

use crate::curve_api::Bls12_446;
use crate::proofs::pke_v2::VerificationPairingMode;
use crate::proofs::test::*;
use crate::proofs::{pke, pke_v2, ComputeLoad};
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, SeedableRng};

type Curve = Bls12_446;

/// Exhaustive GPU-vs-CPU equivalence test for PKE v1.
///
/// For every combination of (CRS variant, invalid flag) we:
///   1. Prove on CPU and GPU with identical inputs.
///   2. Assert the serialized proofs are byte-identical.
///   3. Verify the GPU proof on both CPU and GPU, checking that both agree on accept/reject and
///      that the outcome matches the expected validity.
#[test]
fn test_pke_v1_gpu_cpu_equivalence() {
    let params = crate::proofs::pke::tests::PKEV1_TEST_PARAMS;
    let PkeTestParameters {
        d,
        k,
        B,
        q,
        t,
        msbs_zero_padding_bit_count,
    } = params;

    let seed = thread_rng().gen();
    let rng = &mut StdRng::seed_from_u64(seed);

    // Generate a valid test case: keys, randomness, noise, and plaintext
    let valid_testcase = PkeTestcase::gen(rng, params);
    let ct = valid_testcase.encrypt(params);

    // Independent witnesses for rejection testing. The values are
    // in-range (same distribution as `testcase`), but they are the *wrong*
    // witnesses for `ct` — proving with them produces a proof that does not
    // satisfy the ciphertext-witness relation, so verification must reject.
    let invalid_testcase = PkeTestcase::gen(rng, params);

    // CRS k > message count k exercises the path where the CRS is larger
    // than strictly needed, as happens in production
    let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

    // Same three CRS variants as in `test_pke()`: original, round-tripped
    // through compressed serde, and round-tripped through uncompressed serde.
    let original_public_param =
        pke::crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);
    let public_param_that_was_compressed =
        serialize_then_deserialize(&original_public_param, Compress::Yes).unwrap();
    let public_param_that_was_not_compressed =
        serialize_then_deserialize(&original_public_param, Compress::No).unwrap();

    // Runs for all combinations: 3 CRS variants × 32 invalid-witness flags
    let cases = itertools::iproduct!(
        [
            original_public_param,
            public_param_that_was_compressed,
            public_param_that_was_not_compressed
        ],
        [false, true], // e1
        [false, true], // e2
        [false, true], // m
        [false, true], // r
        [false, true]  // metadata
    );

    for (
        public_param,
        use_invalid_e1,
        use_invalid_e2,
        use_invalid_m,
        use_invalid_r,
        use_invalid_metadata,
    ) in cases
    {
        // Build the commit, substituting invalid witnesses where flagged.
        let (public_commit, private_commit) = pke::commit(
            valid_testcase.a.clone(),
            valid_testcase.b.clone(),
            ct.c1.clone(),
            ct.c2.clone(),
            (if use_invalid_r {
                &invalid_testcase.r
            } else {
                &valid_testcase.r
            })
            .clone(),
            (if use_invalid_e1 {
                &invalid_testcase.e1
            } else {
                &valid_testcase.e1
            })
            .clone(),
            (if use_invalid_m {
                &invalid_testcase.m
            } else {
                &valid_testcase.m
            })
            .clone(),
            (if use_invalid_e2 {
                &invalid_testcase.e2
            } else {
                &valid_testcase.e2
            })
            .clone(),
            &public_param,
        );

        // ComputeLoad::Proof shifts work to the prover; ComputeLoad::Verify
        // shifts it to the verifier. Both must yield identical results.
        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            // Produce proofs from identical inputs on CPU and GPU
            let cpu_proof = pke::prove(
                (&public_param, &public_commit),
                &private_commit,
                &valid_testcase.metadata,
                load,
                &seed.to_be_bytes(),
            );

            let gpu_proof = pke::gpu::prove(
                (&public_param, &public_commit),
                &private_commit,
                &valid_testcase.metadata,
                load,
                &seed.to_be_bytes(),
            );

            // GPU MSM is exact integer arithmetic, so the serialized proofs
            // must be byte-for-byte identical
            assert_eq!(
                bincode::serialize(&cpu_proof).unwrap(),
                bincode::serialize(&gpu_proof).unwrap(),
                "v1 proof mismatch: load={load}, invalid_e1={use_invalid_e1}, \
                 invalid_e2={use_invalid_e2}, invalid_m={use_invalid_m}, \
                 invalid_r={use_invalid_r}",
            );

            // When invalid metadata is used at verification time (but not at
            // proving time), the proof is valid but Fiat-Shamir binding fails
            let verify_metadata = if use_invalid_metadata {
                &invalid_testcase.metadata
            } else {
                &valid_testcase.metadata
            };

            // Any single invalid input should cause verification to reject
            let should_fail = use_invalid_e1
                || use_invalid_e2
                || use_invalid_r
                || use_invalid_m
                || use_invalid_metadata;

            // --- Verify GPU proof on CPU ---
            let cpu_verify_result =
                pke::verify(&gpu_proof, (&public_param, &public_commit), verify_metadata);
            assert_eq!(
                cpu_verify_result.is_err(),
                should_fail,
                "v1 CPU verify mismatch: load={load}, should_fail={should_fail}",
            );

            // --- Verify GPU proof on GPU ---
            let gpu_verify_result =
                pke::gpu::verify(&gpu_proof, (&public_param, &public_commit), verify_metadata);
            assert_eq!(
                gpu_verify_result.is_err(),
                should_fail,
                "v1 GPU verify mismatch: load={load}, should_fail={should_fail}",
            );

            // CPU and GPU verifiers must produce the same Result value
            assert_eq!(
                cpu_verify_result, gpu_verify_result,
                "v1 CPU/GPU verify disagree: load={load}",
            );

            // --- Cross-direction: GPU verify of CPU-produced proof ---
            // Although proofs are byte-identical, this exercises pke::gpu::verify
            // with a proof object constructed entirely on the CPU side, ensuring
            // the GPU verifier does not depend on any GPU-side proof metadata.
            let gpu_verify_cpu_proof =
                pke::gpu::verify(&cpu_proof, (&public_param, &public_commit), verify_metadata);
            assert_eq!(
                gpu_verify_cpu_proof, cpu_verify_result,
                "v1 GPU-verify-of-CPU-proof disagrees with CPU-verify: load={load}",
            );
        }
    }
}

/// Exhaustive GPU-vs-CPU equivalence test for PKE v2.
///
/// Same structure as the v1 test but exercises `pke_v2` functions.  Key
/// differences from v1:
///   - Uses `PKEV2_TEST_PARAMS` and `pke_v2::*` functions.
///   - Seed bytes are little-endian (`to_le_bytes`) per v2 convention.
///   - Verify takes a `VerificationPairingMode`; we test both `TwoSteps` and `Batched` and assert
///     they agree.
#[test]
fn test_pke_v2_gpu_cpu_equivalence() {
    let params = crate::proofs::pke_v2::tests::PKEV2_TEST_PARAMS;
    let PkeTestParameters {
        d,
        k,
        B,
        q,
        t,
        msbs_zero_padding_bit_count,
    } = params;

    let seed = thread_rng().gen();
    let rng = &mut StdRng::seed_from_u64(seed);

    // Generate a valid test case: keys, randomness, noise, and plaintext
    let testcase = PkeTestcase::gen(rng, params);
    let ct = testcase.encrypt(params);

    // Independent witnesses for rejection testing. The values are
    // in-range (same distribution as `testcase`), but they are the *wrong*
    // witnesses for `ct` — proving with them produces a proof that does not
    // satisfy the ciphertext-witness relation, so verification must reject.
    let invalid_testcase = PkeTestcase::gen(rng, params);

    // CRS k > message count k exercises the path where the CRS is larger
    // than strictly needed, as happens in production
    let crs_k = k + 1 + (rng.gen::<usize>() % (d - k));

    // Same three CRS variants as in `test_pke()`: original, round-tripped
    // through compressed serde, and round-tripped through uncompressed serde.
    let original_public_param =
        pke_v2::crs_gen::<Curve>(d, crs_k, B, q, t, msbs_zero_padding_bit_count, rng);
    let public_param_that_was_compressed =
        serialize_then_deserialize(&original_public_param, Compress::Yes).unwrap();
    let public_param_that_was_not_compressed =
        serialize_then_deserialize(&original_public_param, Compress::No).unwrap();

    // Sweep all combinations: 3 CRS variants × 32 invalid-witness flags
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
        // Build the commit, substituting invalid witnesses where flagged.
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

        // ComputeLoad::Proof shifts work to the prover; ComputeLoad::Verify
        // shifts it to the verifier. Both must yield identical results.
        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            // Produce proofs from identical inputs on CPU and GPU.
            // v2 convention: seed bytes are little-endian (to_le_bytes).
            let cpu_proof = pke_v2::prove(
                (&public_param, &public_commit),
                &private_commit,
                &testcase.metadata,
                load,
                &seed.to_le_bytes(),
            );

            let gpu_proof = pke_v2::gpu::prove(
                (&public_param, &public_commit),
                &private_commit,
                &testcase.metadata,
                load,
                &seed.to_le_bytes(),
            );

            // GPU MSM is exact integer arithmetic, so the serialized proofs
            // must be byte-for-byte identical
            assert_eq!(
                bincode::serialize(&cpu_proof).unwrap(),
                bincode::serialize(&gpu_proof).unwrap(),
                "v2 proof mismatch: load={load}, invalid_r={use_invalid_r}, \
                 invalid_e1={use_invalid_e1}, invalid_e2={use_invalid_e2}, \
                 invalid_m={use_invalid_m}",
            );

            // When invalid metadata is used at verification time (but not at
            // proving time), the proof is valid but Fiat-Shamir binding fails
            let verify_metadata = if use_invalid_metadata {
                &invalid_testcase.metadata
            } else {
                &testcase.metadata
            };

            // Any single invalid input should cause verification to reject
            let should_fail = use_invalid_e1
                || use_invalid_e2
                || use_invalid_r
                || use_invalid_m
                || use_invalid_metadata;

            // v2 supports two pairing strategies for verification:
            //   - TwoSteps: two independent pairing checks
            //   - Batched: single batched pairing check (faster but same result)
            // Both must agree with each other and with the CPU verifier.
            for pairing_mode in [
                VerificationPairingMode::TwoSteps,
                VerificationPairingMode::Batched,
            ] {
                // --- Verify GPU proof on CPU ---
                let cpu_verify_result = pke_v2::verify(
                    &gpu_proof,
                    (&public_param, &public_commit),
                    verify_metadata,
                    pairing_mode,
                );
                assert_eq!(
                    cpu_verify_result.is_err(),
                    should_fail,
                    "v2 CPU verify mismatch: load={load}, mode={pairing_mode:?}, \
                     should_fail={should_fail}",
                );

                // --- Verify GPU proof on GPU ---
                let gpu_verify_result = pke_v2::gpu::verify(
                    &gpu_proof,
                    (&public_param, &public_commit),
                    verify_metadata,
                    pairing_mode,
                );
                assert_eq!(
                    gpu_verify_result.is_err(),
                    should_fail,
                    "v2 GPU verify mismatch: load={load}, mode={pairing_mode:?}, \
                     should_fail={should_fail}",
                );

                // CPU and GPU verifiers must produce the same Result value
                assert_eq!(
                    cpu_verify_result, gpu_verify_result,
                    "v2 CPU/GPU verify disagree: load={load}, mode={pairing_mode:?}",
                );

                // --- Cross-direction: GPU verify of CPU-produced proof ---
                // Although proofs are byte-identical, this exercises
                // pke_v2::gpu::verify with a proof object constructed entirely
                // on the CPU side, ensuring the GPU verifier does not depend
                // on any GPU-side proof metadata.
                let gpu_verify_cpu_proof = pke_v2::gpu::verify(
                    &cpu_proof,
                    (&public_param, &public_commit),
                    verify_metadata,
                    pairing_mode,
                );
                assert_eq!(
                    gpu_verify_cpu_proof, cpu_verify_result,
                    "v2 GPU-verify-of-CPU-proof disagrees with CPU-verify: load={load}, \
                     mode={pairing_mode:?}",
                );
            }
        }
    }
}
