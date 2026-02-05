//! Tests comparing zk-cuda-backend MSM results against tfhe-zk-pok CPU implementation

use crate::curve_api::bls12_446::{Zp, G1, G2};
use crate::curve_api::CurveGroupOps;
use crate::gpu::{
    g1_affine_from_zk_cuda, g1_affine_to_zk_cuda, g2_affine_from_zk_cuda, g2_affine_to_zk_cuda,
};
use tfhe_cuda_backend::cuda_bind::{cuda_create_stream, cuda_destroy_stream};
use zk_cuda_backend::conversions::{g1_affine_from_montgomery, g2_affine_from_montgomery};
use zk_cuda_backend::{
    G1Affine as ZkG1Affine, G1Projective as ZkG1Projective, G2Affine as ZkG2Affine,
    G2Projective as ZkG2Projective, Scalar as ZkScalar,
};

/// Helper function to compute triangular number: N * (N+1) / 2
fn triangular_number(n: u64) -> u64 {
    n * (n + 1) / 2
}

#[test]
fn test_g1_conversion_roundtrip() {
    let tfhe_g1_gen = G1::GENERATOR.normalize();
    let zk_g1 = g1_affine_to_zk_cuda(&tfhe_g1_gen);
    let tfhe_g1_again = g1_affine_from_zk_cuda(&zk_g1);
    let zk_g1_again = g1_affine_to_zk_cuda(&tfhe_g1_again);

    assert_eq!(zk_g1.x(), zk_g1_again.x());
    assert_eq!(zk_g1.y(), zk_g1_again.y());
}

#[test]
fn test_g2_conversion_roundtrip() {
    let tfhe_g2_gen = G2::GENERATOR.normalize();
    let zk_g2 = g2_affine_to_zk_cuda(&tfhe_g2_gen);
    let tfhe_g2_again = g2_affine_from_zk_cuda(&zk_g2);
    let zk_g2_again = g2_affine_to_zk_cuda(&tfhe_g2_again);

    assert_eq!(zk_g2.x(), zk_g2_again.x());
    assert_eq!(zk_g2.y(), zk_g2_again.y());
}

#[test]
fn test_g1_msm_scalar_one() {
    let tfhe_g1_gen = G1::GENERATOR.normalize();
    let g1_gen = g1_affine_to_zk_cuda(&tfhe_g1_gen);

    let points: Vec<ZkG1Affine> = vec![g1_gen];
    let scalars: Vec<ZkScalar> = vec![ZkScalar::from_u64(1)];

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = match ZkG1Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!(
                "CUDA MSM failed: {} - Skipping test (CUDA may not be available)",
                e
            );
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let result_mont = result_proj.to_affine();
    let result = g1_affine_from_montgomery(&result_mont);
    let result_tfhe = g1_affine_from_zk_cuda(&result);

    // Scalar=1 should return the input point
    assert_eq!(
        g1_affine_to_zk_cuda(&result_tfhe).x(),
        g1_affine_to_zk_cuda(&tfhe_g1_gen).x(),
        "G1 MSM scalar=1 x mismatch"
    );
    assert_eq!(
        g1_affine_to_zk_cuda(&result_tfhe).y(),
        g1_affine_to_zk_cuda(&tfhe_g1_gen).y(),
        "G1 MSM scalar=1 y mismatch"
    );
}

#[test]
fn test_g2_msm_scalar_one() {
    let tfhe_g2_gen = G2::GENERATOR.normalize();
    let g2_gen = g2_affine_to_zk_cuda(&tfhe_g2_gen);

    let points: Vec<ZkG2Affine> = vec![g2_gen];
    let scalars: Vec<ZkScalar> = vec![ZkScalar::from_u64(1)];

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = match ZkG2Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!(
                "CUDA MSM failed: {} - Skipping test (CUDA may not be available)",
                e
            );
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let result_mont = result_proj.to_affine();
    let result = g2_affine_from_montgomery(&result_mont);
    let result_tfhe = g2_affine_from_zk_cuda(&result);

    assert_eq!(
        g2_affine_to_zk_cuda(&result_tfhe).x(),
        g2_affine_to_zk_cuda(&tfhe_g2_gen).x(),
        "G2 MSM scalar=1 x mismatch"
    );
    assert_eq!(
        g2_affine_to_zk_cuda(&result_tfhe).y(),
        g2_affine_to_zk_cuda(&tfhe_g2_gen).y(),
        "G2 MSM scalar=1 y mismatch"
    );
}

#[test]
fn test_g1_msm_vs_cpu() {
    let tfhe_g1_gen = G1::GENERATOR.normalize();
    let g1_gen = g1_affine_to_zk_cuda(&tfhe_g1_gen);

    // Test with multiple points and scalars [1, 2, 3, 4, 5]
    let n = 5;
    let points: Vec<ZkG1Affine> = (0..n).map(|_| g1_gen).collect();
    let scalars: Vec<ZkScalar> = (1..=n as u64).map(ZkScalar::from_u64).collect();

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let gpu_result_proj = match ZkG1Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let gpu_result_mont = gpu_result_proj.to_affine();
    let gpu_result = g1_affine_from_montgomery(&gpu_result_mont);

    // Compute CPU reference: G * (1 + 2 + 3 + 4 + 5) = G * 15
    let expected_scalar = Zp::from_u64(triangular_number(n as u64));
    let cpu_result = G1::GENERATOR.mul_scalar(expected_scalar).normalize();

    let gpu_result_tfhe = g1_affine_from_zk_cuda(&gpu_result);

    assert_eq!(
        g1_affine_to_zk_cuda(&gpu_result_tfhe).x(),
        g1_affine_to_zk_cuda(&cpu_result).x(),
        "G1 MSM x mismatch"
    );
    assert_eq!(
        g1_affine_to_zk_cuda(&gpu_result_tfhe).y(),
        g1_affine_to_zk_cuda(&cpu_result).y(),
        "G1 MSM y mismatch"
    );
}

#[test]
fn test_g2_msm_vs_cpu() {
    let tfhe_g2_gen = G2::GENERATOR.normalize();
    let g2_gen = g2_affine_to_zk_cuda(&tfhe_g2_gen);

    let n = 5;
    let points: Vec<ZkG2Affine> = (0..n).map(|_| g2_gen).collect();
    let scalars: Vec<ZkScalar> = (1..=n as u64).map(ZkScalar::from_u64).collect();

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let gpu_result_proj = match ZkG2Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let gpu_result_mont = gpu_result_proj.to_affine();
    let gpu_result = g2_affine_from_montgomery(&gpu_result_mont);

    let expected_scalar = Zp::from_u64(triangular_number(n as u64));
    let cpu_result = G2::GENERATOR.mul_scalar(expected_scalar).normalize();

    let gpu_result_tfhe = g2_affine_from_zk_cuda(&gpu_result);

    assert_eq!(
        g2_affine_to_zk_cuda(&gpu_result_tfhe).x(),
        g2_affine_to_zk_cuda(&cpu_result).x(),
        "G2 MSM x mismatch"
    );
    assert_eq!(
        g2_affine_to_zk_cuda(&gpu_result_tfhe).y(),
        g2_affine_to_zk_cuda(&cpu_result).y(),
        "G2 MSM y mismatch"
    );
}

#[test]
fn test_g1_msm_multi_limb_scalar() {
    let tfhe_g1_gen = G1::GENERATOR.normalize();
    let g1_gen = g1_affine_to_zk_cuda(&tfhe_g1_gen);

    // Create Scalar = 2^64 (requires 2 limbs)
    let scalar = ZkScalar::new([0u64, 1u64, 0u64, 0u64, 0u64]);
    let points: Vec<ZkG1Affine> = vec![g1_gen];
    let scalars: Vec<ZkScalar> = vec![scalar];

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let gpu_result_proj = match ZkG1Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let gpu_result_mont = gpu_result_proj.to_affine();
    let gpu_result = g1_affine_from_montgomery(&gpu_result_mont);

    // Compute CPU reference
    let cpu_scalar = Zp::from_bigint([0u64, 1u64, 0u64, 0u64, 0u64]);
    let cpu_result = G1::GENERATOR.mul_scalar(cpu_scalar).normalize();

    let gpu_result_tfhe = g1_affine_from_zk_cuda(&gpu_result);

    assert_eq!(
        g1_affine_to_zk_cuda(&gpu_result_tfhe).x(),
        g1_affine_to_zk_cuda(&cpu_result).x(),
        "G1 MSM 2^64 scalar x mismatch"
    );
    assert_eq!(
        g1_affine_to_zk_cuda(&gpu_result_tfhe).y(),
        g1_affine_to_zk_cuda(&cpu_result).y(),
        "G1 MSM 2^64 scalar y mismatch"
    );
}

#[test]
fn test_g1_msm_with_generator_small_scalars() {
    const N: u64 = 10;

    let tfhe_g1_gen = G1::GENERATOR.normalize();
    let g1_gen = g1_affine_to_zk_cuda(&tfhe_g1_gen);

    let points: Vec<ZkG1Affine> = (0..N).map(|_| g1_gen).collect();
    let scalars: Vec<ZkScalar> = (1..=N).map(ZkScalar::from_u64).collect();

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let gpu_result_proj = match ZkG1Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let gpu_result_mont = gpu_result_proj.to_affine();
    let gpu_result = g1_affine_from_montgomery(&gpu_result_mont);

    // Expected: G * (1 + 2 + ... + N) = G * N*(N+1)/2
    let expected_sum = triangular_number(N);
    let cpu_scalar = Zp::from_u64(expected_sum);
    let cpu_result = G1::GENERATOR.mul_scalar(cpu_scalar).normalize();

    let gpu_result_tfhe = g1_affine_from_zk_cuda(&gpu_result);

    assert_eq!(
        g1_affine_to_zk_cuda(&gpu_result_tfhe).x(),
        g1_affine_to_zk_cuda(&cpu_result).x(),
        "G1 MSM small scalars x mismatch"
    );
    assert_eq!(
        g1_affine_to_zk_cuda(&gpu_result_tfhe).y(),
        g1_affine_to_zk_cuda(&cpu_result).y(),
        "G1 MSM small scalars y mismatch"
    );
}

#[test]
fn test_g2_msm_with_generator_small_scalars() {
    const N: u64 = 10;

    let tfhe_g2_gen = G2::GENERATOR.normalize();
    let g2_gen = g2_affine_to_zk_cuda(&tfhe_g2_gen);

    let points: Vec<ZkG2Affine> = (0..N).map(|_| g2_gen).collect();
    let scalars: Vec<ZkScalar> = (1..=N).map(ZkScalar::from_u64).collect();

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let gpu_result_proj = match ZkG2Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let gpu_result_mont = gpu_result_proj.to_affine();
    let gpu_result = g2_affine_from_montgomery(&gpu_result_mont);

    let expected_sum = triangular_number(N);
    let cpu_scalar = Zp::from_u64(expected_sum);
    let cpu_result = G2::GENERATOR.mul_scalar(cpu_scalar).normalize();

    let gpu_result_tfhe = g2_affine_from_zk_cuda(&gpu_result);

    assert_eq!(
        g2_affine_to_zk_cuda(&gpu_result_tfhe).x(),
        g2_affine_to_zk_cuda(&cpu_result).x(),
        "G2 MSM small scalars x mismatch"
    );
    assert_eq!(
        g2_affine_to_zk_cuda(&gpu_result_tfhe).y(),
        g2_affine_to_zk_cuda(&cpu_result).y(),
        "G2 MSM small scalars y mismatch"
    );
}

#[test]
fn test_g1_msm_large_n() {
    const MAX_N: u64 = 100;

    let tfhe_g1_gen = G1::GENERATOR.normalize();
    let g1_gen = g1_affine_to_zk_cuda(&tfhe_g1_gen);

    // Test CUDA availability first
    {
        let test_points: Vec<ZkG1Affine> = vec![g1_gen];
        let test_scalars: Vec<ZkScalar> = vec![ZkScalar::from_u64(1)];
        let test_stream = unsafe { cuda_create_stream(0) };
        if ZkG1Projective::msm(&test_points, &test_scalars, test_stream, 0, false).is_err() {
            unsafe { cuda_destroy_stream(test_stream, 0) };
            eprintln!("CUDA not available - Skipping test");
            return;
        }
        unsafe { cuda_destroy_stream(test_stream, 0) };
    }

    for n in 1..=MAX_N {
        let points: Vec<ZkG1Affine> = (0..n).map(|_| g1_gen).collect();
        let scalars: Vec<ZkScalar> = (1..=n).map(ZkScalar::from_u64).collect();

        let stream = unsafe { cuda_create_stream(0) };
        let (gpu_result_proj, _size_tracker) =
            ZkG1Projective::msm(&points, &scalars, stream, 0, false)
                .unwrap_or_else(|_| panic!("CUDA MSM failed at N={}", n));
        unsafe { cuda_destroy_stream(stream, 0) };

        let gpu_result_mont = gpu_result_proj.to_affine();
        let gpu_result = g1_affine_from_montgomery(&gpu_result_mont);

        let expected_sum = triangular_number(n);
        let cpu_scalar = Zp::from_u64(expected_sum);
        let cpu_result = G1::GENERATOR.mul_scalar(cpu_scalar).normalize();

        let gpu_result_tfhe = g1_affine_from_zk_cuda(&gpu_result);

        assert_eq!(
            g1_affine_to_zk_cuda(&gpu_result_tfhe).is_infinity(),
            g1_affine_to_zk_cuda(&cpu_result).is_infinity(),
            "G1MSMLargeN: N={} infinity mismatch",
            n
        );
        if !gpu_result.is_infinity() {
            assert_eq!(
                g1_affine_to_zk_cuda(&gpu_result_tfhe).x(),
                g1_affine_to_zk_cuda(&cpu_result).x(),
                "G1MSMLargeN: N={} x mismatch",
                n
            );
            assert_eq!(
                g1_affine_to_zk_cuda(&gpu_result_tfhe).y(),
                g1_affine_to_zk_cuda(&cpu_result).y(),
                "G1MSMLargeN: N={} y mismatch",
                n
            );
        }
    }
}

#[test]
fn test_g2_msm_large_n() {
    const MAX_N: u64 = 100;

    let tfhe_g2_gen = G2::GENERATOR.normalize();
    let g2_gen = g2_affine_to_zk_cuda(&tfhe_g2_gen);

    // Test CUDA availability first
    {
        let test_points: Vec<ZkG2Affine> = vec![g2_gen];
        let test_scalars: Vec<ZkScalar> = vec![ZkScalar::from_u64(1)];
        let test_stream = unsafe { cuda_create_stream(0) };
        if ZkG2Projective::msm(&test_points, &test_scalars, test_stream, 0, false).is_err() {
            unsafe { cuda_destroy_stream(test_stream, 0) };
            eprintln!("CUDA not available - Skipping test");
            return;
        }
        unsafe { cuda_destroy_stream(test_stream, 0) };
    }

    for n in 1..=MAX_N {
        let points: Vec<ZkG2Affine> = (0..n).map(|_| g2_gen).collect();
        let scalars: Vec<ZkScalar> = (1..=n).map(ZkScalar::from_u64).collect();

        let stream = unsafe { cuda_create_stream(0) };
        let (gpu_result_proj, _size_tracker) =
            ZkG2Projective::msm(&points, &scalars, stream, 0, false)
                .unwrap_or_else(|_| panic!("CUDA MSM failed at N={}", n));
        unsafe { cuda_destroy_stream(stream, 0) };

        let gpu_result_mont = gpu_result_proj.to_affine();
        let gpu_result = g2_affine_from_montgomery(&gpu_result_mont);

        let expected_sum = triangular_number(n);
        let cpu_scalar = Zp::from_u64(expected_sum);
        let cpu_result = G2::GENERATOR.mul_scalar(cpu_scalar).normalize();

        let gpu_result_tfhe = g2_affine_from_zk_cuda(&gpu_result);

        assert_eq!(
            g2_affine_to_zk_cuda(&gpu_result_tfhe).is_infinity(),
            g2_affine_to_zk_cuda(&cpu_result).is_infinity(),
            "G2MSMLargeN: N={} infinity mismatch",
            n
        );
        if !gpu_result.is_infinity() {
            assert_eq!(
                g2_affine_to_zk_cuda(&gpu_result_tfhe).x(),
                g2_affine_to_zk_cuda(&cpu_result).x(),
                "G2MSMLargeN: N={} x mismatch",
                n
            );
            assert_eq!(
                g2_affine_to_zk_cuda(&gpu_result_tfhe).y(),
                g2_affine_to_zk_cuda(&cpu_result).y(),
                "G2MSMLargeN: N={} y mismatch",
                n
            );
        }
    }
}

// =============================================================================
// Edge Case Tests (Negative Coverage)
// =============================================================================

/// Test MSM with all-zero scalars - result should be infinity
#[test]
fn test_g1_msm_zero_scalars_returns_infinity() {
    let tfhe_g1_gen = G1::GENERATOR.normalize();
    let g1_gen = g1_affine_to_zk_cuda(&tfhe_g1_gen);

    // Multiple points with all-zero scalars
    let points: Vec<ZkG1Affine> = vec![g1_gen; 5];
    let scalars: Vec<ZkScalar> = vec![ZkScalar::from_u64(0); 5];

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = match ZkG1Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    // Result should be at infinity (Z = 0)
    let z_limbs = result_proj.from_montgomery_normalized().Z();
    let is_infinity = z_limbs.iter().all(|&limb| limb == 0);
    assert!(
        is_infinity,
        "G1 MSM with all-zero scalars should return infinity"
    );
}

/// Test MSM with canceling scalars - result should be infinity
/// sum(s_i * P) where s_0 = 1, s_1 = -1 (mod r) and P_0 = P_1
#[test]
fn test_g1_msm_canceling_scalars_returns_infinity() {
    let tfhe_g1_gen = G1::GENERATOR.normalize();
    let g1_gen = g1_affine_to_zk_cuda(&tfhe_g1_gen);

    // Same point twice with scalars 1 and -1 (which is r-1 mod r)
    let points: Vec<ZkG1Affine> = vec![g1_gen, g1_gen];

    // Scalar field modulus r for BLS12-446
    // r = 645383785691237230677916041525710377746967055506026847120930304831624105190538527824412673
    // r - 1 in limbs (little-endian)
    let r_minus_1: [u64; 5] = [
        0x0428001400040000, // r_0 - 1
        0x7bb9b0e8d8ca3461,
        0xd04c98ccc4c050bc,
        0x7995b34995830fa4,
        0x00000511b70539f2,
    ];

    let scalars: Vec<ZkScalar> = vec![ZkScalar::from_u64(1), ZkScalar::from(r_minus_1)];

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = match ZkG1Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    // Result should be at infinity (1*G + (-1)*G = O)
    let z_limbs = result_proj.from_montgomery_normalized().Z();
    let is_infinity = z_limbs.iter().all(|&limb| limb == 0);
    assert!(
        is_infinity,
        "G1 MSM with canceling scalars (1*G + (-1)*G) should return infinity"
    );
}

/// Test G2 MSM with all-zero scalars - result should be infinity
#[test]
fn test_g2_msm_zero_scalars_returns_infinity() {
    let tfhe_g2_gen = G2::GENERATOR.normalize();
    let g2_gen = g2_affine_to_zk_cuda(&tfhe_g2_gen);

    let points: Vec<ZkG2Affine> = vec![g2_gen; 5];
    let scalars: Vec<ZkScalar> = vec![ZkScalar::from_u64(0); 5];

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = match ZkG2Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    // Result should be at infinity (Z = 0 in Fq2)
    let (z_c0, z_c1) = result_proj.from_montgomery_normalized().Z();
    let is_infinity = z_c0.iter().all(|&limb| limb == 0) && z_c1.iter().all(|&limb| limb == 0);
    assert!(
        is_infinity,
        "G2 MSM with all-zero scalars should return infinity"
    );
}

/// Test MSM with infinity point as input
#[test]
fn test_g1_msm_infinity_point_input() {
    let tfhe_g1_gen = G1::GENERATOR.normalize();
    let g1_gen = g1_affine_to_zk_cuda(&tfhe_g1_gen);
    let g1_inf = ZkG1Affine::infinity();

    // Mix of regular point and infinity
    let points: Vec<ZkG1Affine> = vec![g1_inf, g1_gen, g1_inf];
    let scalars: Vec<ZkScalar> = vec![
        ZkScalar::from_u64(5),
        ZkScalar::from_u64(3),
        ZkScalar::from_u64(7),
    ];

    let gpu_index = 0;
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = match ZkG1Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    // Expected result: 5*O + 3*G + 7*O = 3*G
    let expected = G1::GENERATOR.mul_scalar(Zp::from_u64(3)).normalize();
    let expected_zk = g1_affine_to_zk_cuda(&expected);

    let result_mont = result_proj.to_affine();
    let result = g1_affine_from_montgomery(&result_mont);

    assert_eq!(
        result.x(),
        expected_zk.x(),
        "G1 MSM with infinity points: x mismatch"
    );
    assert_eq!(
        result.y(),
        expected_zk.y(),
        "G1 MSM with infinity points: y mismatch"
    );
}

/// Test scalar validation functions
#[test]
fn test_scalar_validation() {
    // Valid scalar (less than modulus)
    let valid_scalar = ZkScalar::from_u64(12345);
    assert!(valid_scalar.is_valid(), "Small scalar should be valid");

    // Scalar equal to modulus minus 1 (r - 1)
    let r_minus_1: [u64; 5] = [
        0x0428001400040000,
        0x7bb9b0e8d8ca3461,
        0xd04c98ccc4c050bc,
        0x7995b34995830fa4,
        0x00000511b70539f2,
    ];
    let max_valid = ZkScalar::from(r_minus_1);
    assert!(max_valid.is_valid(), "r-1 should be valid");

    // Scalar equal to modulus (invalid)
    let r: [u64; 5] = [
        0x0428001400040001,
        0x7bb9b0e8d8ca3461,
        0xd04c98ccc4c050bc,
        0x7995b34995830fa4,
        0x00000511b70539f2,
    ];
    let equal_to_r = ZkScalar::from(r);
    assert!(!equal_to_r.is_valid(), "r should be invalid");

    // Test reduction
    let reduced = equal_to_r.reduce_if_needed();
    assert!(
        reduced.is_valid(),
        "Reduced scalar should be valid (equals zero)"
    );
}
