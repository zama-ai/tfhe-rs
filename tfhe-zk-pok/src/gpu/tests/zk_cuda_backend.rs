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

/// BLS12-446 scalar field modulus minus one (r - 1), little-endian limbs.
/// Used by canceling-scalar tests: 1*G + (r-1)*G = r*G = O.
const R_MINUS_1: [u64; 5] = [
    0x0428001400040000,
    0x7bb9b0e8d8ca3461,
    0xd04c98ccc4c050bc,
    0x7995b34995830fa4,
    0x00000511b70539f2,
];

/// Check that a G1 projective point has Z == 0 (point at infinity).
/// Converts from Montgomery form first so limbs are directly comparable.
fn g1_proj_z_is_zero(p: &ZkG1Projective) -> bool {
    let z = p.from_montgomery_normalized().Z();
    z.limb.iter().all(|&limb| limb == 0)
}

/// Check that a G2 projective point has Z == 0 (point at infinity).
/// G2 lives over Fp2, so both c0 and c1 components must be zero.
fn g2_proj_z_is_zero(p: &ZkG2Projective) -> bool {
    let z = p.from_montgomery_normalized().Z();
    z.c0.limb.iter().all(|&limb| limb == 0) && z.c1.limb.iter().all(|&limb| limb == 0)
}

// =============================================================================
// Macro: generates G1 and G2 MSM test variants from a single template.
//
// Parameters:
//   $Group        - tfhe-zk-pok curve group (G1 or G2)
//   $ZkAffine     - zk-cuda-backend affine type (ZkG1Affine or ZkG2Affine)
//   $ZkProjective - zk-cuda-backend projective type
//   $to_zk        - conversion: tfhe-zk-pok affine -> zk-cuda affine
//   $from_zk      - conversion: zk-cuda affine -> tfhe-zk-pok affine
//   $from_mont    - Montgomery-to-normal conversion for zk-cuda affine
//   $proj_z_is_zero - fn to check projective Z == 0 (group-specific)
//   $test_*       - test function names (avoids `paste` dependency)
// =============================================================================
macro_rules! msm_tests {
    (
        group: $Group:ty,
        zk_affine: $ZkAffine:ty,
        zk_proj: $ZkProjective:ty,
        to_zk: $to_zk:expr,
        from_zk: $from_zk:expr,
        from_mont: $from_mont:expr,
        proj_z_is_zero: $proj_z_is_zero:expr,
        label: $label:expr,
        test_large_n: $test_large_n:ident,
        test_zero_scalars: $test_zero_scalars:ident,
        test_canceling: $test_canceling:ident,
        test_infinity_input: $test_infinity_input:ident
    ) => {
        #[test]
        fn $test_large_n() {
            const MAX_N: u64 = 100;

            let gen = <$Group>::GENERATOR.normalize();
            let gen_zk = $to_zk(&gen);

            // Probe CUDA availability with a trivial MSM before the sweep
            {
                let probe_points: Vec<$ZkAffine> = vec![gen_zk];
                let probe_scalars: Vec<ZkScalar> = vec![ZkScalar::from_u64(1)];
                // SAFETY: gpu_index 0 is valid (checked by test setup)
                let probe_stream = unsafe { cuda_create_stream(0) };
                if <$ZkProjective>::msm(&probe_points, &probe_scalars, probe_stream, 0, false)
                    .is_err()
                {
                    // SAFETY: stream was created above and is not used after this point
                    unsafe { cuda_destroy_stream(probe_stream, 0) };
                    eprintln!("CUDA not available - Skipping test");
                    return;
                }
                // SAFETY: stream was created above and is not used after this point
                unsafe { cuda_destroy_stream(probe_stream, 0) };
            }

            // Sweep N from 1..=MAX_N: points = [G; N], scalars = [1..=N].
            // Expected result = G * triangular(N).
            for n in 1..=MAX_N {
                let points: Vec<$ZkAffine> = (0..n).map(|_| gen_zk).collect();
                let scalars: Vec<ZkScalar> = (1..=n).map(ZkScalar::from_u64).collect();

                // SAFETY: gpu_index 0 is valid (checked by test setup)
                let stream = unsafe { cuda_create_stream(0) };
                let (gpu_result_proj, _size_tracker) =
                    <$ZkProjective>::msm(&points, &scalars, stream, 0, false)
                        .unwrap_or_else(|_| panic!("CUDA MSM failed at N={}", n));
                // SAFETY: stream was created above and is not used after this point
                unsafe { cuda_destroy_stream(stream, 0) };

                let gpu_result = $from_mont(&gpu_result_proj.to_affine());

                let expected_scalar = Zp::from_u64(triangular_number(n));
                let cpu_result = <$Group>::GENERATOR.mul_scalar(expected_scalar).normalize();

                let gpu_tfhe = $from_zk(&gpu_result);

                assert_eq!(
                    $to_zk(&gpu_tfhe).is_infinity(),
                    $to_zk(&cpu_result).is_infinity(),
                    "{} MSM large_n: N={} infinity mismatch",
                    $label,
                    n
                );
                if !gpu_result.is_infinity() {
                    assert_eq!(
                        $to_zk(&gpu_tfhe).x(),
                        $to_zk(&cpu_result).x(),
                        "{} MSM large_n: N={} x mismatch",
                        $label,
                        n
                    );
                    assert_eq!(
                        $to_zk(&gpu_tfhe).y(),
                        $to_zk(&cpu_result).y(),
                        "{} MSM large_n: N={} y mismatch",
                        $label,
                        n
                    );
                }
            }
        }

        #[test]
        fn $test_zero_scalars() {
            let gen = <$Group>::GENERATOR.normalize();
            let gen_zk = $to_zk(&gen);

            // All-zero scalars: 0*G + 0*G + ... = O
            let points: Vec<$ZkAffine> = vec![gen_zk; 5];
            let scalars: Vec<ZkScalar> = vec![ZkScalar::from_u64(0); 5];

            let gpu_index = 0;
            // SAFETY: gpu_index 0 is valid (checked by test setup)
            let stream = unsafe { cuda_create_stream(gpu_index) };
            let result_proj =
                match <$ZkProjective>::msm(&points, &scalars, stream, gpu_index, false) {
                    Ok((result, _size_tracker)) => result,
                    Err(e) => {
                        eprintln!("CUDA MSM failed: {} - Skipping test", e);
                        // SAFETY: stream was created above and is not used after this point
                        unsafe { cuda_destroy_stream(stream, gpu_index) };
                        return;
                    }
                };
            // SAFETY: stream was created above and is not used after this point
            unsafe { cuda_destroy_stream(stream, gpu_index) };

            let is_infinity = ($proj_z_is_zero)(&result_proj);
            assert!(
                is_infinity,
                "{} MSM with all-zero scalars should return infinity",
                $label
            );
        }

        #[test]
        fn $test_canceling() {
            let gen = <$Group>::GENERATOR.normalize();
            let gen_zk = $to_zk(&gen);

            // 1*G + (r-1)*G = r*G = O
            let points: Vec<$ZkAffine> = vec![gen_zk, gen_zk];
            let scalars: Vec<ZkScalar> = vec![ZkScalar::from_u64(1), ZkScalar::from(R_MINUS_1)];

            let gpu_index = 0;
            // SAFETY: gpu_index 0 is valid (checked by test setup)
            let stream = unsafe { cuda_create_stream(gpu_index) };
            let result_proj =
                match <$ZkProjective>::msm(&points, &scalars, stream, gpu_index, false) {
                    Ok((result, _size_tracker)) => result,
                    Err(e) => {
                        eprintln!("CUDA MSM failed: {} - Skipping test", e);
                        // SAFETY: stream was created above and is not used after this point
                        unsafe { cuda_destroy_stream(stream, gpu_index) };
                        return;
                    }
                };
            // SAFETY: stream was created above and is not used after this point
            unsafe { cuda_destroy_stream(stream, gpu_index) };

            let is_infinity = ($proj_z_is_zero)(&result_proj);
            assert!(
                is_infinity,
                "{} MSM with canceling scalars (1*G + (r-1)*G) should return infinity",
                $label
            );
        }

        #[test]
        fn $test_infinity_input() {
            let gen = <$Group>::GENERATOR.normalize();
            let gen_zk = $to_zk(&gen);
            let inf = <$ZkAffine>::infinity();

            // 5*O + 3*G + 7*O = 3*G (infinity inputs contribute nothing)
            let points: Vec<$ZkAffine> = vec![inf, gen_zk, inf];
            let scalars: Vec<ZkScalar> = vec![
                ZkScalar::from_u64(5),
                ZkScalar::from_u64(3),
                ZkScalar::from_u64(7),
            ];

            let gpu_index = 0;
            // SAFETY: gpu_index 0 is valid (checked by test setup)
            let stream = unsafe { cuda_create_stream(gpu_index) };
            let result_proj =
                match <$ZkProjective>::msm(&points, &scalars, stream, gpu_index, false) {
                    Ok((result, _size_tracker)) => result,
                    Err(e) => {
                        eprintln!("CUDA MSM failed: {} - Skipping test", e);
                        // SAFETY: stream was created above and is not used after this point
                        unsafe { cuda_destroy_stream(stream, gpu_index) };
                        return;
                    }
                };
            // SAFETY: stream was created above and is not used after this point
            unsafe { cuda_destroy_stream(stream, gpu_index) };

            let expected = <$Group>::GENERATOR.mul_scalar(Zp::from_u64(3)).normalize();
            let expected_zk = $to_zk(&expected);

            let result = $from_mont(&result_proj.to_affine());

            assert_eq!(
                result.x(),
                expected_zk.x(),
                "{} MSM with infinity points: x mismatch",
                $label
            );
            assert_eq!(
                result.y(),
                expected_zk.y(),
                "{} MSM with infinity points: y mismatch",
                $label
            );
        }
    };
}

// Generate G1 MSM tests
msm_tests! {
    group: G1,
    zk_affine: ZkG1Affine,
    zk_proj: ZkG1Projective,
    to_zk: g1_affine_to_zk_cuda,
    from_zk: g1_affine_from_zk_cuda,
    from_mont: g1_affine_from_montgomery,
    proj_z_is_zero: g1_proj_z_is_zero,
    label: "G1",
    test_large_n: test_g1_msm_large_n,
    test_zero_scalars: test_g1_msm_zero_scalars_returns_infinity,
    test_canceling: test_g1_msm_canceling_scalars_returns_infinity,
    test_infinity_input: test_g1_msm_infinity_point_input
}

// Generate G2 MSM tests
msm_tests! {
    group: G2,
    zk_affine: ZkG2Affine,
    zk_proj: ZkG2Projective,
    to_zk: g2_affine_to_zk_cuda,
    from_zk: g2_affine_from_zk_cuda,
    from_mont: g2_affine_from_montgomery,
    proj_z_is_zero: g2_proj_z_is_zero,
    label: "G2",
    test_large_n: test_g2_msm_large_n,
    test_zero_scalars: test_g2_msm_zero_scalars_returns_infinity,
    test_canceling: test_g2_msm_canceling_scalars_returns_infinity,
    test_infinity_input: test_g2_msm_infinity_point_input
}

// =============================================================================
// Non-macro tests: these test unique behavior not shared between G1/G2
// =============================================================================

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
fn test_g1_msm_multi_limb_scalar() {
    let tfhe_g1_gen = G1::GENERATOR.normalize();
    let g1_gen = g1_affine_to_zk_cuda(&tfhe_g1_gen);

    // Scalar = 2^64 (requires 2 limbs) to exercise multi-limb scalar handling
    let scalar = ZkScalar::new([0u64, 1u64, 0u64, 0u64, 0u64]);
    let points: Vec<ZkG1Affine> = vec![g1_gen];
    let scalars: Vec<ZkScalar> = vec![scalar];

    let gpu_index = 0;
    // SAFETY: gpu_index 0 is valid (checked by test setup)
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let gpu_result_proj = match ZkG1Projective::msm(&points, &scalars, stream, gpu_index, false) {
        Ok((result, _size_tracker)) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            // SAFETY: stream was created above and is not used after this point
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    // SAFETY: stream was created above and is not used after this point
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let gpu_result_mont = gpu_result_proj.to_affine();
    let gpu_result = g1_affine_from_montgomery(&gpu_result_mont);

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

/// Test scalar validation functions
#[test]
fn test_scalar_validation() {
    // Valid scalar (less than modulus)
    let valid_scalar = ZkScalar::from_u64(12345);
    assert!(valid_scalar.is_valid(), "Small scalar should be valid");

    // Scalar equal to modulus minus 1 (r - 1)
    let max_valid = ZkScalar::from(R_MINUS_1);
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
    let reduced = equal_to_r.reduce_once();
    assert!(
        reduced.is_valid(),
        "Reduced scalar should be valid (equals zero)"
    );
}
