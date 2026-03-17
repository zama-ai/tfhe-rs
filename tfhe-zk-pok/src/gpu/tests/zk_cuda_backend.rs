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

fn triangular_number(n: u64) -> u64 {
    n * (n + 1) / 2
}

/// BLS12-446 scalar field modulus minus one (r - 1), little-endian limbs.
/// Used by canceling-scalar tests: 1*G + (r-1)*G = r*G = O.
/// Derived from arkworks: (-Zp::ONE) is the additive inverse of 1 in Fr, i.e. r - 1.
fn r_minus_1() -> [u64; 5] {
    use ark_ff::PrimeField;
    (-Zp::ONE).inner.into_bigint().0
}

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
// Trait-based abstraction over G1/G2 MSM test variants.
//
// Each curve group has different affine/projective types, coordinate field types
// (Fp vs Fp2), and conversion functions. This trait captures those differences so
// the four MSM test bodies can be written once as generic functions.
// =============================================================================

trait MsmTestGroup {
    const LABEL: &'static str;
    type Group: CurveGroupOps<Zp>;
    type ZkAffine: Copy + PartialEq + std::fmt::Debug;
    type ZkProjective;
    /// Coordinate field type: Fp for G1, Fp2 for G2. Used in per-coordinate assertions
    /// to give precise x/y diagnostics when GPU results diverge.
    type Coord: PartialEq + std::fmt::Debug;

    fn to_zk(affine: &<Self::Group as CurveGroupOps<Zp>>::Affine) -> Self::ZkAffine;
    fn from_zk(affine: &Self::ZkAffine) -> <Self::Group as CurveGroupOps<Zp>>::Affine;
    fn from_mont(proj: &Self::ZkProjective) -> Self::ZkAffine;
    fn proj_z_is_zero(proj: &Self::ZkProjective) -> bool;
    fn infinity() -> Self::ZkAffine;
    fn x(affine: &Self::ZkAffine) -> Self::Coord;
    fn y(affine: &Self::ZkAffine) -> Self::Coord;
    fn is_infinity(affine: &Self::ZkAffine) -> bool;
    fn msm(
        points: &[Self::ZkAffine],
        scalars: &[ZkScalar],
        stream: *mut std::ffi::c_void,
        gpu_index: u32,
    ) -> Result<Self::ZkProjective, String>;
}

struct G1MSM;

impl MsmTestGroup for G1MSM {
    const LABEL: &'static str = "G1";
    type Group = G1;
    type ZkAffine = ZkG1Affine;
    type ZkProjective = ZkG1Projective;
    type Coord = zk_cuda_backend::Fp;

    fn to_zk(affine: &<G1 as CurveGroupOps<Zp>>::Affine) -> ZkG1Affine {
        g1_affine_to_zk_cuda(affine)
    }
    fn from_zk(affine: &ZkG1Affine) -> <G1 as CurveGroupOps<Zp>>::Affine {
        g1_affine_from_zk_cuda(affine)
    }
    fn from_mont(proj: &ZkG1Projective) -> ZkG1Affine {
        g1_affine_from_montgomery(&proj.to_affine())
    }
    fn proj_z_is_zero(proj: &ZkG1Projective) -> bool {
        g1_proj_z_is_zero(proj)
    }
    fn infinity() -> ZkG1Affine {
        ZkG1Affine::infinity()
    }
    fn x(affine: &ZkG1Affine) -> zk_cuda_backend::Fp {
        affine.x()
    }
    fn y(affine: &ZkG1Affine) -> zk_cuda_backend::Fp {
        affine.y()
    }
    fn is_infinity(affine: &ZkG1Affine) -> bool {
        affine.is_infinity()
    }
    fn msm(
        points: &[ZkG1Affine],
        scalars: &[ZkScalar],
        stream: *mut std::ffi::c_void,
        gpu_index: u32,
    ) -> Result<ZkG1Projective, String> {
        ZkG1Projective::msm(points, scalars, stream, gpu_index, false)
    }
}

struct G2MSM;

impl MsmTestGroup for G2MSM {
    const LABEL: &'static str = "G2";
    type Group = G2;
    type ZkAffine = ZkG2Affine;
    type ZkProjective = ZkG2Projective;
    type Coord = zk_cuda_backend::bindings::Fp2;

    fn to_zk(affine: &<G2 as CurveGroupOps<Zp>>::Affine) -> ZkG2Affine {
        g2_affine_to_zk_cuda(affine)
    }
    fn from_zk(affine: &ZkG2Affine) -> <G2 as CurveGroupOps<Zp>>::Affine {
        g2_affine_from_zk_cuda(affine)
    }
    fn from_mont(proj: &ZkG2Projective) -> ZkG2Affine {
        g2_affine_from_montgomery(&proj.to_affine())
    }
    fn proj_z_is_zero(proj: &ZkG2Projective) -> bool {
        g2_proj_z_is_zero(proj)
    }
    fn infinity() -> ZkG2Affine {
        ZkG2Affine::infinity()
    }
    fn x(affine: &ZkG2Affine) -> zk_cuda_backend::bindings::Fp2 {
        affine.x()
    }
    fn y(affine: &ZkG2Affine) -> zk_cuda_backend::bindings::Fp2 {
        affine.y()
    }
    fn is_infinity(affine: &ZkG2Affine) -> bool {
        affine.is_infinity()
    }
    fn msm(
        points: &[ZkG2Affine],
        scalars: &[ZkScalar],
        stream: *mut std::ffi::c_void,
        gpu_index: u32,
    ) -> Result<ZkG2Projective, String> {
        ZkG2Projective::msm(points, scalars, stream, gpu_index, false)
    }
}

// =============================================================================
// Generic MSM test functions, parameterized by MsmTestGroup
// =============================================================================

fn msm_large_n<T: MsmTestGroup>() {
    const MAX_N: u64 = 100;

    let gen = T::Group::GENERATOR.normalize();
    let gen_zk = T::to_zk(&gen);

    // Probe CUDA availability with a trivial MSM before the sweep
    {
        let probe_points = vec![gen_zk];
        let probe_scalars = vec![ZkScalar::from_u64(1)];
        // SAFETY: gpu_index 0 is valid (checked by test setup)
        let probe_stream = unsafe { cuda_create_stream(0) };
        if T::msm(&probe_points, &probe_scalars, probe_stream, 0).is_err() {
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
        let points: Vec<T::ZkAffine> = (0..n).map(|_| gen_zk).collect();
        let scalars: Vec<ZkScalar> = (1..=n).map(ZkScalar::from_u64).collect();

        // SAFETY: gpu_index 0 is valid (checked by test setup)
        let stream = unsafe { cuda_create_stream(0) };
        let gpu_result_proj = T::msm(&points, &scalars, stream, 0)
            .unwrap_or_else(|_| panic!("CUDA MSM failed at N={}", n));
        // SAFETY: stream was created above and is not used after this point
        unsafe { cuda_destroy_stream(stream, 0) };

        let gpu_result = T::from_mont(&gpu_result_proj);

        let expected_scalar = Zp::from_u64(triangular_number(n));
        let cpu_result = T::Group::GENERATOR.mul_scalar(expected_scalar).normalize();

        let gpu_tfhe = T::from_zk(&gpu_result);

        assert_eq!(
            T::is_infinity(&T::to_zk(&gpu_tfhe)),
            T::is_infinity(&T::to_zk(&cpu_result)),
            "{} MSM large_n: N={} infinity mismatch",
            T::LABEL,
            n
        );
        if !T::is_infinity(&gpu_result) {
            assert_eq!(
                T::x(&T::to_zk(&gpu_tfhe)),
                T::x(&T::to_zk(&cpu_result)),
                "{} MSM large_n: N={} x mismatch",
                T::LABEL,
                n
            );
            assert_eq!(
                T::y(&T::to_zk(&gpu_tfhe)),
                T::y(&T::to_zk(&cpu_result)),
                "{} MSM large_n: N={} y mismatch",
                T::LABEL,
                n
            );
        }
    }
}

fn msm_zero_scalars<T: MsmTestGroup>() {
    let gen = T::Group::GENERATOR.normalize();
    let gen_zk = T::to_zk(&gen);

    // All-zero scalars: 0*G + 0*G + ... = O
    let points = vec![gen_zk; 5];
    let scalars = vec![ZkScalar::from_u64(0); 5];

    let gpu_index = 0;
    // SAFETY: gpu_index 0 is valid (checked by test setup)
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = match T::msm(&points, &scalars, stream, gpu_index) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            // SAFETY: stream was created above and is not used after this point
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    // SAFETY: stream was created above and is not used after this point
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let is_infinity = T::proj_z_is_zero(&result_proj);
    assert!(
        is_infinity,
        "{} MSM with all-zero scalars should return infinity",
        T::LABEL
    );
}

fn msm_canceling<T: MsmTestGroup>() {
    let gen = T::Group::GENERATOR.normalize();
    let gen_zk = T::to_zk(&gen);

    // 1*G + (r-1)*G = r*G = O
    let points = vec![gen_zk, gen_zk];
    let scalars = vec![ZkScalar::from_u64(1), ZkScalar::from(r_minus_1())];

    let gpu_index = 0;
    // SAFETY: gpu_index 0 is valid (checked by test setup)
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = match T::msm(&points, &scalars, stream, gpu_index) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            // SAFETY: stream was created above and is not used after this point
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    // SAFETY: stream was created above and is not used after this point
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let is_infinity = T::proj_z_is_zero(&result_proj);
    assert!(
        is_infinity,
        "{} MSM with canceling scalars (1*G + (r-1)*G) should return infinity",
        T::LABEL
    );
}

fn msm_infinity_input<T: MsmTestGroup>() {
    let gen = T::Group::GENERATOR.normalize();
    let gen_zk = T::to_zk(&gen);
    let inf = T::infinity();

    // 5*O + 3*G + 7*O = 3*G (infinity inputs contribute nothing)
    let points = vec![inf, gen_zk, inf];
    let scalars = vec![
        ZkScalar::from_u64(5),
        ZkScalar::from_u64(3),
        ZkScalar::from_u64(7),
    ];

    let gpu_index = 0;
    // SAFETY: gpu_index 0 is valid (checked by test setup)
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = match T::msm(&points, &scalars, stream, gpu_index) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("CUDA MSM failed: {} - Skipping test", e);
            // SAFETY: stream was created above and is not used after this point
            unsafe { cuda_destroy_stream(stream, gpu_index) };
            return;
        }
    };
    // SAFETY: stream was created above and is not used after this point
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let expected = T::Group::GENERATOR.mul_scalar(Zp::from_u64(3)).normalize();
    let expected_zk = T::to_zk(&expected);

    let result = T::from_mont(&result_proj);

    assert_eq!(
        T::x(&result),
        T::x(&expected_zk),
        "{} MSM with infinity points: x mismatch",
        T::LABEL
    );
    assert_eq!(
        T::y(&result),
        T::y(&expected_zk),
        "{} MSM with infinity points: y mismatch",
        T::LABEL
    );
}

// =============================================================================
// Test wrappers: instantiate generic tests for G1 and G2
// =============================================================================

#[test]
fn test_g1_msm_large_n() {
    msm_large_n::<G1MSM>();
}

#[test]
fn test_g1_msm_zero_scalars_returns_infinity() {
    msm_zero_scalars::<G1MSM>();
}

#[test]
fn test_g1_msm_canceling_scalars_returns_infinity() {
    msm_canceling::<G1MSM>();
}

#[test]
fn test_g1_msm_infinity_point_input() {
    msm_infinity_input::<G1MSM>();
}

#[test]
fn test_g2_msm_large_n() {
    msm_large_n::<G2MSM>();
}

#[test]
fn test_g2_msm_zero_scalars_returns_infinity() {
    msm_zero_scalars::<G2MSM>();
}

#[test]
fn test_g2_msm_canceling_scalars_returns_infinity() {
    msm_canceling::<G2MSM>();
}

#[test]
fn test_g2_msm_infinity_point_input() {
    msm_infinity_input::<G2MSM>();
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
        Ok(result) => result,
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

#[test]
fn test_scalar_validation() {
    let valid_scalar = ZkScalar::from_u64(12345);
    assert!(valid_scalar.is_valid(), "Small scalar should be valid");

    let max_valid = ZkScalar::from(r_minus_1());
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

    let reduced = equal_to_r.reduce_once();
    assert!(
        reduced.is_valid(),
        "Reduced scalar should be valid (equals zero)"
    );
}
