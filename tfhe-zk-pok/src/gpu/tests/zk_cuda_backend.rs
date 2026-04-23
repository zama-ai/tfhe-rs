//! Tests comparing zk-cuda-backend MSM results against tfhe-zk-pok CPU implementation

use crate::curve_api::bls12_446::{Zp, G1, G2};
use crate::curve_api::CurveGroupOps;
use crate::gpu::{g1_affine_from_cuda, g1_affine_to_cuda, g2_affine_from_cuda, g2_affine_to_cuda};
use tfhe_cuda_common::cuda_bind::{cuda_create_stream, cuda_destroy_stream};
use zk_cuda_backend::conversions::{g1_affine_from_montgomery, g2_affine_from_montgomery};
use zk_cuda_backend::{
    G1Affine as CudaG1Affine, G1Projective as CudaG1Projective, G2Affine as CudaG2Affine,
    G2Projective as CudaG2Projective, Scalar as CudaScalar,
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
fn g1_proj_z_is_zero(p: &CudaG1Projective) -> bool {
    let z = p.from_montgomery_normalized().Z();
    z.limb.iter().all(|&limb| limb == 0)
}

/// Check that a G2 projective point has Z == 0 (point at infinity).
/// G2 lives over Fp2, so both c0 and c1 components must be zero.
fn g2_proj_z_is_zero(p: &CudaG2Projective) -> bool {
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
    type CudaAffine: Copy + PartialEq + std::fmt::Debug;
    type CudaProjective;
    /// Coordinate field type: Fp for G1, Fp2 for G2. Used in per-coordinate assertions
    /// to give precise x/y diagnostics when GPU results diverge.
    type Coord: PartialEq + std::fmt::Debug;

    fn to_cuda(affine: &<Self::Group as CurveGroupOps<Zp>>::Affine) -> Self::CudaAffine;
    fn from_cuda(affine: &Self::CudaAffine) -> <Self::Group as CurveGroupOps<Zp>>::Affine;
    fn from_mont(proj: &Self::CudaProjective) -> Self::CudaAffine;
    fn proj_z_is_zero(proj: &Self::CudaProjective) -> bool;
    fn infinity() -> Self::CudaAffine;
    fn x(affine: &Self::CudaAffine) -> Self::Coord;
    fn y(affine: &Self::CudaAffine) -> Self::Coord;
    fn is_infinity(affine: &Self::CudaAffine) -> bool;
    fn msm(
        points: &[Self::CudaAffine],
        scalars: &[CudaScalar],
        stream: *mut std::ffi::c_void,
        gpu_index: u32,
    ) -> Result<Self::CudaProjective, String>;
}

struct G1MSM;

impl MsmTestGroup for G1MSM {
    const LABEL: &'static str = "G1";
    type Group = G1;
    type CudaAffine = CudaG1Affine;
    type CudaProjective = CudaG1Projective;
    type Coord = zk_cuda_backend::Fp;

    fn to_cuda(affine: &<G1 as CurveGroupOps<Zp>>::Affine) -> CudaG1Affine {
        g1_affine_to_cuda(affine)
    }
    fn from_cuda(affine: &CudaG1Affine) -> <G1 as CurveGroupOps<Zp>>::Affine {
        g1_affine_from_cuda(affine)
    }
    fn from_mont(proj: &CudaG1Projective) -> CudaG1Affine {
        g1_affine_from_montgomery(&proj.to_affine())
    }
    fn proj_z_is_zero(proj: &CudaG1Projective) -> bool {
        g1_proj_z_is_zero(proj)
    }
    fn infinity() -> CudaG1Affine {
        CudaG1Affine::infinity()
    }
    fn x(affine: &CudaG1Affine) -> zk_cuda_backend::Fp {
        affine.x()
    }
    fn y(affine: &CudaG1Affine) -> zk_cuda_backend::Fp {
        affine.y()
    }
    fn is_infinity(affine: &CudaG1Affine) -> bool {
        affine.is_infinity()
    }
    fn msm(
        points: &[CudaG1Affine],
        scalars: &[CudaScalar],
        stream: *mut std::ffi::c_void,
        gpu_index: u32,
    ) -> Result<CudaG1Projective, String> {
        CudaG1Projective::msm(points, scalars, stream, gpu_index, false)
    }
}

struct G2MSM;

impl MsmTestGroup for G2MSM {
    const LABEL: &'static str = "G2";
    type Group = G2;
    type CudaAffine = CudaG2Affine;
    type CudaProjective = CudaG2Projective;
    type Coord = zk_cuda_backend::bindings::Fp2;

    fn to_cuda(affine: &<G2 as CurveGroupOps<Zp>>::Affine) -> CudaG2Affine {
        g2_affine_to_cuda(affine)
    }
    fn from_cuda(affine: &CudaG2Affine) -> <G2 as CurveGroupOps<Zp>>::Affine {
        g2_affine_from_cuda(affine)
    }
    fn from_mont(proj: &CudaG2Projective) -> CudaG2Affine {
        g2_affine_from_montgomery(&proj.to_affine())
    }
    fn proj_z_is_zero(proj: &CudaG2Projective) -> bool {
        g2_proj_z_is_zero(proj)
    }
    fn infinity() -> CudaG2Affine {
        CudaG2Affine::infinity()
    }
    fn x(affine: &CudaG2Affine) -> zk_cuda_backend::bindings::Fp2 {
        affine.x()
    }
    fn y(affine: &CudaG2Affine) -> zk_cuda_backend::bindings::Fp2 {
        affine.y()
    }
    fn is_infinity(affine: &CudaG2Affine) -> bool {
        affine.is_infinity()
    }
    fn msm(
        points: &[CudaG2Affine],
        scalars: &[CudaScalar],
        stream: *mut std::ffi::c_void,
        gpu_index: u32,
    ) -> Result<CudaG2Projective, String> {
        CudaG2Projective::msm(points, scalars, stream, gpu_index, false)
    }
}

// =============================================================================
// Generic MSM test functions, parameterized by MsmTestGroup
// =============================================================================

fn msm_large_n<T: MsmTestGroup>() {
    const MAX_N: u64 = 100;

    let gen = T::Group::GENERATOR.normalize();
    let gen_cuda = T::to_cuda(&gen);

    // Probe CUDA availability with a trivial MSM before the sweep
    {
        let probe_points = vec![gen_cuda];
        let probe_scalars = vec![CudaScalar::from_u64(1)];
        // SAFETY: gpu_index 0 is assumed valid on any CUDA-capable machine
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
        let points: Vec<T::CudaAffine> = (0..n).map(|_| gen_cuda).collect();
        let scalars: Vec<CudaScalar> = (1..=n).map(CudaScalar::from_u64).collect();

        // SAFETY: gpu_index 0 is assumed valid on any CUDA-capable machine
        let stream = unsafe { cuda_create_stream(0) };
        let gpu_result_proj = T::msm(&points, &scalars, stream, 0)
            .unwrap_or_else(|_| panic!("CUDA MSM failed at N={}", n));
        // SAFETY: stream was created above and is not used after this point
        unsafe { cuda_destroy_stream(stream, 0) };

        let gpu_result = T::from_mont(&gpu_result_proj);

        let expected_scalar = Zp::from_u64(triangular_number(n));
        let cpu_result = T::Group::GENERATOR.mul_scalar(expected_scalar).normalize();

        let gpu_result_affine = T::from_cuda(&gpu_result);

        assert!(
            !T::is_infinity(&gpu_result),
            "{} MSM large_n: N={} unexpected infinity",
            T::LABEL,
            n
        );
        assert_eq!(
            T::x(&T::to_cuda(&gpu_result_affine)),
            T::x(&T::to_cuda(&cpu_result)),
            "{} MSM large_n: N={} x mismatch",
            T::LABEL,
            n
        );
        assert_eq!(
            T::y(&T::to_cuda(&gpu_result_affine)),
            T::y(&T::to_cuda(&cpu_result)),
            "{} MSM large_n: N={} y mismatch",
            T::LABEL,
            n
        );
    }
}

fn msm_zero_scalars<T: MsmTestGroup>() {
    let gen = T::Group::GENERATOR.normalize();
    let gen_cuda = T::to_cuda(&gen);

    // All-zero scalars: 0*G + 0*G + ... = O
    let points = vec![gen_cuda; 5];
    let scalars = vec![CudaScalar::from_u64(0); 5];

    let gpu_index = 0;
    // SAFETY: gpu_index 0 is assumed valid on any CUDA-capable machine
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = T::msm(&points, &scalars, stream, gpu_index)
        .unwrap_or_else(|e| panic!("CUDA MSM failed: {e}"));
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
    let gen_cuda = T::to_cuda(&gen);

    // 1*G + (r-1)*G = r*G = O
    let points = vec![gen_cuda, gen_cuda];
    let scalars = vec![CudaScalar::from_u64(1), CudaScalar::from(r_minus_1())];

    let gpu_index = 0;
    // SAFETY: gpu_index 0 is assumed valid on any CUDA-capable machine
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = T::msm(&points, &scalars, stream, gpu_index)
        .unwrap_or_else(|e| panic!("CUDA MSM failed: {e}"));
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
    let gen_cuda = T::to_cuda(&gen);
    let inf = T::infinity();

    // 5*O + 3*G + 7*O = 3*G (infinity inputs contribute nothing)
    let points = vec![inf, gen_cuda, inf];
    let scalars = vec![
        CudaScalar::from_u64(5),
        CudaScalar::from_u64(3),
        CudaScalar::from_u64(7),
    ];

    let gpu_index = 0;
    // SAFETY: gpu_index 0 is assumed valid on any CUDA-capable machine
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let result_proj = T::msm(&points, &scalars, stream, gpu_index)
        .unwrap_or_else(|e| panic!("CUDA MSM failed: {e}"));
    // SAFETY: stream was created above and is not used after this point
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let expected = T::Group::GENERATOR.mul_scalar(Zp::from_u64(3)).normalize();
    let expected_cuda = T::to_cuda(&expected);

    let result = T::from_mont(&result_proj);

    assert_eq!(
        T::x(&result),
        T::x(&expected_cuda),
        "{} MSM with infinity points: x mismatch",
        T::LABEL
    );
    assert_eq!(
        T::y(&result),
        T::y(&expected_cuda),
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
// Non-generic tests: these test unique behavior not shared between G1/G2
// =============================================================================

#[test]
fn test_g1_conversion_roundtrip() {
    let cpu_g1_gen = G1::GENERATOR.normalize();
    let cuda_g1 = g1_affine_to_cuda(&cpu_g1_gen);
    let cpu_g1_again = g1_affine_from_cuda(&cuda_g1);
    let cuda_g1_again = g1_affine_to_cuda(&cpu_g1_again);

    assert_eq!(cuda_g1.x(), cuda_g1_again.x());
    assert_eq!(cuda_g1.y(), cuda_g1_again.y());
}

#[test]
fn test_g2_conversion_roundtrip() {
    let cpu_g2_gen = G2::GENERATOR.normalize();
    let cuda_g2 = g2_affine_to_cuda(&cpu_g2_gen);
    let cpu_g2_again = g2_affine_from_cuda(&cuda_g2);
    let cuda_g2_again = g2_affine_to_cuda(&cpu_g2_again);

    assert_eq!(cuda_g2.x(), cuda_g2_again.x());
    assert_eq!(cuda_g2.y(), cuda_g2_again.y());
}

#[test]
fn test_g1_msm_multi_limb_scalar() {
    let cpu_g1_gen = G1::GENERATOR.normalize();
    let g1_gen = g1_affine_to_cuda(&cpu_g1_gen);

    // Scalar = 2^64 (requires 2 limbs) to exercise multi-limb scalar handling
    let scalar = CudaScalar::new([0u64, 1u64, 0u64, 0u64, 0u64]);
    let points: Vec<CudaG1Affine> = vec![g1_gen];
    let scalars: Vec<CudaScalar> = vec![scalar];

    let gpu_index = 0;
    // SAFETY: gpu_index 0 is assumed valid on any CUDA-capable machine
    let stream = unsafe { cuda_create_stream(gpu_index) };
    let gpu_result_proj = CudaG1Projective::msm(&points, &scalars, stream, gpu_index, false)
        .unwrap_or_else(|e| panic!("CUDA MSM failed: {e}"));
    // SAFETY: stream was created above and is not used after this point
    unsafe { cuda_destroy_stream(stream, gpu_index) };

    let gpu_result_mont = gpu_result_proj.to_affine();
    let gpu_result = g1_affine_from_montgomery(&gpu_result_mont);

    let cpu_scalar = Zp::from_bigint([0u64, 1u64, 0u64, 0u64, 0u64]);
    let cpu_result = G1::GENERATOR.mul_scalar(cpu_scalar).normalize();

    let gpu_result_tfhe = g1_affine_from_cuda(&gpu_result);

    assert_eq!(
        g1_affine_to_cuda(&gpu_result_tfhe).x(),
        g1_affine_to_cuda(&cpu_result).x(),
        "G1 MSM 2^64 scalar x mismatch"
    );
    assert_eq!(
        g1_affine_to_cuda(&gpu_result_tfhe).y(),
        g1_affine_to_cuda(&cpu_result).y(),
        "G1 MSM 2^64 scalar y mismatch"
    );
}

#[test]
fn test_scalar_validation() {
    let valid_scalar = CudaScalar::from_u64(12345);
    assert!(valid_scalar.is_valid(), "Small scalar should be valid");

    let max_valid = CudaScalar::from(r_minus_1());
    assert!(max_valid.is_valid(), "r-1 should be valid");

    // Scalar equal to modulus (invalid)
    let r: [u64; 5] = [
        0x0428001400040001,
        0x7bb9b0e8d8ca3461,
        0xd04c98ccc4c050bc,
        0x7995b34995830fa4,
        0x00000511b70539f2,
    ];
    let equal_to_r = CudaScalar::from(r);
    assert!(!equal_to_r.is_valid(), "r should be invalid");

    let reduced = equal_to_r.reduce_once();
    assert!(
        reduced.is_valid(),
        "Reduced scalar should be valid (equals zero)"
    );
    assert_eq!(
        reduced,
        CudaScalar::from_u64(0),
        "Scalar equal to r should reduce to zero"
    );
}
