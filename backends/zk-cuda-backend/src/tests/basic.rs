//! Basic tests that don't require external dependencies
//!
//! These tests verify the fundamental type operations and conversions
//! without needing tfhe-zk-pok.

use crate::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

#[test]
fn test_g1_affine_creation() {
    // Create a G1 affine point at infinity
    let g1_inf = G1Affine::infinity();
    assert!(g1_inf.is_infinity());

    // Create a G1 affine point from coordinates
    let x = [0x1234567890abcdef, 0, 0, 0, 0, 0, 0];
    let y = [0xfedcba0987654321, 0, 0, 0, 0, 0, 0];
    let g1_point = G1Affine::new(x, y, false);
    assert!(!g1_point.is_infinity());
}

#[test]
fn test_g1_affine_to_projective() {
    let x = [1, 0, 0, 0, 0, 0, 0];
    let y = [2, 0, 0, 0, 0, 0, 0];
    let g1_affine = G1Affine::new(x, y, false);

    let g1_proj = g1_affine.to_projective();
    let g1_affine_again = g1_proj.to_affine();

    // After round-trip conversion, coordinates should match
    assert_eq!(g1_affine.x(), g1_affine_again.x());
    assert_eq!(g1_affine.y(), g1_affine_again.y());
}

#[test]
fn test_g2_affine_creation() {
    // Create a G2 affine point at infinity
    let g2_inf = G2Affine::infinity();
    assert!(g2_inf.is_infinity());

    // Create a G2 affine point from coordinates
    let x = ([0x1234, 0, 0, 0, 0, 0, 0], [0x5678, 0, 0, 0, 0, 0, 0]);
    let y = ([0x9abc, 0, 0, 0, 0, 0, 0], [0xdef0, 0, 0, 0, 0, 0, 0]);
    let g2_point = G2Affine::new(x, y, false);
    assert!(!g2_point.is_infinity());
}

#[test]
fn test_g2_affine_to_projective() {
    let x = ([1, 0, 0, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0, 0]);
    let y = ([3, 0, 0, 0, 0, 0, 0], [4, 0, 0, 0, 0, 0, 0]);
    let g2_affine = G2Affine::new(x, y, false);

    let g2_proj = g2_affine.to_projective();
    let g2_affine_again = g2_proj.to_affine();

    // After round-trip conversion, coordinates should match
    assert_eq!(g2_affine.x(), g2_affine_again.x());
    assert_eq!(g2_affine.y(), g2_affine_again.y());
}

#[test]
fn test_scalar_creation() {
    let scalar = Scalar::from_u64(42);
    let limbs = scalar.limbs();
    assert_eq!(limbs[0], 42);
    assert_eq!(limbs[1], 0);
    assert_eq!(limbs[2], 0);
    assert_eq!(limbs[3], 0);
    assert_eq!(limbs[4], 0);
}

#[test]
fn test_scalar_multi_limb() {
    // Create a scalar with multiple limbs: 2^64 + 1
    let scalar = Scalar::new([1u64, 1u64, 0u64, 0u64, 0u64]);
    let limbs = scalar.limbs();
    assert_eq!(limbs[0], 1);
    assert_eq!(limbs[1], 1);
    assert_eq!(limbs[2], 0);
}

#[test]
fn test_g1_infinity_to_projective() {
    let g1_inf = G1Affine::infinity();
    let g1_proj = g1_inf.to_projective();
    let g1_inf_again = g1_proj.to_affine();
    assert!(g1_inf_again.is_infinity());
}

#[test]
fn test_g2_infinity_to_projective() {
    let g2_inf = G2Affine::infinity();
    let g2_proj = g2_inf.to_projective();
    let g2_inf_again = g2_proj.to_affine();
    assert!(g2_inf_again.is_infinity());
}

#[test]
fn test_g1_msm_returns_err_on_length_mismatch() {
    let points = vec![G1Affine::infinity()];
    let scalars: Vec<Scalar> = vec![];
    let result = G1Projective::msm(&points, &scalars, std::ptr::null_mut(), 0u32, false);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("points and scalars must have the same length"));
}

#[test]
fn test_g2_msm_returns_err_on_length_mismatch() {
    let points = vec![G2Affine::infinity()];
    let scalars: Vec<Scalar> = vec![];
    let result = G2Projective::msm(&points, &scalars, std::ptr::null_mut(), 0u32, false);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("points and scalars must have the same length"));
}

#[test]
fn test_g1_msm_returns_err_on_null_stream() {
    let points = vec![G1Affine::infinity()];
    let scalars = vec![Scalar::from_u64(1)];
    let result = G1Projective::msm(&points, &scalars, std::ptr::null_mut(), 0u32, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("stream pointer is null"));
}

#[test]
fn test_g2_msm_returns_err_on_null_stream() {
    let points = vec![G2Affine::infinity()];
    let scalars = vec![Scalar::from_u64(1)];
    let result = G2Projective::msm(&points, &scalars, std::ptr::null_mut(), 0u32, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("stream pointer is null"));
}
