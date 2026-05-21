use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GlweSize,
    LweBskGroupingFactor, LweDimension, PolynomialSize,
};
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::{
    FourierLweBootstrapKeyOwned, LweBootstrapKeyConformanceParams,
};

// --- FourierLweBootstrapKey (non-multi-bit) ---

fn make_bsk_params() -> LweBootstrapKeyConformanceParams<u64> {
    LweBootstrapKeyConformanceParams {
        decomp_base_log: DecompositionBaseLog(8),
        decomp_level_count: DecompositionLevelCount(3),
        input_lwe_dimension: LweDimension(600),
        output_glwe_size: GlweSize(2),
        polynomial_size: PolynomialSize(1024),
        ciphertext_modulus: CiphertextModulus::new_native(),
    }
}

#[test]
fn test_conformant_fourier_bsk() {
    let params = make_bsk_params();
    let bsk = FourierLweBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        params.output_glwe_size,
        params.polynomial_size,
        params.decomp_base_log,
        params.decomp_level_count,
    );
    assert!(bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_bsk_wrong_input_lwe_dimension() {
    let params = make_bsk_params();
    let bsk = FourierLweBootstrapKeyOwned::new(
        LweDimension(params.input_lwe_dimension.0 + 1),
        params.output_glwe_size,
        params.polynomial_size,
        params.decomp_base_log,
        params.decomp_level_count,
    );
    assert!(!bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_bsk_wrong_glwe_size() {
    let params = make_bsk_params();
    let bsk = FourierLweBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        GlweSize(params.output_glwe_size.0 + 1),
        params.polynomial_size,
        params.decomp_base_log,
        params.decomp_level_count,
    );
    assert!(!bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_bsk_wrong_polynomial_size() {
    let params = make_bsk_params();
    let bsk = FourierLweBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        params.output_glwe_size,
        PolynomialSize(params.polynomial_size.0 * 2),
        params.decomp_base_log,
        params.decomp_level_count,
    );
    assert!(!bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_bsk_wrong_decomp_base_log() {
    let params = make_bsk_params();
    let bsk = FourierLweBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        params.output_glwe_size,
        params.polynomial_size,
        DecompositionBaseLog(params.decomp_base_log.0 + 1),
        params.decomp_level_count,
    );
    assert!(!bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_bsk_wrong_decomp_level_count() {
    let params = make_bsk_params();
    let bsk = FourierLweBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        params.output_glwe_size,
        params.polynomial_size,
        params.decomp_base_log,
        DecompositionLevelCount(params.decomp_level_count.0 + 1),
    );
    assert!(!bsk.is_conformant(&params));
}

// --- FourierLweMultiBitBootstrapKey ---

fn make_multi_bit_bsk_params() -> MultiBitBootstrapKeyConformanceParams<u64> {
    MultiBitBootstrapKeyConformanceParams {
        decomp_base_log: DecompositionBaseLog(8),
        decomp_level_count: DecompositionLevelCount(3),
        input_lwe_dimension: LweDimension(600),
        output_glwe_size: GlweSize(2),
        polynomial_size: PolynomialSize(1024),
        grouping_factor: LweBskGroupingFactor(2),
        ciphertext_modulus: CiphertextModulus::new_native(),
    }
}

#[test]
fn test_conformant_fourier_multi_bit_bsk() {
    let params = make_multi_bit_bsk_params();
    let bsk = FourierLweMultiBitBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        params.output_glwe_size,
        params.polynomial_size,
        params.decomp_base_log,
        params.decomp_level_count,
        params.grouping_factor,
    );
    assert!(bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_multi_bit_bsk_wrong_input_lwe_dimension() {
    let params = make_multi_bit_bsk_params();
    // Use a dimension that is still a multiple of grouping_factor but different from expected
    let wrong_dim = LweDimension(params.input_lwe_dimension.0 + params.grouping_factor.0);
    let bsk = FourierLweMultiBitBootstrapKeyOwned::new(
        wrong_dim,
        params.output_glwe_size,
        params.polynomial_size,
        params.decomp_base_log,
        params.decomp_level_count,
        params.grouping_factor,
    );
    assert!(!bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_multi_bit_bsk_wrong_glwe_size() {
    let params = make_multi_bit_bsk_params();
    let bsk = FourierLweMultiBitBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        GlweSize(params.output_glwe_size.0 + 1),
        params.polynomial_size,
        params.decomp_base_log,
        params.decomp_level_count,
        params.grouping_factor,
    );
    assert!(!bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_multi_bit_bsk_wrong_polynomial_size() {
    let params = make_multi_bit_bsk_params();
    let bsk = FourierLweMultiBitBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        params.output_glwe_size,
        PolynomialSize(params.polynomial_size.0 * 2),
        params.decomp_base_log,
        params.decomp_level_count,
        params.grouping_factor,
    );
    assert!(!bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_multi_bit_bsk_wrong_decomp_base_log() {
    let params = make_multi_bit_bsk_params();
    let bsk = FourierLweMultiBitBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        params.output_glwe_size,
        params.polynomial_size,
        DecompositionBaseLog(params.decomp_base_log.0 + 1),
        params.decomp_level_count,
        params.grouping_factor,
    );
    assert!(!bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_multi_bit_bsk_wrong_decomp_level_count() {
    let params = make_multi_bit_bsk_params();
    let bsk = FourierLweMultiBitBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        params.output_glwe_size,
        params.polynomial_size,
        params.decomp_base_log,
        DecompositionLevelCount(params.decomp_level_count.0 + 1),
        params.grouping_factor,
    );
    assert!(!bsk.is_conformant(&params));
}

#[test]
fn test_non_conformant_fourier_multi_bit_bsk_wrong_grouping_factor() {
    let params = make_multi_bit_bsk_params();
    // grouping_factor(3) still divides input_lwe_dimension(600)
    let wrong_grouping = LweBskGroupingFactor(3);
    let bsk = FourierLweMultiBitBootstrapKeyOwned::new(
        params.input_lwe_dimension,
        params.output_glwe_size,
        params.polynomial_size,
        params.decomp_base_log,
        params.decomp_level_count,
        wrong_grouping,
    );
    assert!(!bsk.is_conformant(&params));
}
