use crate::core_crypto::fft_impl::common::tests::test_bootstrap_generic;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKeyOwned;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap_half_rotate::tests::{
    half_rotate_bootstrap_generic, half_rotate_matches_classic_bsk_generic,
};
use crate::core_crypto::prelude::test::{FFT_U128_PARAMS, FFT_U32_PARAMS, FFT_U64_PARAMS};

#[test]
fn test_bootstrap_u128() {
    test_bootstrap_generic::<u128, Fourier128LweBootstrapKeyOwned>(FFT_U128_PARAMS);
}

#[test]
fn test_bootstrap_u64() {
    test_bootstrap_generic::<u64, Fourier128LweBootstrapKeyOwned>(FFT_U64_PARAMS);
}

#[test]
fn test_bootstrap_u32() {
    test_bootstrap_generic::<u32, Fourier128LweBootstrapKeyOwned>(FFT_U32_PARAMS);
}

// `u128` output: goes through the split-limb `blind_rotate_u128` path.
#[test]
fn test_half_rotate_bootstrap_u128() {
    half_rotate_bootstrap_generic::<u128>();
}

// `u64` output: goes through the generic `blind_rotate_assign` path (the non-`u128` branch of
// `blind_rotate`), which the `u128` test never reaches.
#[test]
fn test_half_rotate_bootstrap_u64() {
    half_rotate_bootstrap_generic::<u64>();
}

// `u32` output: also goes through the generic `blind_rotate_assign` path.
#[test]
fn test_half_rotate_bootstrap_u32() {
    half_rotate_bootstrap_generic::<u32>();
}

#[test]
fn test_half_rotate_matches_classic_bsk_u128() {
    half_rotate_matches_classic_bsk_generic::<u128>();
}

#[test]
fn test_half_rotate_matches_classic_bsk_u64() {
    half_rotate_matches_classic_bsk_generic::<u64>();
}
