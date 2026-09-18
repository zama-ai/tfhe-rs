use crate::core_crypto::fft_impl::common::tests::test_bootstrap_generic;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKeyOwned;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap_half_product::tests::{
    half_product_bootstrap_generic, half_product_matches_classic_bsk_generic,
};
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap_half_product_half_rotate::tests::{
    half_product_half_rotate_bootstrap_generic,
    half_product_half_rotate_matches_classic_bsk_generic,
};
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

// `u128` output: goes through the split-limb `blind_rotate_u128` path.
#[test]
fn test_half_product_bootstrap_u128() {
    half_product_bootstrap_generic::<u128>();
}

// `u64` output: goes through the generic `blind_rotate_assign` path (the non-`u128` branch of
// `blind_rotate`), which the `u128` test never reaches.
#[test]
fn test_half_product_bootstrap_u64() {
    half_product_bootstrap_generic::<u64>();
}

// `u32` output: also goes through the generic `blind_rotate_assign` path.
#[test]
fn test_half_product_bootstrap_u32() {
    half_product_bootstrap_generic::<u32>();
}

// The split-limb `u128` path accumulates near the `fft128` precision limit, so the low bits of the
// two accumulation orders differ. The deviation is a function of the random key and input, so the
// tolerance is set well above the values observed in practice (around `2^40`) rather than at a
// tight bound a rare draw could exceed. `2^56` out of `2^128` is still 67 bits below the `2^123`
// spacing of the encoded messages, so a structural error cannot hide under it.
#[test]
fn test_half_product_matches_classic_bsk_u128() {
    half_product_matches_classic_bsk_generic::<u128>(1 << 56);
}

#[test]
fn test_half_product_matches_classic_bsk_u64() {
    half_product_matches_classic_bsk_generic::<u64>(0);
}

#[test]
fn test_half_product_half_rotate_bootstrap_u128() {
    half_product_half_rotate_bootstrap_generic::<u128>();
}

#[test]
fn test_half_product_half_rotate_bootstrap_u64() {
    half_product_half_rotate_bootstrap_generic::<u64>();
}

// See `test_half_product_matches_classic_bsk_u128` for the tolerance.
#[test]
fn test_half_product_half_rotate_matches_classic_bsk_u128() {
    half_product_half_rotate_matches_classic_bsk_generic::<u128>(1 << 56);
}

#[test]
fn test_half_product_half_rotate_matches_classic_bsk_u64() {
    half_product_half_rotate_matches_classic_bsk_generic::<u64>(0);
}
