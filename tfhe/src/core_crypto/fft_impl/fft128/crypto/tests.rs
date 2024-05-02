use crate::core_crypto::fft_impl::common::tests::test_bootstrap_generic;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKeyOwned;
#[cfg(tarpaulin)]
use crate::core_crypto::prelude::test::{
    COVERAGE_FFT_U128_PARAMS, COVERAGE_FFT_U32_PARAMS, COVERAGE_FFT_U64_PARAMS,
};
use crate::core_crypto::prelude::test::{FFT_U128_PARAMS, FFT_U32_PARAMS, FFT_U64_PARAMS};

#[test]
fn test_bootstrap_u128() {
    #[cfg(not(tarpaulin))]
    test_bootstrap_generic::<u128, Fourier128LweBootstrapKeyOwned>(FFT_U128_PARAMS);
    #[cfg(tarpaulin)]
    test_bootstrap_generic::<u128, Fourier128LweBootstrapKeyOwned>(COVERAGE_FFT_U128_PARAMS);
}

#[test]
fn test_bootstrap_u64() {
    #[cfg(not(tarpaulin))]
    test_bootstrap_generic::<u64, Fourier128LweBootstrapKeyOwned>(FFT_U64_PARAMS);
    #[cfg(tarpaulin)]
    test_bootstrap_generic::<u64, Fourier128LweBootstrapKeyOwned>(COVERAGE_FFT_U64_PARAMS);
}

#[test]
fn test_bootstrap_u32() {
    #[cfg(not(tarpaulin))]
    test_bootstrap_generic::<u32, Fourier128LweBootstrapKeyOwned>(FFT_U32_PARAMS);
    #[cfg(tarpaulin)]
    test_bootstrap_generic::<u32, Fourier128LweBootstrapKeyOwned>(COVERAGE_FFT_U32_PARAMS);
}
