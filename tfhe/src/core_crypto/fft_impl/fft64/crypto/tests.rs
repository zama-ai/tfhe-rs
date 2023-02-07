use crate::core_crypto::fft_impl::common::tests::test_bootstrap_generic;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKeyOwned;
use crate::core_crypto::prelude::*;

#[test]
fn test_bootstrap_u64() {
    test_bootstrap_generic::<u64, FourierLweBootstrapKeyOwned>(
        StandardDev(0.000007069849454709433),
        StandardDev(0.00000000000000029403601535432533),
    );
}

#[test]
fn test_bootstrap_u32() {
    test_bootstrap_generic::<u32, FourierLweBootstrapKeyOwned>(
        StandardDev(0.000007069849454709433),
        StandardDev(0.00000000000000029403601535432533),
    );
}
