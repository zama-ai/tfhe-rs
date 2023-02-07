use crate::core_crypto::fft_impl::common::tests::test_bootstrap_generic;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKeyOwned;
use crate::core_crypto::prelude::*;

fn sqr(x: f64) -> f64 {
    x * x
}

#[test]
fn test_bootstrap_u128() {
    test_bootstrap_generic::<u128, Fourier128LweBootstrapKeyOwned>(
        StandardDev(sqr(0.000007069849454709433)),
        StandardDev(sqr(0.00000000000000029403601535432533)),
    );
}

#[test]
fn test_bootstrap_u64() {
    test_bootstrap_generic::<u64, Fourier128LweBootstrapKeyOwned>(
        StandardDev(sqr(0.000007069849454709433)),
        StandardDev(sqr(0.00000000000000029403601535432533)),
    );
}

#[test]
fn test_bootstrap_u32() {
    test_bootstrap_generic::<u32, Fourier128LweBootstrapKeyOwned>(
        StandardDev(sqr(0.000007069849454709433)),
        StandardDev(sqr(0.00000000000000029403601535432533)),
    );
}
