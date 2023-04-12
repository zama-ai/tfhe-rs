use super::bootstrap::CrtNttLweBootstrapKey;
use crate::core_crypto::fft_impl::common::tests::test_bootstrap_generic;
use crate::core_crypto::prelude::*;
use aligned_vec::ABox;

#[test]
fn test_crt_bootstrap_u64() {
    test_bootstrap_generic::<u64, CrtNttLweBootstrapKey<u32, 5, ABox<[u32]>>>(
        StandardDev(0.000007069849454709433),
        StandardDev(0.00000000000000029403601535432533),
    );
}
