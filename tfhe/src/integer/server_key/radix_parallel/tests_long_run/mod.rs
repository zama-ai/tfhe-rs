pub(crate) mod test_erc20;
pub(crate) mod test_random_op_sequence;
pub(crate) mod test_signed_erc20;
pub(crate) mod test_signed_random_op_sequence;
pub(crate) const NB_CTXT_LONG_RUN: usize = 32;
pub(crate) const NB_TESTS_LONG_RUN: usize = 20000;
pub(crate) const NB_TESTS_LONG_RUN_MINIMAL: usize = 200;

pub(crate) fn get_long_test_iterations() -> usize {
    static SINGLE_KEY_DEBUG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    let is_long_tests_minimal = *SINGLE_KEY_DEBUG.get_or_init(|| {
        std::env::var("TFHE_RS_BENCH_LONG_TESTS_MINIMAL")
            .is_ok_and(|val| val.to_uppercase() == "TRUE")
    });

    if is_long_tests_minimal {
        NB_TESTS_LONG_RUN_MINIMAL
    } else {
        NB_TESTS_LONG_RUN
    }
}
