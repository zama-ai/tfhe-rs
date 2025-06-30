use std::env;
pub(crate) mod test_erc20;
pub(crate) mod test_random_op_sequence;
pub(crate) mod test_signed_erc20;
pub(crate) mod test_signed_random_op_sequence;
pub(crate) const NB_CTXT_LONG_RUN: usize = 32;
pub(crate) const NB_TESTS_LONG_RUN: usize = 20000;
pub(crate) const NB_TESTS_LONG_RUN_MINIMAL: usize = 200;

pub(crate) fn get_long_test_iterations() -> usize {
    if env::var("LONG_TESTS_MINIMAL")
        .unwrap_or_else(|_| "FALSE".to_string())
        .to_uppercase()
        == "TRUE"
    {
        NB_TESTS_LONG_RUN_MINIMAL
    } else {
        NB_TESTS_LONG_RUN
    }
}
