pub mod modulus_switch_compression;
pub mod noise_distribution;
pub mod noise_level;
pub mod parameterized_test;
pub mod parameterized_test_bivariate_pbs_compliant;
pub mod shortint_compact_pk;

/// Number of assert in randomized tests
#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 200;
/// Number of iterations in randomized tests for smart operations
#[cfg(not(tarpaulin))]
const NB_TESTS_SMART: usize = 10;
/// Number of sub tests used to increase degree of ciphertexts
#[cfg(not(tarpaulin))]
const NB_SUB_TEST_SMART: usize = 40;

// Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to code
// instrumentation
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;
/// Number of iterations in randomized tests for smart operations
#[cfg(tarpaulin)]
const NB_TESTS_SMART: usize = 1;
// This constant is tailored to trigger a message extract during operation processing.
// It's applicable for PARAM_MESSAGE_2_CARRY_2_KS_PBS parameters set.
#[cfg(tarpaulin)]
const NB_SUB_TEST_SMART: usize = 5;
