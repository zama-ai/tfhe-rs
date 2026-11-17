pub mod modulus_switch_compression;
pub mod noise_distribution;
pub mod noise_level;
pub mod parameterized_test;
pub mod parameterized_test_bivariate_pbs_compliant;
pub mod shortint_compact_pk;

/// Number of assert in randomized tests
#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 200;

// Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to code
// instrumentation
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;
