mod modulus_switch_compression;
pub(crate) mod test_add;
pub(crate) mod test_bitwise_op;
pub(crate) mod test_cmux;
pub(crate) mod test_comparison;
pub(crate) mod test_mul;
pub(crate) mod test_neg;
pub(crate) mod test_rotate;
pub(crate) mod test_scalar_add;
pub(crate) mod test_scalar_bitwise_op;
pub(crate) mod test_scalar_comparison;
pub(crate) mod test_scalar_mul;
pub(crate) mod test_scalar_rotate;
pub(crate) mod test_scalar_shift;
pub(crate) mod test_scalar_sub;
pub(crate) mod test_shift;
pub(crate) mod test_sub;
pub(crate) mod test_vector_comparisons;

use super::tests_cases_unsigned::*;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::tests::create_parametrized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::ciphertext::MaxDegree;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::prelude::ThreadRng;
use rand::Rng;
use std::sync::Arc;

/// Number of loop iteration within randomized tests
#[cfg(not(tarpaulin))]
pub(crate) const NB_TESTS: usize = 30;
/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
#[cfg(not(tarpaulin))]
pub(crate) const NB_TESTS_SMALLER: usize = 10;
// Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to code
// instrumentation
#[cfg(tarpaulin)]
pub(crate) const NB_TESTS: usize = 1;
#[cfg(tarpaulin)]
pub(crate) const NB_TESTS_SMALLER: usize = 1;

#[cfg(not(tarpaulin))]
pub(crate) const NB_CTXT: usize = 4;
#[cfg(tarpaulin)]
pub(crate) const NB_CTXT: usize = 2;

#[cfg(not(tarpaulin))]
pub(crate) const NB_TESTS_UNCHECKED: usize = NB_TESTS;
/// Unchecked test cases needs a minimum number of tests of 4 in order to provide guarantees.
#[cfg(tarpaulin)]
pub(crate) const NB_TESTS_UNCHECKED: usize = 4;

#[cfg(not(tarpaulin))]
pub(crate) const MAX_VEC_LEN: usize = 25;
#[cfg(tarpaulin)]
pub(crate) const MAX_VEC_LEN: usize = 5;

/// Returns th number of loop iteration within randomized tests
///
/// The bigger the number of bits bootstrapped by the input parameters, the smaller the
/// number of iteration is
pub(crate) const fn nb_tests_for_params(params: PBSParameters) -> usize {
    let full_modulus = params.message_modulus().0 * params.carry_modulus().0;

    if cfg!(tarpaulin) {
        // Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to
        // code instrumentation
        1
    } else {
        // >= 8 bits (4_4)
        if full_modulus >= 1 << 8 {
            return 5;
        }

        // >= 6 bits (3_3)
        if full_modulus >= 1 << 6 {
            return 15;
        }

        30
    }
}

pub(crate) fn random_non_zero_value(rng: &mut ThreadRng, modulus: u64) -> u64 {
    rng.gen_range(1..modulus)
}

/// helper function to do a rotate left when the type used to store
/// the value is bigger than the actual intended bit size
pub(crate) fn rotate_left_helper(value: u64, n: u32, actual_bit_size: u32) -> u64 {
    // We start with:
    // [0000000000000|xxxx]
    // 64           b    0
    //
    // rotated will be
    // [0000000000xx|xx00]
    // 64           b    0
    let n = n % actual_bit_size;
    let mask = 1u64.wrapping_shl(actual_bit_size) - 1;
    let shifted_mask = mask.wrapping_shl(n) & !mask;

    let rotated = value.rotate_left(n);

    (rotated & mask) | ((rotated & shifted_mask) >> actual_bit_size)
}

/// helper function to do a rotate right when the type used to store
/// the value is bigger than the actual intended bit size
pub(crate) fn rotate_right_helper(value: u64, n: u32, actual_bit_size: u32) -> u64 {
    // We start with:
    // [0000000000000|xxxx]
    // 64           b    0
    //
    // mask: [000000000000|mmmm]
    // shifted_ mask: [mm0000000000|0000]
    //
    // rotated will be
    // [xx0000000000|00xx]
    // 64           b    0
    //
    // To get the 'cycled' bits where they should be,
    // we get them using a mask then shift
    let n = n % actual_bit_size;
    let mask = 1u64.wrapping_shl(actual_bit_size) - 1;
    // shifted mask only needs the bits that cycled
    let shifted_mask = mask.rotate_right(n) & !mask;

    let rotated = value.rotate_right(n);

    (rotated & mask) | ((rotated & shifted_mask) >> (u64::BITS - actual_bit_size))
}

pub(crate) fn overflowing_sub_under_modulus(lhs: u64, rhs: u64, modulus: u64) -> (u64, bool) {
    assert!(
        !(modulus.is_power_of_two() && (modulus - 1).overflowing_mul(2).1),
        "If modulus is not a power of two, then  must not overflow u64"
    );
    let (result, overflowed) = lhs.overflowing_sub(rhs);
    (result % modulus, overflowed)
}

pub(crate) fn overflowing_add_under_modulus(lhs: u64, rhs: u64, modulus: u64) -> (u64, bool) {
    let (result, overflowed) = lhs.overflowing_add(rhs);
    (result % modulus, overflowed || result >= modulus)
}

pub(crate) fn overflowing_sum_slice_under_modulus(elems: &[u64], modulus: u64) -> (u64, bool) {
    let mut s = 0u64;
    let mut o = false;
    for e in elems.iter().copied() {
        let (curr_s, curr_o) = overflowing_add_under_modulus(s, e, modulus);
        s = curr_s;
        o |= curr_o;
    }
    (s, o)
}

pub(crate) fn overflowing_mul_under_modulus(a: u64, b: u64, modulus: u64) -> (u64, bool) {
    let (mut result, mut overflow) = a.overflowing_mul(b);
    overflow |= result >= modulus;
    result %= modulus;
    (result, overflow)
}

pub(crate) fn unsigned_modulus(block_modulus: MessageModulus, num_blocks: u32) -> u64 {
    (block_modulus.0 as u64)
        .checked_pow(num_blocks)
        .expect("Modulus exceed u64::MAX")
}

/// Given a radix ciphertext, checks that all the block's decrypted message and carry
/// do not exceed the block's degree.
#[track_caller]
fn panic_if_any_block_values_exceeds_its_degree<C>(ct: &RadixCiphertext, cks: &C)
where
    C: AsRef<crate::integer::ClientKey>,
{
    let cks = cks.as_ref();
    for (i, block) in ct.blocks.iter().enumerate() {
        let block_value = cks.key.decrypt_message_and_carry(block);
        assert!(
            block_value <= block.degree.get() as u64,
            "Block at index {i} has a value {block_value} that exceeds its degree ({:?})",
            block.degree
        );
    }
}

#[track_caller]
fn panic_if_any_block_info_exceeds_max_degree_or_noise(
    ct: &RadixCiphertext,
    max_degree: MaxDegree,
    max_noise_level: MaxNoiseLevel,
) {
    if ct.blocks.is_empty() {
        return;
    }

    // The max degree is made such that a block is able to receive the carry from
    // its predecessor when using the sequential propagation algorithm.
    //
    // However, as the first block does not have a predecessor, its max degree is actually
    // bigger
    let first_block = &ct.blocks[0];
    let first_block_max_degree =
        MaxDegree::from_msg_carry_modulus(first_block.message_modulus, first_block.carry_modulus);
    assert!(
        first_block_max_degree.validate(first_block.degree).is_ok(),
        "Block at index 0 has a degree {:?} that exceeds max degree ({first_block_max_degree:?})",
        first_block.degree
    );
    assert!(
        max_noise_level.validate(first_block.noise_level).is_ok(),
        "Block at index 0 has a noise level {:?} that exceeds max noise level ({max_noise_level:?})",
        first_block.degree
    );

    for (i, block) in ct.blocks.iter().enumerate().skip(1) {
        assert!(
            max_degree.validate(block.degree).is_ok(),
            "Block at index {i} has a degree {:?} that exceeds max degree ({max_degree:?})",
            block.degree
        );
        assert!(
            max_noise_level.validate(block.noise_level).is_ok(),
            "Block at index {i} has a noise level {:?} that exceeds max noise level ({max_noise_level:?})",
            block.degree
        );
    }
}

/// In radix context, a block is considered clean if:
/// - Its degree is <= message_modulus - 1
/// - Its decrypted_value is <= its degree
/// - Its noise level is nominal
#[track_caller]
fn panic_if_any_block_is_not_clean<C>(ct: &RadixCiphertext, cks: &C)
where
    C: AsRef<crate::integer::ClientKey>,
{
    let cks = cks.as_ref();

    let max_degree_acceptable = cks.key.parameters.message_modulus().0 - 1;

    for (i, block) in ct.blocks.iter().enumerate() {
        assert_eq!(
            block.noise_level,
            NoiseLevel::NOMINAL,
            "Block at index {i} has a non nominal noise level: {:?}",
            block.noise_level
        );

        assert!(
            block.degree.get() <= max_degree_acceptable,
            "Block at index {i} has a degree {:?} that exceeds the maximum ({}) for a clean block",
            block.degree,
            max_degree_acceptable
        );

        let block_value = cks.key.decrypt_message_and_carry(block);
        assert!(
            block_value <= block.degree.get() as u64,
            "Block at index {i} has a value {block_value} that exceeds its degree ({:?})",
            block.degree
        );
    }
}

/// Little struct meant to reduce test boilerplate and increase readability
struct ExpectedValues<T> {
    values: Vec<T>,
}

type ExpectedNoiseLevels = ExpectedValues<NoiseLevel>;
type ExpectedDegrees = ExpectedValues<Degree>;

impl<T> ExpectedValues<T> {
    fn new(init: T, len: usize) -> Self
    where
        T: Clone,
    {
        Self {
            values: vec![init; len],
        }
    }

    fn set_with(&mut self, iter: impl Iterator<Item = T>) {
        let mut self_iter = self.values.iter_mut();
        self_iter
            .by_ref()
            .zip(iter)
            .for_each(|(old_value, new_value)| {
                *old_value = new_value;
            });
        assert!(
            self_iter.next().is_none(),
            "Did not update all expected values"
        );
    }
}

impl ExpectedNoiseLevels {
    #[track_caller]
    fn panic_if_any_is_not_equal(&self, ct: &RadixCiphertext) {
        assert_eq!(self.values.len(), ct.blocks.len());
        for (i, (block, expected_noise)) in ct
            .blocks
            .iter()
            .zip(self.values.iter().copied())
            .enumerate()
        {
            assert_eq!(
                block.noise_level, expected_noise,
                "Block at index {i} has noise level {:?}, but {expected_noise:?} was expected",
                block.noise_level
            );
        }
    }
}

impl ExpectedDegrees {
    #[track_caller]
    fn panic_if_any_is_not_equal(&self, ct: &RadixCiphertext) {
        assert_eq!(self.values.len(), ct.blocks.len());
        for (i, (block, expected_degree)) in ct
            .blocks
            .iter()
            .zip(self.values.iter().copied())
            .enumerate()
        {
            assert_eq!(
                block.degree, expected_degree,
                "Block at index {i} has degree {:?}, but {expected_degree:?} was expected",
                block.degree
            );
        }
    }
}

create_parametrized_test!(
    integer_smart_div_rem {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_smart_div {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_smart_rem {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_default_div_rem {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_default_rem {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_default_div {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(integer_smart_sum_ciphertexts_slice);
create_parametrized_test!(integer_default_unsigned_overflowing_sum_ciphertexts_vec);
// left/right shifts
create_parametrized_test!(
    integer_unchecked_left_shift {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // This algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_unchecked_right_shift {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // This algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
// left/right rotations
create_parametrized_test!(
    integer_unchecked_rotate_left {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // This algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_unchecked_rotate_right {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // This algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
// left/right rotations
create_parametrized_test!(integer_default_scalar_div_rem);
create_parametrized_test!(integer_trim_radix_msb_blocks_handles_dirty_inputs);
create_parametrized_test!(integer_default_trailing_zeros);
create_parametrized_test!(integer_default_trailing_ones);
create_parametrized_test!(integer_default_leading_zeros);
create_parametrized_test!(integer_default_leading_ones);
create_parametrized_test!(integer_default_ilog2);
create_parametrized_test!(integer_default_checked_ilog2 {
    // This uses comparisons, so require more than 1 bit
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});

create_parametrized_test!(
    integer_full_propagate {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MESSAGE_2_CARRY_3_KS_PBS,  // Test case where carry_modulus > message_modulus
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_2_CARRY_3_KS_PBS,  // Test case where carry_modulus > message_modulus
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);

/// The function executor for cpu server key
///
/// It will mainly simply forward call to a server key method
pub(crate) struct CpuFunctionExecutor<F> {
    /// The server key is set later, when the test cast calls setup
    pub(crate) sks: Option<Arc<ServerKey>>,
    /// The server key function which will be called
    pub(crate) func: F,
}

impl<F> CpuFunctionExecutor<F> {
    pub(crate) fn new(func: F) -> Self {
        Self { sks: None, func }
    }
}

/// For unary function
///
/// Note, we don't do
/// impl<F, I, O> TestExecutor<I, O> for CpuTestExecutor<F>
/// where F: Fn(&ServerKey, I) -> O {}
/// As it would conflict with other impls.
///
/// impl<F, I1, O> TestExecutor<(I,), O> for CpuTestExecutor<F>
/// would be possible tho.
impl<'a, F> FunctionExecutor<&'a RadixCiphertext, (RadixCiphertext, BooleanBlock)>
    for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &RadixCiphertext) -> (RadixCiphertext, BooleanBlock),
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a RadixCiphertext) -> (RadixCiphertext, BooleanBlock) {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}

impl<'a, F> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &RadixCiphertext) -> RadixCiphertext,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a RadixCiphertext) -> RadixCiphertext {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}

impl<'a, F> FunctionExecutor<&'a Vec<RadixCiphertext>, Option<RadixCiphertext>>
    for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &Vec<RadixCiphertext>) -> Option<RadixCiphertext>,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a Vec<RadixCiphertext>) -> Option<RadixCiphertext> {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}

/// Unary assign fn
impl<'a, F> FunctionExecutor<&'a mut RadixCiphertext, ()> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &'a mut RadixCiphertext),
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a mut RadixCiphertext) {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input);
    }
}

impl<'a, F> FunctionExecutor<&'a mut RadixCiphertext, RadixCiphertext> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &mut RadixCiphertext) -> RadixCiphertext,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a mut RadixCiphertext) -> RadixCiphertext {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}

/// For binary operations
impl<F, I1, I2, O> FunctionExecutor<(I1, I2), O> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, I1, I2) -> O,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: (I1, I2)) -> O {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input.0, input.1)
    }
}

/// For ternary operations
impl<F, I1, I2, I3, O> FunctionExecutor<(I1, I2, I3), O> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, I1, I2, I3) -> O,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: (I1, I2, I3)) -> O {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input.0, input.1, input.2)
    }
}

//=============================================================================
// Unchecked Tests
//=============================================================================

fn integer_unchecked_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_left_shift_parallelized);
    unchecked_left_shift_test(param, executor);
}

fn integer_unchecked_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_right_shift_parallelized);
    unchecked_right_shift_test(param, executor);
}

fn integer_unchecked_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_left_parallelized);
    unchecked_rotate_left_test(param, executor);
}

fn integer_unchecked_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_right_parallelized);
    unchecked_rotate_right_test(param, executor);
}

//=============================================================================
// Unchecked Scalar Tests
//=============================================================================

//=============================================================================
// Smart Tests
//=============================================================================

fn integer_smart_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_div_rem_parallelized);
    smart_div_rem_test(param, executor);
}

fn integer_smart_div<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_div_parallelized);
    smart_div_test(param, executor);
}

fn integer_smart_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_rem_parallelized);
    smart_rem_test(param, executor);
}

fn integer_smart_sum_ciphertexts_slice<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for len in [1, 2, 15, 16, 17, 64, 65] {
        for _ in 0..NB_TESTS_SMALLER {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            // encryption of integers
            let mut ctxts = clears
                .iter()
                .copied()
                .map(|clear| cks.encrypt(clear))
                .collect::<Vec<_>>();

            let ct_res = sks.smart_sum_ciphertexts_parallelized(&mut ctxts).unwrap();
            let ct_res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(ct_res, clear);
        }
    }
}

fn integer_default_unsigned_overflowing_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<PBSParameters>,
{
    integer_default_unsigned_overflowing_sum_ciphertexts_test(param);
}

//=============================================================================
// Smart Scalar Tests
//=============================================================================

//=============================================================================
// Default Tests
//=============================================================================

fn integer_default_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::div_rem_parallelized);
    default_div_rem_test(param, executor);
}

fn integer_default_div<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::div_parallelized);
    default_div_test(param, executor);
}

fn integer_default_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rem_parallelized);
    default_rem_test(param, executor);
}

fn integer_default_trailing_zeros<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::trailing_zeros_parallelized);
    default_trailing_zeros_test(param, executor);
}

fn integer_default_trailing_ones<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::trailing_ones_parallelized);
    default_trailing_ones_test(param, executor);
}

fn integer_default_leading_zeros<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::leading_zeros_parallelized);
    default_leading_zeros_test(param, executor);
}

fn integer_default_leading_ones<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::leading_ones_parallelized);
    default_leading_ones_test(param, executor);
}

fn integer_default_ilog2<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::ilog2_parallelized);
    default_ilog2_test(param, executor);
}

fn integer_default_checked_ilog2<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::checked_ilog2_parallelized);
    default_checked_ilog2_test(param, executor);
}

fn integer_default_scalar_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_div_rem_parallelized);
    default_scalar_div_rem_test(param, executor);
}

#[test]
#[cfg(not(tarpaulin))]
fn test_non_regression_clone_from() {
    // Issue: https://github.com/zama-ai/tfhe-rs/issues/410
    let (client_key, server_key) =
        KEY_CACHE.get_from_params(PARAM_MESSAGE_2_CARRY_2, IntegerKeyKind::Radix);
    let num_block: usize = 4;
    let a: u8 = 248;
    let b: u8 = 249;
    let c: u8 = 250;
    let d: u8 = 251;

    let enc_a = client_key.encrypt_radix(a, num_block);
    let enc_b = client_key.encrypt_radix(b, num_block);
    let enc_c = client_key.encrypt_radix(c, num_block);
    let enc_d = client_key.encrypt_radix(d, num_block);

    let (mut q1, mut r1) = server_key.div_rem_parallelized(&enc_b, &enc_a);
    let (mut q2, mut r2) = server_key.div_rem_parallelized(&enc_d, &enc_c);

    assert_eq!(client_key.decrypt_radix::<u8>(&r1), 1);
    assert_eq!(client_key.decrypt_radix::<u8>(&r2), 1);
    assert_eq!(client_key.decrypt_radix::<u8>(&q1), 1);
    assert_eq!(client_key.decrypt_radix::<u8>(&q2), 1);

    // The consequence of the bug was that r1r2 would be 0 instead of one
    let r1r2 = server_key.smart_mul_parallelized(&mut r1, &mut r2);
    assert_eq!(client_key.decrypt_radix::<u8>(&r1r2), 1);
    let q1q2 = server_key.smart_mul_parallelized(&mut q1, &mut q2);
    assert_eq!(client_key.decrypt_radix::<u8>(&q1q2), 1);
}

fn integer_trim_radix_msb_blocks_handles_dirty_inputs<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let param = param.into();
    let (client_key, server_key) = crate::integer::gen_keys_radix(param, NB_CTXT);
    let modulus = (param.message_modulus().0 as u64)
        .checked_pow(NB_CTXT as u32)
        .expect("modulus of ciphertext exceed u64::MAX");
    let num_bits = param.message_modulus().0.ilog2() * NB_CTXT as u32;

    let msg1 = 1u64 << (num_bits - 1);
    let msg2 = 1u64 << (num_bits - 1);

    let mut ct_1 = client_key.encrypt(msg1);
    let mut ct_2 = client_key.encrypt(msg2);

    // We are now working on modulus * modulus
    server_key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut ct_1, NB_CTXT);
    server_key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut ct_2, NB_CTXT);

    let mut ct_3 = server_key.unchecked_add_parallelized(&ct_1, &ct_2);
    let output: u64 = client_key.decrypt(&ct_3);
    // Seems to be a false positive
    #[allow(clippy::suspicious_operation_groupings)]
    {
        assert_eq!(output, (msg2 + msg1) % (modulus * modulus));
    }
    assert_ne!(output, (msg2 + msg1) % (modulus));

    server_key.trim_radix_blocks_msb_assign(&mut ct_3, NB_CTXT);

    let output: u64 = client_key.decrypt(&ct_3);
    assert_eq!(output, (msg2 + msg1) % (modulus));

    // If the trim radix did not clean carries, the result of output
    // would still be on modulus * modulus
    server_key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut ct_3, NB_CTXT);
    let output: u64 = client_key.decrypt(&ct_3);
    assert_eq!(output, (msg2 + msg1) % (modulus));
}

fn integer_full_propagate<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::full_propagate_parallelized);
    full_propagate_test(param, executor);
}
