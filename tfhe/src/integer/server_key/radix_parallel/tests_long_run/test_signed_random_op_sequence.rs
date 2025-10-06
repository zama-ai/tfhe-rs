use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_long_run::{
    get_long_test_iterations, get_user_defined_seed, sanity_check_op_sequence_result_bool,
    sanity_check_op_sequence_result_i64, sanity_check_op_sequence_result_u64,
    OpSequenceFunctionExecutor, RandomOpSequenceDataGenerator, NB_CTXT_LONG_RUN,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::OpSequenceCpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
use crate::shortint::parameters::*;
use crate::{ClientKey, CompressedServerKey, Seed, Tag};
use std::cmp::{max, min};
use std::sync::Arc;

create_parameterized_test!(random_op_sequence {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

pub(crate) type SignedBinaryOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
>;
pub(crate) type SignedShiftRotateExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, &'a RadixCiphertext),
        SignedRadixCiphertext,
    >,
>;
pub(crate) type SignedUnaryOpExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>>;

pub(crate) type SignedScalarBinaryOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
>;
pub(crate) type SignedScalarShiftRotateExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
>;
pub(crate) type SignedOverflowingOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, BooleanBlock),
    >,
>;
pub(crate) type SignedScalarOverflowingOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, i64),
        (SignedRadixCiphertext, BooleanBlock),
    >,
>;
pub(crate) type SignedComparisonOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        BooleanBlock,
    >,
>;
pub(crate) type SignedScalarComparisonOpExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<(&'a SignedRadixCiphertext, i64), BooleanBlock>>;
pub(crate) type SignedSelectOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (
            &'a BooleanBlock,
            &'a SignedRadixCiphertext,
            &'a SignedRadixCiphertext,
        ),
        SignedRadixCiphertext,
    >,
>;
pub(crate) type SignedDivRemOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    >,
>;
pub(crate) type SignedScalarDivRemOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, i64),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    >,
>;
pub(crate) type SignedLog2OpExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>>;

// Add these new types for Signed OPRF operations
pub(crate) type SignedOprfExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<(Seed, u64), SignedRadixCiphertext>>;
pub(crate) type SignedOprfBoundedExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<(Seed, u64, u64), SignedRadixCiphertext>>;

fn random_op_sequence<P>(param: P)
where
    P: Into<TestParameters> + Clone,
{
    // Binary Ops Executors
    let add_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::add_parallelized);
    let sub_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::sub_parallelized);
    let bitwise_and_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::bitand_parallelized);
    let bitwise_or_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::bitor_parallelized);
    let bitwise_xor_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::bitxor_parallelized);
    let mul_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::mul_parallelized);
    let max_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::max_parallelized);
    let min_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::min_parallelized);

    // Binary Ops Clear functions
    let clear_add = |x: i64, y: i64| x.wrapping_add(y);
    let clear_sub = |x: i64, y: i64| x.wrapping_sub(y);
    let clear_bitwise_and = |x, y| x & y;
    let clear_bitwise_or = |x, y| x | y;
    let clear_bitwise_xor = |x, y| x ^ y;
    let clear_mul = |x: i64, y: i64| x.wrapping_mul(y);
    let clear_max = |x: i64, y: i64| max(x, y);
    let clear_min = |x: i64, y: i64| min(x, y);

    #[allow(clippy::type_complexity)]
    let mut binary_ops: Vec<(SignedBinaryOpExecutor, &dyn Fn(i64, i64) -> i64, String)> = vec![
        (Box::new(add_executor), &clear_add, "add".to_string()),
        (Box::new(sub_executor), &clear_sub, "sub".to_string()),
        (
            Box::new(bitwise_and_executor),
            &clear_bitwise_and,
            "bitand".to_string(),
        ),
        (
            Box::new(bitwise_or_executor),
            &clear_bitwise_or,
            "bitor".to_string(),
        ),
        (
            Box::new(bitwise_xor_executor),
            &clear_bitwise_xor,
            "bitxor".to_string(),
        ),
        (Box::new(mul_executor), &clear_mul, "mul".to_string()),
        (Box::new(max_executor), &clear_max, "max".to_string()),
        (Box::new(min_executor), &clear_min, "min".to_string()),
    ];

    let rotate_left_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::rotate_left_parallelized);
    let left_shift_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::left_shift_parallelized);
    let rotate_right_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::rotate_right_parallelized);
    let right_shift_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::right_shift_parallelized);
    // Warning this rotate definition only works with 64-bit ciphertexts
    let clear_rotate_left = |x: i64, y: u64| x.rotate_left(y as u32);
    let clear_left_shift = |x: i64, y: u64| x << y;
    // Warning this rotate definition only works with 64-bit ciphertexts
    let clear_rotate_right = |x: i64, y: u64| x.rotate_right(y as u32);
    let clear_right_shift = |x: i64, y: u64| x >> y;
    #[allow(clippy::type_complexity)]
    let mut rotate_shift_ops: Vec<(
        SignedShiftRotateExecutor,
        &dyn Fn(i64, u64) -> i64,
        String,
    )> = vec![
        (
            Box::new(rotate_left_executor),
            &clear_rotate_left,
            "rotate left".to_string(),
        ),
        (
            Box::new(left_shift_executor),
            &clear_left_shift,
            "left shift".to_string(),
        ),
        (
            Box::new(rotate_right_executor),
            &clear_rotate_right,
            "rotate right".to_string(),
        ),
        (
            Box::new(right_shift_executor),
            &clear_right_shift,
            "right shift".to_string(),
        ),
    ];
    // Unary Ops Executors
    let neg_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::neg_parallelized);
    let bitnot_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::bitnot);
    let reverse_bits_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::reverse_bits_parallelized);
    // Unary Ops Clear functions
    let clear_neg = |x: i64| x.wrapping_neg();
    let clear_bitnot = |x: i64| !x;
    let clear_reverse_bits = |x: i64| x.reverse_bits();
    #[allow(clippy::type_complexity)]
    let mut unary_ops: Vec<(SignedUnaryOpExecutor, &dyn Fn(i64) -> i64, String)> = vec![
        (Box::new(neg_executor), &clear_neg, "neg".to_string()),
        (
            Box::new(bitnot_executor),
            &clear_bitnot,
            "bitnot".to_string(),
        ),
        (
            Box::new(reverse_bits_executor),
            &clear_reverse_bits,
            "reverse bits".to_string(),
        ),
    ];

    // Scalar binary Ops Executors
    let scalar_add_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized);
    let scalar_sub_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized);
    let scalar_bitwise_and_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_bitand_parallelized);
    let scalar_bitwise_or_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_bitor_parallelized);
    let scalar_bitwise_xor_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_bitxor_parallelized);
    let scalar_mul_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_mul_parallelized);

    #[allow(clippy::type_complexity)]
    let mut scalar_binary_ops: Vec<(
        SignedScalarBinaryOpExecutor,
        &dyn Fn(i64, i64) -> i64,
        String,
    )> = vec![
        (
            Box::new(scalar_add_executor),
            &clear_add,
            "scalar add".to_string(),
        ),
        (
            Box::new(scalar_sub_executor),
            &clear_sub,
            "scalar sub".to_string(),
        ),
        (
            Box::new(scalar_bitwise_and_executor),
            &clear_bitwise_and,
            "scalar bitand".to_string(),
        ),
        (
            Box::new(scalar_bitwise_or_executor),
            &clear_bitwise_or,
            "scalar bitor".to_string(),
        ),
        (
            Box::new(scalar_bitwise_xor_executor),
            &clear_bitwise_xor,
            "scalar bitxor".to_string(),
        ),
        (
            Box::new(scalar_mul_executor),
            &clear_mul,
            "scalar mul".to_string(),
        ),
    ];

    let scalar_rotate_left_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_rotate_left_parallelized);
    let scalar_left_shift_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_left_shift_parallelized);
    let scalar_rotate_right_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_rotate_right_parallelized);
    let scalar_right_shift_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_right_shift_parallelized);
    #[allow(clippy::type_complexity)]
    let mut scalar_shift_rotate_ops: Vec<(
        SignedScalarShiftRotateExecutor,
        &dyn Fn(i64, u64) -> i64,
        String,
    )> = vec![
        (
            Box::new(scalar_rotate_left_executor),
            &clear_rotate_left,
            "scalar rotate left".to_string(),
        ),
        (
            Box::new(scalar_left_shift_executor),
            &clear_left_shift,
            "scalar left shift".to_string(),
        ),
        (
            Box::new(scalar_rotate_right_executor),
            &clear_rotate_right,
            "scalar rotate right".to_string(),
        ),
        (
            Box::new(scalar_right_shift_executor),
            &clear_right_shift,
            "scalar right shift".to_string(),
        ),
    ];

    // Overflowing Ops Executors
    let overflowing_add_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::signed_overflowing_add_parallelized);
    let overflowing_sub_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::signed_overflowing_sub_parallelized);
    let overflowing_mul_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::signed_overflowing_mul_parallelized);
    // Overflowing Ops Clear functions
    let clear_overflowing_add = |x: i64, y: i64| -> (i64, bool) { x.overflowing_add(y) };
    let clear_overflowing_sub = |x: i64, y: i64| -> (i64, bool) { x.overflowing_sub(y) };
    let clear_overflowing_mul = |x: i64, y: i64| -> (i64, bool) { x.overflowing_mul(y) };

    #[allow(clippy::type_complexity)]
    let mut overflowing_ops: Vec<(
        SignedOverflowingOpExecutor,
        &dyn Fn(i64, i64) -> (i64, bool),
        String,
    )> = vec![
        (
            Box::new(overflowing_add_executor),
            &clear_overflowing_add,
            "overflowing add".to_string(),
        ),
        (
            Box::new(overflowing_sub_executor),
            &clear_overflowing_sub,
            "overflowing sub".to_string(),
        ),
        (
            Box::new(overflowing_mul_executor),
            &clear_overflowing_mul,
            "overflowing mul".to_string(),
        ),
    ];

    // Scalar Overflowing Ops Executors
    let overflowing_scalar_add_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::signed_overflowing_scalar_add_parallelized);
    let overflowing_scalar_sub_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::signed_overflowing_scalar_sub_parallelized);

    #[allow(clippy::type_complexity)]
    let mut scalar_overflowing_ops: Vec<(
        SignedScalarOverflowingOpExecutor,
        &dyn Fn(i64, i64) -> (i64, bool),
        String,
    )> = vec![
        (
            Box::new(overflowing_scalar_add_executor),
            &clear_overflowing_add,
            "overflowing scalar add".to_string(),
        ),
        (
            Box::new(overflowing_scalar_sub_executor),
            &clear_overflowing_sub,
            "overflowing scalar sub".to_string(),
        ),
    ];

    // Comparison Ops Executors
    let gt_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::gt_parallelized);
    let ge_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::ge_parallelized);
    let lt_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::lt_parallelized);
    let le_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::le_parallelized);
    let eq_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::eq_parallelized);
    let ne_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::ne_parallelized);

    // Comparison Ops Clear functions
    let clear_gt = |x: i64, y: i64| -> bool { x > y };
    let clear_ge = |x: i64, y: i64| -> bool { x >= y };
    let clear_lt = |x: i64, y: i64| -> bool { x < y };
    let clear_le = |x: i64, y: i64| -> bool { x <= y };
    let clear_eq = |x: i64, y: i64| -> bool { x == y };
    let clear_ne = |x: i64, y: i64| -> bool { x != y };

    #[allow(clippy::type_complexity)]
    let mut comparison_ops: Vec<(
        SignedComparisonOpExecutor,
        &dyn Fn(i64, i64) -> bool,
        String,
    )> = vec![
        (Box::new(gt_executor), &clear_gt, "gt".to_string()),
        (Box::new(ge_executor), &clear_ge, "ge".to_string()),
        (Box::new(lt_executor), &clear_lt, "lt".to_string()),
        (Box::new(le_executor), &clear_le, "le".to_string()),
        (Box::new(eq_executor), &clear_eq, "eq".to_string()),
        (Box::new(ne_executor), &clear_ne, "ne".to_string()),
    ];

    // Scalar Comparison Ops Executors
    let scalar_gt_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_gt_parallelized);
    let scalar_ge_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_ge_parallelized);
    let scalar_lt_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_lt_parallelized);
    let scalar_le_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_le_parallelized);
    let scalar_eq_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_eq_parallelized);
    let scalar_ne_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_ne_parallelized);

    #[allow(clippy::type_complexity)]
    let mut scalar_comparison_ops: Vec<(
        SignedScalarComparisonOpExecutor,
        &dyn Fn(i64, i64) -> bool,
        String,
    )> = vec![
        (
            Box::new(scalar_gt_executor),
            &clear_gt,
            "scalar gt".to_string(),
        ),
        (
            Box::new(scalar_ge_executor),
            &clear_ge,
            "scalar ge".to_string(),
        ),
        (
            Box::new(scalar_lt_executor),
            &clear_lt,
            "scalar lt".to_string(),
        ),
        (
            Box::new(scalar_le_executor),
            &clear_le,
            "scalar le".to_string(),
        ),
        (
            Box::new(scalar_eq_executor),
            &clear_eq,
            "scalar eq".to_string(),
        ),
        (
            Box::new(scalar_ne_executor),
            &clear_ne,
            "scalar ne".to_string(),
        ),
    ];

    // Select Executor
    let select_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::cmux_parallelized);

    // Select
    let clear_select = |b: bool, x: i64, y: i64| if b { x } else { y };

    #[allow(clippy::type_complexity)]
    let mut select_op: Vec<(
        SignedSelectOpExecutor,
        &dyn Fn(bool, i64, i64) -> i64,
        String,
    )> = vec![(
        Box::new(select_executor),
        &clear_select,
        "select".to_string(),
    )];

    // Div executor
    let div_rem_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::div_rem_parallelized);
    // Div Rem Clear functions
    let clear_div_rem = |x: i64, y: i64| -> (i64, i64) { (x.wrapping_div(y), x.wrapping_rem(y)) };
    #[allow(clippy::type_complexity)]
    let mut div_rem_op: Vec<(
        SignedDivRemOpExecutor,
        &dyn Fn(i64, i64) -> (i64, i64),
        String,
    )> = vec![(
        Box::new(div_rem_executor),
        &clear_div_rem,
        "div rem".to_string(),
    )];

    // Scalar Div executor
    let scalar_div_rem_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::signed_scalar_div_rem_parallelized);
    #[allow(clippy::type_complexity)]
    let mut scalar_div_rem_op: Vec<(
        SignedScalarDivRemOpExecutor,
        &dyn Fn(i64, i64) -> (i64, i64),
        String,
    )> = vec![(
        Box::new(scalar_div_rem_executor),
        &clear_div_rem,
        "scalar div rem".to_string(),
    )];

    // Log2/Hamming weight ops
    let ilog2_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::ilog2_parallelized);
    let count_zeros_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::count_zeros_parallelized);
    let count_ones_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::count_ones_parallelized);
    let clear_ilog2 = |x: i64| x.ilog2() as u64;
    let clear_count_zeros = |x: i64| x.count_zeros() as u64;
    let clear_count_ones = |x: i64| x.count_ones() as u64;

    #[allow(clippy::type_complexity)]
    let mut log2_ops: Vec<(SignedLog2OpExecutor, &dyn Fn(i64) -> u64, String)> = vec![
        (Box::new(ilog2_executor), &clear_ilog2, "ilog2".to_string()),
        (
            Box::new(count_zeros_executor),
            &clear_count_zeros,
            "count zeros".to_string(),
        ),
        (
            Box::new(count_ones_executor),
            &clear_count_ones,
            "count ones".to_string(),
        ),
    ];

    let signed_oprf_executor = OpSequenceCpuFunctionExecutor::new(
        &ServerKey::par_generate_oblivious_pseudo_random_signed_integer,
    );
    let signed_oprf_bounded_executor = OpSequenceCpuFunctionExecutor::new(
        &ServerKey::par_generate_oblivious_pseudo_random_signed_integer_bounded,
    );

    let mut signed_oprf_ops: Vec<(SignedOprfExecutor, String)> = vec![(
        Box::new(signed_oprf_executor),
        "par_generate_oblivious_pseudo_random_signed_integer".to_string(),
    )];

    let mut signed_oprf_bounded_ops: Vec<(SignedOprfBoundedExecutor, String)> = vec![(
        Box::new(signed_oprf_bounded_executor),
        "par_generate_oblivious_pseudo_random_signed_integer_bounded".to_string(),
    )];

    let (cks, sks, mut datagen) = signed_random_op_sequence_test_init_cpu(
        param,
        &mut binary_ops,
        &mut unary_ops,
        &mut scalar_binary_ops,
        &mut overflowing_ops,
        &mut scalar_overflowing_ops,
        &mut comparison_ops,
        &mut scalar_comparison_ops,
        &mut select_op,
        &mut div_rem_op,
        &mut scalar_div_rem_op,
        &mut log2_ops,
        &mut rotate_shift_ops,
        &mut scalar_shift_rotate_ops,
        &mut signed_oprf_ops,
        &mut signed_oprf_bounded_ops,
    );

    signed_random_op_sequence_test(
        &mut datagen,
        &cks,
        &sks,
        &mut binary_ops,
        &mut unary_ops,
        &mut scalar_binary_ops,
        &mut overflowing_ops,
        &mut scalar_overflowing_ops,
        &mut comparison_ops,
        &mut scalar_comparison_ops,
        &mut select_op,
        &mut div_rem_op,
        &mut scalar_div_rem_op,
        &mut log2_ops,
        &mut rotate_shift_ops,
        &mut scalar_shift_rotate_ops,
        &mut signed_oprf_ops,
        &mut signed_oprf_bounded_ops,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn signed_random_op_sequence_test_init_cpu<P>(
    param: P,
    binary_ops: &mut [(SignedBinaryOpExecutor, impl Fn(i64, i64) -> i64, String)],
    unary_ops: &mut [(SignedUnaryOpExecutor, impl Fn(i64) -> i64, String)],
    scalar_binary_ops: &mut [(
        SignedScalarBinaryOpExecutor,
        impl Fn(i64, i64) -> i64,
        String,
    )],
    overflowing_ops: &mut [(
        SignedOverflowingOpExecutor,
        impl Fn(i64, i64) -> (i64, bool),
        String,
    )],
    scalar_overflowing_ops: &mut [(
        SignedScalarOverflowingOpExecutor,
        impl Fn(i64, i64) -> (i64, bool),
        String,
    )],
    comparison_ops: &mut [(
        SignedComparisonOpExecutor,
        impl Fn(i64, i64) -> bool,
        String,
    )],
    scalar_comparison_ops: &mut [(
        SignedScalarComparisonOpExecutor,
        impl Fn(i64, i64) -> bool,
        String,
    )],
    select_op: &mut [(
        SignedSelectOpExecutor,
        impl Fn(bool, i64, i64) -> i64,
        String,
    )],
    div_rem_op: &mut [(
        SignedDivRemOpExecutor,
        impl Fn(i64, i64) -> (i64, i64),
        String,
    )],
    scalar_div_rem_op: &mut [(
        SignedScalarDivRemOpExecutor,
        impl Fn(i64, i64) -> (i64, i64),
        String,
    )],
    log2_ops: &mut [(SignedLog2OpExecutor, impl Fn(i64) -> u64, String)],
    rotate_shift_ops: &mut [(SignedShiftRotateExecutor, impl Fn(i64, u64) -> i64, String)],
    scalar_rotate_shift_ops: &mut [(
        SignedScalarShiftRotateExecutor,
        impl Fn(i64, u64) -> i64,
        String,
    )],
    signed_oprf_ops: &mut [(SignedOprfExecutor, String)],
    signed_oprf_bounded_ops: &mut [(SignedOprfBoundedExecutor, String)],
) -> (
    RadixClientKey,
    Arc<ServerKey>,
    RandomOpSequenceDataGenerator<i64, SignedRadixCiphertext>,
)
where
    P: Into<TestParameters>,
{
    let total_num_ops = binary_ops.len()
        + unary_ops.len()
        + scalar_binary_ops.len()
        + overflowing_ops.len()
        + scalar_overflowing_ops.len()
        + comparison_ops.len()
        + scalar_comparison_ops.len()
        + select_op.len()
        + div_rem_op.len()
        + scalar_div_rem_op.len()
        + log2_ops.len()
        + rotate_shift_ops.len()
        + scalar_rotate_shift_ops.len()
        + signed_oprf_ops.len()
        + signed_oprf_bounded_ops.len();

    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let temp_cks =
        ClientKey::from_raw_parts(cks.clone(), None, None, None, None, None, Tag::default());
    let comp_sks = CompressedServerKey::new(&temp_cks);

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT_LONG_RUN));

    let mut datagen = get_user_defined_seed().map_or_else(
        || RandomOpSequenceDataGenerator::<i64, SignedRadixCiphertext>::new(total_num_ops, &cks),
        |seed| {
            RandomOpSequenceDataGenerator::<i64, SignedRadixCiphertext>::new_with_seed(
                total_num_ops,
                seed,
                &cks,
            )
        },
    );

    println!(
        "signed_random_op_sequence_test::seed = {}",
        datagen.get_seed().0
    );

    for x in binary_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in unary_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in scalar_binary_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in overflowing_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in scalar_overflowing_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in comparison_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in scalar_comparison_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in select_op.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in div_rem_op.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in scalar_div_rem_op.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in log2_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in rotate_shift_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in scalar_rotate_shift_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in signed_oprf_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in signed_oprf_bounded_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }

    (cks, sks, datagen)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn signed_random_op_sequence_test(
    datagen: &mut RandomOpSequenceDataGenerator<i64, SignedRadixCiphertext>,
    cks: &RadixClientKey,
    sks: &Arc<ServerKey>,
    binary_ops: &mut [(SignedBinaryOpExecutor, impl Fn(i64, i64) -> i64, String)],
    unary_ops: &mut [(SignedUnaryOpExecutor, impl Fn(i64) -> i64, String)],
    scalar_binary_ops: &mut [(
        SignedScalarBinaryOpExecutor,
        impl Fn(i64, i64) -> i64,
        String,
    )],
    overflowing_ops: &mut [(
        SignedOverflowingOpExecutor,
        impl Fn(i64, i64) -> (i64, bool),
        String,
    )],
    scalar_overflowing_ops: &mut [(
        SignedScalarOverflowingOpExecutor,
        impl Fn(i64, i64) -> (i64, bool),
        String,
    )],
    comparison_ops: &mut [(
        SignedComparisonOpExecutor,
        impl Fn(i64, i64) -> bool,
        String,
    )],
    scalar_comparison_ops: &mut [(
        SignedScalarComparisonOpExecutor,
        impl Fn(i64, i64) -> bool,
        String,
    )],
    select_op: &mut [(
        SignedSelectOpExecutor,
        impl Fn(bool, i64, i64) -> i64,
        String,
    )],
    div_rem_op: &mut [(
        SignedDivRemOpExecutor,
        impl Fn(i64, i64) -> (i64, i64),
        String,
    )],
    scalar_div_rem_op: &mut [(
        SignedScalarDivRemOpExecutor,
        impl Fn(i64, i64) -> (i64, i64),
        String,
    )],
    log2_ops: &mut [(SignedLog2OpExecutor, impl Fn(i64) -> u64, String)],
    rotate_shift_ops: &mut [(SignedShiftRotateExecutor, impl Fn(i64, u64) -> i64, String)],
    scalar_rotate_shift_ops: &mut [(
        SignedScalarShiftRotateExecutor,
        impl Fn(i64, u64) -> i64,
        String,
    )],
    signed_oprf_ops: &mut [(SignedOprfExecutor, String)],
    signed_oprf_bounded_ops: &mut [(SignedOprfBoundedExecutor, String)],
) {
    let binary_ops_range = 0..binary_ops.len();
    let unary_ops_range = binary_ops_range.end..binary_ops_range.end + unary_ops.len();
    let scalar_binary_ops_range =
        unary_ops_range.end..unary_ops_range.end + scalar_binary_ops.len();
    let overflowing_ops_range =
        scalar_binary_ops_range.end..scalar_binary_ops_range.end + overflowing_ops.len();
    let scalar_overflowing_ops_range =
        overflowing_ops_range.end..overflowing_ops_range.end + scalar_overflowing_ops.len();
    let comparison_ops_range =
        scalar_overflowing_ops_range.end..scalar_overflowing_ops_range.end + comparison_ops.len();
    let scalar_comparison_ops_range =
        comparison_ops_range.end..comparison_ops_range.end + scalar_comparison_ops.len();
    let select_op_range =
        scalar_comparison_ops_range.end..scalar_comparison_ops_range.end + select_op.len();
    let div_rem_op_range = select_op_range.end..select_op_range.end + div_rem_op.len();
    let scalar_div_rem_op_range =
        div_rem_op_range.end..div_rem_op_range.end + scalar_div_rem_op.len();
    let log2_ops_range = scalar_div_rem_op_range.end..scalar_div_rem_op_range.end + log2_ops.len();
    let rotate_shift_ops_range = log2_ops_range.end..log2_ops_range.end + rotate_shift_ops.len();
    let scalar_rotate_shift_ops_range =
        rotate_shift_ops_range.end..rotate_shift_ops_range.end + scalar_rotate_shift_ops.len();
    let signed_oprf_ops_range = scalar_rotate_shift_ops_range.end
        ..scalar_rotate_shift_ops_range.end + signed_oprf_ops.len();
    let signed_oprf_bounded_ops_range =
        signed_oprf_ops_range.end..signed_oprf_ops_range.end + signed_oprf_bounded_ops.len();

    for fn_index in 0..get_long_test_iterations() {
        let (i, idx) = datagen.gen_op_index();

        if binary_ops_range.contains(&i) {
            let index = i - binary_ops_range.start;
            let (binary_op_executor, clear_fn, fn_name) = &mut binary_ops[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let res = binary_op_executor.execute((&lhs.c, &rhs.c));

            // Determinism check
            let res_1 = binary_op_executor.execute((&lhs.c, &rhs.c));

            let decrypt_signed_res: i64 = cks.decrypt_signed(&res);
            let expected_res: i64 = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res,
                expected_res,
                lhs.p,
                rhs.p,
            );
        } else if unary_ops_range.contains(&i) {
            let index = i - unary_ops_range.start;
            let (unary_op_executor, clear_fn, fn_name) = &mut unary_ops[index];

            let operand = datagen.gen_op_single_operand(idx, fn_name);

            let res = unary_op_executor.execute(&operand.c);
            // Determinism check
            let res_1 = unary_op_executor.execute(&operand.c);

            let decrypt_signed_res: i64 = cks.decrypt_signed(&res);
            let expected_res: i64 = clear_fn(operand.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res,
                expected_res,
                operand.p,
                operand.p,
            );
        } else if scalar_binary_ops_range.contains(&i) {
            let index = i - scalar_binary_ops_range.start;
            let (scalar_binary_op_executor, clear_fn, fn_name) = &mut scalar_binary_ops[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let res = scalar_binary_op_executor.execute((&lhs.c, rhs.p));
            // Determinism check
            let res_1 = scalar_binary_op_executor.execute((&lhs.c, rhs.p));

            let decrypt_signed_res: i64 = cks.decrypt_signed(&res);
            let expected_res: i64 = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res,
                expected_res,
                lhs.p,
                rhs.p,
            );
        } else if overflowing_ops_range.contains(&i) {
            let index = i - overflowing_ops_range.start;
            let (overflowing_op_executor, clear_fn, fn_name) = &mut overflowing_ops[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let (res, overflow) = overflowing_op_executor.execute((&lhs.c, &rhs.c));
            // Determinism check
            let (res_1, overflow_1) = overflowing_op_executor.execute((&lhs.c, &rhs.c));

            let decrypt_signed_res: i64 = cks.decrypt_signed(&res);
            let decrypt_signed_overflow = cks.decrypt_bool(&overflow);
            let (expected_res, expected_overflow) = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res,
                expected_res,
                lhs.p,
                rhs.p,
            );

            sanity_check_op_sequence_result_bool(
                idx,
                fn_name,
                fn_index,
                &overflow,
                &overflow_1,
                decrypt_signed_overflow,
                expected_overflow,
                lhs.p,
                rhs.p,
            );
        } else if scalar_overflowing_ops_range.contains(&i) {
            let index = i - scalar_overflowing_ops_range.start;
            let (scalar_overflowing_op_executor, clear_fn, fn_name) =
                &mut scalar_overflowing_ops[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let (res, overflow) = scalar_overflowing_op_executor.execute((&lhs.c, rhs.p));
            // Check carries are empty and noise level is lower or equal to nominal
            let (res_1, overflow_1) = scalar_overflowing_op_executor.execute((&lhs.c, rhs.p));

            let decrypt_signed_res: i64 = cks.decrypt_signed(&res);
            let decrypt_signed_overflow = cks.decrypt_bool(&overflow);
            let (expected_res, expected_overflow) = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res,
                expected_res,
                lhs.p,
                rhs.p,
            );

            sanity_check_op_sequence_result_bool(
                idx,
                fn_name,
                fn_index,
                &overflow,
                &overflow_1,
                decrypt_signed_overflow,
                expected_overflow,
                lhs.p,
                rhs.p,
            );
        } else if comparison_ops_range.contains(&i) {
            let index = i - comparison_ops_range.start;
            let (comparison_op_executor, clear_fn, fn_name) = &mut comparison_ops[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let res = comparison_op_executor.execute((&lhs.c, &rhs.c));
            // Determinism check
            let res_1 = comparison_op_executor.execute((&lhs.c, &rhs.c));

            let decrypt_signed_res = cks.decrypt_bool(&res);
            let expected_res = clear_fn(lhs.p, rhs.p);

            let res_ct: SignedRadixCiphertext = sks.cast_to_signed(
                res.clone().into_radix::<SignedRadixCiphertext>(1, sks),
                NB_CTXT_LONG_RUN,
            );

            datagen.put_op_result_random_side(expected_res as i64, &res_ct, fn_name, idx);

            sanity_check_op_sequence_result_bool(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res,
                expected_res,
                lhs.p,
                rhs.p,
            );
        } else if scalar_comparison_ops_range.contains(&i) {
            let index = i - scalar_comparison_ops_range.start;
            let (scalar_comparison_op_executor, clear_fn, fn_name) =
                &mut scalar_comparison_ops[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let res = scalar_comparison_op_executor.execute((&lhs.c, rhs.p));
            // Determinism check
            let res_1 = scalar_comparison_op_executor.execute((&lhs.c, rhs.p));

            let decrypt_signed_res = cks.decrypt_bool(&res);
            let expected_res = clear_fn(lhs.p, rhs.p);

            let res_ct: SignedRadixCiphertext = sks.cast_to_signed(
                res.clone().into_radix::<SignedRadixCiphertext>(1, sks),
                NB_CTXT_LONG_RUN,
            );

            //sks.cast_to_signed(res_ct, NB_CTXT_LONG_RUN);
            datagen.put_op_result_random_side(expected_res as i64, &res_ct, fn_name, idx);

            sanity_check_op_sequence_result_bool(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res,
                expected_res,
                lhs.p,
                rhs.p,
            );
        } else if select_op_range.contains(&i) {
            let index = i - select_op_range.start;
            let (select_op_executor, clear_fn, fn_name) = &mut select_op[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let clear_bool: bool = datagen.gen_bool_uniform();
            let bool_input = cks.encrypt_bool(clear_bool);

            let res = select_op_executor.execute((&bool_input, &lhs.c, &rhs.c));

            // Determinism check
            let res_1 = select_op_executor.execute((&bool_input, &lhs.c, &rhs.c));

            let decrypt_signed_res: i64 = cks.decrypt_signed(&res);
            let expected_res = clear_fn(clear_bool, lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res,
                expected_res,
                lhs.p,
                rhs.p,
            );
        } else if div_rem_op_range.contains(&i) {
            let index = i - div_rem_op_range.start;
            let (div_rem_op_executor, clear_fn, fn_name) = &mut div_rem_op[index];

            let (mut lhs, mut rhs) = datagen.gen_op_operands(idx, fn_name);

            let mut iters = 0;
            while rhs.p == 0 && iters < 10 {
                (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);
                iters += 1;
            }

            if rhs.p == 0 {
                println!("{idx}: {fn_name} execution skipped because rhs is 0.");
                continue;
            }

            let (res_q, res_r) = div_rem_op_executor.execute((&lhs.c, &rhs.c));
            // Check carries are empty and noise level is lower or equal to nominal

            // Determinism check
            let (res_q1, res_r1) = div_rem_op_executor.execute((&lhs.c, &rhs.c));

            let decrypt_signed_res_q: i64 = cks.decrypt_signed(&res_q);
            let decrypt_signed_res_r: i64 = cks.decrypt_signed(&res_r);
            let (expected_res_q, expected_res_r) = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res_q, &res_q, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res_q,
                &res_q1,
                expected_res_q,
                decrypt_signed_res_q,
                lhs.p,
                rhs.p,
            );

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res_r,
                &res_r1,
                expected_res_r,
                decrypt_signed_res_r,
                lhs.p,
                rhs.p,
            );
        } else if scalar_div_rem_op_range.contains(&i) {
            let index = i - scalar_div_rem_op_range.start;
            let (scalar_div_rem_op_executor, clear_fn, fn_name) = &mut scalar_div_rem_op[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            if rhs.p == 0 {
                continue;
            }
            let (res_q, res_r) = scalar_div_rem_op_executor.execute((&lhs.c, rhs.p));
            // Check carries are empty and noise level is lower or equal to nominal
            // Determinism check
            let (res_q1, res_r1) = scalar_div_rem_op_executor.execute((&lhs.c, rhs.p));

            let decrypt_signed_res_q: i64 = cks.decrypt_signed(&res_q);
            let decrypt_signed_res_r: i64 = cks.decrypt_signed(&res_r);
            let (expected_res_q, expected_res_r) = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res_r, &res_r, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res_q,
                &res_q1,
                decrypt_signed_res_q,
                expected_res_q,
                lhs.p,
                rhs.p,
            );

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res_r,
                &res_r1,
                decrypt_signed_res_r,
                expected_res_r,
                lhs.p,
                rhs.p,
            );
        } else if log2_ops_range.contains(&i) {
            let index = i - log2_ops_range.start;
            let (log2_executor, clear_fn, fn_name) = &mut log2_ops[index];

            let input = datagen.gen_op_single_operand(idx, fn_name);

            if input.p <= 0 {
                println!("{idx}: {fn_name} execution skipped because input is <=0.");
                continue;
            }

            let res = log2_executor.execute(&input.c);
            // Determinism check
            let res_1 = log2_executor.execute(&input.c);

            let cast_res = sks.cast_to_signed(res.clone(), NB_CTXT_LONG_RUN);
            let decrypt_signed_res: i64 = cks.decrypt_signed(&cast_res);
            let expected_res = clear_fn(input.p) as i64;

            datagen.put_op_result_random_side(expected_res, &cast_res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res as u64,
                expected_res as u64,
                input.p as u64,
                input.p as u64,
            );
        } else if rotate_shift_ops_range.contains(&i) {
            let index = i - rotate_shift_ops_range.start;
            let (rotate_shift_op_executor, clear_fn, fn_name) = &mut rotate_shift_ops[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let unsigned_right = sks.cast_to_unsigned(rhs.c.clone(), NB_CTXT_LONG_RUN);
            let res = rotate_shift_op_executor.execute((&lhs.c, &unsigned_right));

            // Determinism check
            let res_1 = rotate_shift_op_executor.execute((&lhs.c, &unsigned_right));

            let decrypt_signed_res: i64 = cks.decrypt_signed(&res);
            let expected_res: i64 = clear_fn(lhs.p, rhs.p as u64);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res,
                expected_res,
                lhs.p,
                rhs.p,
            );
        } else if scalar_rotate_shift_ops_range.contains(&i) {
            let index = i - scalar_rotate_shift_ops_range.start;
            let (scalar_rotate_shift_op_executor, clear_fn, fn_name) =
                &mut scalar_rotate_shift_ops[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let res = scalar_rotate_shift_op_executor.execute((&lhs.c, rhs.p as u64));
            // Determinism check
            let res_1 = scalar_rotate_shift_op_executor.execute((&lhs.c, rhs.p as u64));

            let decrypt_signed_res: i64 = cks.decrypt_signed(&res);
            let expected_res: i64 = clear_fn(lhs.p, rhs.p as u64);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypt_signed_res,
                expected_res,
                lhs.p,
                rhs.p,
            );
        } else if signed_oprf_ops_range.contains(&i) {
            let index = i - signed_oprf_ops_range.start;
            let (op_executor, fn_name) = &mut signed_oprf_ops[index];

            let seed = datagen.gen_seed();
            let num_blocks = NB_CTXT_LONG_RUN as u64;

            println!(
                "{idx}: Start {fn_name} with seed={:?}, num_blocks={num_blocks}",
                seed.0
            );

            let res = op_executor.execute((seed, num_blocks));
            let res_1 = op_executor.execute((seed, num_blocks));

            let decrypted_res: i64 = cks.decrypt_signed(&res);

            let bits_per_block = sks.message_modulus().0.ilog2();
            let total_bits = num_blocks * bits_per_block as u64;
            let upper_bound = 1i128 << (total_bits - 1);
            let lower_bound = -upper_bound;
            assert!((decrypted_res as i128) < upper_bound);
            assert!((decrypted_res as i128) >= lower_bound);

            datagen.put_op_result_random_side(decrypted_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
                decrypted_res,
                0,
                0,
            );
        } else if signed_oprf_bounded_ops_range.contains(&i) {
            let index = i - signed_oprf_bounded_ops_range.start;
            let (op_executor, fn_name) = &mut signed_oprf_bounded_ops[index];

            let seed = datagen.gen_seed();
            let num_blocks = NB_CTXT_LONG_RUN as u64;
            let bits_per_block = sks.message_modulus().0.ilog2();
            let max_bits = num_blocks * bits_per_block as u64 - 1;
            let random_bits_count = datagen.gen_random_bits_count(max_bits);

            println!(
                "{idx}: Start {fn_name} with seed={:?}, bits={random_bits_count}, num_blocks={num_blocks}",
                seed.0
            );

            let res = op_executor.execute((seed, random_bits_count, num_blocks));
            let res_1 = op_executor.execute((seed, random_bits_count, num_blocks));

            let decrypted_res: i64 = cks.decrypt_signed(&res);

            let upper_bound = 1i64 << random_bits_count;
            assert!(decrypted_res >= 0);
            assert!(decrypted_res < upper_bound);

            datagen.put_op_result_random_side(decrypted_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_i64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
                decrypted_res,
                0,
                0,
            );
        }
    }
}
