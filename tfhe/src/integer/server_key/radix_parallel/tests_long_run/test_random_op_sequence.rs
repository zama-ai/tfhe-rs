use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_long_run::{
    get_long_test_iterations, get_user_defined_seed, sanity_check_op_sequence_result_bool,
    sanity_check_op_sequence_result_u64, OpSequenceFunctionExecutor, RandomOpSequenceDataGenerator,
    NB_CTXT_LONG_RUN,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::OpSequenceCpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::*;
use crate::{ClientKey, CompressedServerKey, Seed, Tag};
use std::cmp::{max, min};
use std::sync::Arc;

create_parameterized_test!(random_op_sequence {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_parameterized_test!(random_op_sequence_data_generator {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

pub(crate) type BinaryOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        RadixCiphertext,
    >,
>;
pub(crate) type UnaryOpExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<&'a RadixCiphertext, RadixCiphertext>>;

pub(crate) type ScalarBinaryOpExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>>;
pub(crate) type OverflowingOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
>;
pub(crate) type ScalarOverflowingOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a RadixCiphertext, u64),
        (RadixCiphertext, BooleanBlock),
    >,
>;
pub(crate) type ComparisonOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        BooleanBlock,
    >,
>;
pub(crate) type ScalarComparisonOpExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<(&'a RadixCiphertext, u64), BooleanBlock>>;
pub(crate) type SelectOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a BooleanBlock, &'a RadixCiphertext, &'a RadixCiphertext),
        RadixCiphertext,
    >,
>;
pub(crate) type DivRemOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, RadixCiphertext),
    >,
>;
pub(crate) type ScalarDivRemOpExecutor = Box<
    dyn for<'a> OpSequenceFunctionExecutor<
        (&'a RadixCiphertext, u64),
        (RadixCiphertext, RadixCiphertext),
    >,
>;
pub(crate) type Log2OpExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<&'a RadixCiphertext, RadixCiphertext>>;

pub(crate) type OprfExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<(Seed, u64), RadixCiphertext>>;

pub(crate) type OprfBoundedExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<(Seed, u64, u64), RadixCiphertext>>;

pub(crate) type OprfCustomRangeExecutor =
    Box<dyn for<'a> OpSequenceFunctionExecutor<(Seed, u64, u64, u64), RadixCiphertext>>;

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
    let rotate_left_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::rotate_left_parallelized);
    let left_shift_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::left_shift_parallelized);
    let rotate_right_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::rotate_right_parallelized);
    let right_shift_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::right_shift_parallelized);
    let max_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::max_parallelized);
    let min_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::min_parallelized);

    // Binary Ops Clear functions
    let clear_add = |x: u64, y: u64| x.wrapping_add(y);
    let clear_sub = |x: u64, y: u64| x.wrapping_sub(y);
    let clear_bitwise_and = |x, y| x & y;
    let clear_bitwise_or = |x, y| x | y;
    let clear_bitwise_xor = |x, y| x ^ y;
    let clear_mul = |x: u64, y: u64| x.wrapping_mul(y);
    // Warning this rotate definition only works with 64-bit ciphertexts
    let clear_rotate_left = |x: u64, y: u64| x.rotate_left(y as u32);
    let clear_left_shift = |x, y| x << y;
    // Warning this rotate definition only works with 64-bit ciphertexts
    let clear_rotate_right = |x: u64, y: u64| x.rotate_right(y as u32);
    let clear_right_shift = |x, y| x >> y;
    let clear_max = |x: u64, y: u64| max(x, y);
    let clear_min = |x: u64, y: u64| min(x, y);

    #[allow(clippy::type_complexity)]
    let mut binary_ops: Vec<(BinaryOpExecutor, &dyn Fn(u64, u64) -> u64, String)> = vec![
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
        (Box::new(max_executor), &clear_max, "max".to_string()),
        (Box::new(min_executor), &clear_min, "min".to_string()),
    ];

    // Unary Ops Executors
    let neg_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::neg_parallelized);
    let bitnot_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::bitnot);
    let reverse_bits_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::reverse_bits_parallelized);
    // Unary Ops Clear functions
    let clear_neg = |x: u64| x.wrapping_neg();
    let clear_bitnot = |x: u64| !x;
    let clear_reverse_bits = |x: u64| x.reverse_bits();
    #[allow(clippy::type_complexity)]
    let mut unary_ops: Vec<(UnaryOpExecutor, &dyn Fn(u64) -> u64, String)> = vec![
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
    let scalar_rotate_left_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_rotate_left_parallelized);
    let scalar_left_shift_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_left_shift_parallelized);
    let scalar_rotate_right_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_rotate_right_parallelized);
    let scalar_right_shift_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_right_shift_parallelized);

    #[allow(clippy::type_complexity)]
    let mut scalar_binary_ops: Vec<(ScalarBinaryOpExecutor, &dyn Fn(u64, u64) -> u64, String)> = vec![
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
        OpSequenceCpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_add_parallelized);
    let overflowing_sub_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_sub_parallelized);
    let overflowing_mul_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_mul_parallelized);

    // Overflowing Ops Clear functions
    let clear_overflowing_add = |x: u64, y: u64| -> (u64, bool) { x.overflowing_add(y) };
    let clear_overflowing_sub = |x: u64, y: u64| -> (u64, bool) { x.overflowing_sub(y) };
    let clear_overflowing_mul = |x: u64, y: u64| -> (u64, bool) { x.overflowing_mul(y) };

    #[allow(clippy::type_complexity)]
    let mut overflowing_ops: Vec<(
        OverflowingOpExecutor,
        &dyn Fn(u64, u64) -> (u64, bool),
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
    let overflowing_scalar_add_executor = OpSequenceCpuFunctionExecutor::new(
        &ServerKey::unsigned_overflowing_scalar_add_parallelized,
    );
    let overflowing_scalar_sub_executor = OpSequenceCpuFunctionExecutor::new(
        &ServerKey::unsigned_overflowing_scalar_sub_parallelized,
    );

    #[allow(clippy::type_complexity)]
    let mut scalar_overflowing_ops: Vec<(
        ScalarOverflowingOpExecutor,
        &dyn Fn(u64, u64) -> (u64, bool),
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
    let clear_gt = |x: u64, y: u64| -> bool { x > y };
    let clear_ge = |x: u64, y: u64| -> bool { x >= y };
    let clear_lt = |x: u64, y: u64| -> bool { x < y };
    let clear_le = |x: u64, y: u64| -> bool { x <= y };
    let clear_eq = |x: u64, y: u64| -> bool { x == y };
    let clear_ne = |x: u64, y: u64| -> bool { x != y };

    #[allow(clippy::type_complexity)]
    let mut comparison_ops: Vec<(ComparisonOpExecutor, &dyn Fn(u64, u64) -> bool, String)> = vec![
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
        ScalarComparisonOpExecutor,
        &dyn Fn(u64, u64) -> bool,
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
    let clear_select = |b: bool, x: u64, y: u64| if b { x } else { y };

    #[allow(clippy::type_complexity)]
    let mut select_op: Vec<(SelectOpExecutor, &dyn Fn(bool, u64, u64) -> u64, String)> = vec![(
        Box::new(select_executor),
        &clear_select,
        "select".to_string(),
    )];

    // Div executor
    let div_rem_executor = OpSequenceCpuFunctionExecutor::new(&ServerKey::div_rem_parallelized);
    // Div Rem Clear functions
    let clear_div_rem = |x: u64, y: u64| -> (u64, u64) { (x.wrapping_div(y), x.wrapping_rem(y)) };
    #[allow(clippy::type_complexity)]
    let mut div_rem_op: Vec<(DivRemOpExecutor, &dyn Fn(u64, u64) -> (u64, u64), String)> = vec![(
        Box::new(div_rem_executor),
        &clear_div_rem,
        "div rem".to_string(),
    )];

    // Scalar Div executor
    let scalar_div_rem_executor =
        OpSequenceCpuFunctionExecutor::new(&ServerKey::scalar_div_rem_parallelized);
    #[allow(clippy::type_complexity)]
    let mut scalar_div_rem_op: Vec<(
        ScalarDivRemOpExecutor,
        &dyn Fn(u64, u64) -> (u64, u64),
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
    let clear_ilog2 = |x: u64| x.ilog2() as u64;
    let clear_count_zeros = |x: u64| x.count_zeros() as u64;
    let clear_count_ones = |x: u64| x.count_ones() as u64;

    #[allow(clippy::type_complexity)]
    let mut log2_ops: Vec<(Log2OpExecutor, &dyn Fn(u64) -> u64, String)> = vec![
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

    // OPRF Executors
    let oprf_executor = OpSequenceCpuFunctionExecutor::new(
        &ServerKey::par_generate_oblivious_pseudo_random_unsigned_integer,
    );
    let oprf_bounded_executor = OpSequenceCpuFunctionExecutor::new(
        &ServerKey::par_generate_oblivious_pseudo_random_unsigned_integer_bounded,
    );
    let oprf_custom_range_executor = OpSequenceCpuFunctionExecutor::new(
        &ServerKey::par_generate_oblivious_pseudo_random_unsigned_custom_range,
    );

    let mut oprf_ops: Vec<(OprfExecutor, String)> = vec![(
        Box::new(oprf_executor),
        "par_generate_oblivious_pseudo_random_unsigned_integer".to_string(),
    )];

    let mut oprf_bounded_ops: Vec<(OprfBoundedExecutor, String)> = vec![(
        Box::new(oprf_bounded_executor),
        "par_generate_oblivious_pseudo_random_unsigned_integer_bounded".to_string(),
    )];

    let mut oprf_custom_range_ops: Vec<(OprfCustomRangeExecutor, String)> = vec![(
        Box::new(oprf_custom_range_executor),
        "par_generate_oblivious_pseudo_random_unsigned_custom_range".to_string(),
    )];

    let (cks, sks, mut datagen) = random_op_sequence_test_init_cpu(
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
        &mut oprf_ops,
        &mut oprf_bounded_ops,
        &mut oprf_custom_range_ops,
    );

    random_op_sequence_test(
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
        &mut oprf_ops,
        &mut oprf_bounded_ops,
        &mut oprf_custom_range_ops,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn random_op_sequence_test_init_cpu<P>(
    param: P,
    binary_ops: &mut [(BinaryOpExecutor, impl Fn(u64, u64) -> u64, String)],
    unary_ops: &mut [(UnaryOpExecutor, impl Fn(u64) -> u64, String)],
    scalar_binary_ops: &mut [(ScalarBinaryOpExecutor, impl Fn(u64, u64) -> u64, String)],
    overflowing_ops: &mut [(
        OverflowingOpExecutor,
        impl Fn(u64, u64) -> (u64, bool),
        String,
    )],
    scalar_overflowing_ops: &mut [(
        ScalarOverflowingOpExecutor,
        impl Fn(u64, u64) -> (u64, bool),
        String,
    )],
    comparison_ops: &mut [(ComparisonOpExecutor, impl Fn(u64, u64) -> bool, String)],
    scalar_comparison_ops: &mut [(
        ScalarComparisonOpExecutor,
        impl Fn(u64, u64) -> bool,
        String,
    )],
    select_op: &mut [(SelectOpExecutor, impl Fn(bool, u64, u64) -> u64, String)],
    div_rem_op: &mut [(DivRemOpExecutor, impl Fn(u64, u64) -> (u64, u64), String)],
    scalar_div_rem_op: &mut [(
        ScalarDivRemOpExecutor,
        impl Fn(u64, u64) -> (u64, u64),
        String,
    )],
    log2_ops: &mut [(Log2OpExecutor, impl Fn(u64) -> u64, String)],
    oprf_ops: &mut [(OprfExecutor, String)],
    oprf_bounded_ops: &mut [(OprfBoundedExecutor, String)],
    oprf_custom_range_ops: &mut [(OprfCustomRangeExecutor, String)],
) -> (
    RadixClientKey,
    Arc<ServerKey>,
    RandomOpSequenceDataGenerator<u64, RadixCiphertext>,
)
where
    P: Into<TestParameters>,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let temp_cks =
        ClientKey::from_raw_parts(cks.clone(), None, None, None, None, None, Tag::default());
    let comp_sks = CompressedServerKey::new(&temp_cks);

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
        + oprf_ops.len()
        + oprf_bounded_ops.len()
        + oprf_custom_range_ops.len();
    println!("Total num ops {total_num_ops}");

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT_LONG_RUN));

    let mut datagen = get_user_defined_seed().map_or_else(
        || RandomOpSequenceDataGenerator::<u64, RadixCiphertext>::new(total_num_ops, &cks),
        |seed| {
            RandomOpSequenceDataGenerator::<u64, RadixCiphertext>::new_with_seed(
                total_num_ops,
                seed,
                &cks,
            )
        },
    );
    println!("random_op_sequence_test::seed = {}", datagen.get_seed().0);

    println!("Setting up operations");

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
    for x in oprf_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in oprf_bounded_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }
    for x in oprf_custom_range_ops.iter_mut() {
        x.0.setup(&cks, &comp_sks, &mut datagen.deterministic_seeder);
    }

    (cks, sks, datagen)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn random_op_sequence_test(
    datagen: &mut RandomOpSequenceDataGenerator<u64, RadixCiphertext>,
    cks: &RadixClientKey,
    sks: &Arc<ServerKey>,
    binary_ops: &mut [(BinaryOpExecutor, impl Fn(u64, u64) -> u64, String)],
    unary_ops: &mut [(UnaryOpExecutor, impl Fn(u64) -> u64, String)],
    scalar_binary_ops: &mut [(ScalarBinaryOpExecutor, impl Fn(u64, u64) -> u64, String)],
    overflowing_ops: &mut [(
        OverflowingOpExecutor,
        impl Fn(u64, u64) -> (u64, bool),
        String,
    )],
    scalar_overflowing_ops: &mut [(
        ScalarOverflowingOpExecutor,
        impl Fn(u64, u64) -> (u64, bool),
        String,
    )],
    comparison_ops: &mut [(ComparisonOpExecutor, impl Fn(u64, u64) -> bool, String)],
    scalar_comparison_ops: &mut [(
        ScalarComparisonOpExecutor,
        impl Fn(u64, u64) -> bool,
        String,
    )],
    select_op: &mut [(SelectOpExecutor, impl Fn(bool, u64, u64) -> u64, String)],
    div_rem_op: &mut [(DivRemOpExecutor, impl Fn(u64, u64) -> (u64, u64), String)],
    scalar_div_rem_op: &mut [(
        ScalarDivRemOpExecutor,
        impl Fn(u64, u64) -> (u64, u64),
        String,
    )],
    log2_ops: &mut [(Log2OpExecutor, impl Fn(u64) -> u64, String)],
    oprf_ops: &mut [(OprfExecutor, String)],
    oprf_bounded_ops: &mut [(OprfBoundedExecutor, String)],
    oprf_custom_range_ops: &mut [(OprfCustomRangeExecutor, String)],
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
    let oprf_ops_range = log2_ops_range.end..log2_ops_range.end + oprf_ops.len();
    let oprf_bounded_ops_range = oprf_ops_range.end..oprf_ops_range.end + oprf_bounded_ops.len();
    let oprf_custom_range_ops_range =
        oprf_bounded_ops_range.end..oprf_bounded_ops_range.end + oprf_custom_range_ops.len();

    for fn_index in 0..get_long_test_iterations() {
        let (i, idx) = datagen.gen_op_index();

        if binary_ops_range.contains(&i) {
            let index = i - binary_ops_range.start;
            let (binary_op_executor, clear_fn, fn_name) = &mut binary_ops[index];
            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let res = binary_op_executor.execute((&lhs.c, &rhs.c));
            // Determinism check
            let res_1 = binary_op_executor.execute((&lhs.c, &rhs.c));
            let decrypted_res: u64 = cks.decrypt(&res);
            let expected_res: u64 = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
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

            let decrypted_res: u64 = cks.decrypt(&res);
            let expected_res: u64 = clear_fn(operand.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
                expected_res,
                operand.p,
                operand.p,
            );
        } else if scalar_binary_ops_range.contains(&i) {
            let index = i - scalar_binary_ops_range.start;
            let (scalar_binary_op_executor, clear_fn, fn_name) = &mut scalar_binary_ops[index];
            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let res = scalar_binary_op_executor.execute((&lhs.c, rhs.p));
            let res_1 = scalar_binary_op_executor.execute((&lhs.c, rhs.p));

            let decrypted_res: u64 = cks.decrypt(&res);
            let expected_res: u64 = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
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

            let decrypted_res: u64 = cks.decrypt(&res);
            let decrypted_overflow = cks.decrypt_bool(&overflow);
            let (expected_res, expected_overflow) = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
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
                decrypted_overflow,
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

            // Determinism check
            let (res_1, overflow_1) = scalar_overflowing_op_executor.execute((&lhs.c, rhs.p));

            let decrypted_res: u64 = cks.decrypt(&res);
            let decrypted_overflow = cks.decrypt_bool(&overflow);
            let (expected_res, expected_overflow) = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
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
                decrypted_overflow,
                expected_overflow,
                lhs.p,
                rhs.p,
            );
        } else if comparison_ops_range.contains(&i) {
            let index = i - comparison_ops_range.start;
            let (comparison_op_executor, clear_fn, fn_name) = &mut comparison_ops[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let res = comparison_op_executor.execute((&lhs.c, &rhs.c));
            let res_1 = comparison_op_executor.execute((&lhs.c, &rhs.c));
            let decrypted_res = cks.decrypt_bool(&res);
            let expected_res = clear_fn(lhs.p, rhs.p);

            let res_ct = sks.cast_to_unsigned(
                res.clone().into_radix::<RadixCiphertext>(1, sks),
                NB_CTXT_LONG_RUN,
            );
            datagen.put_op_result_random_side(expected_res as u64, &res_ct, fn_name, idx);

            sanity_check_op_sequence_result_bool(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
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

            let decrypted_res = cks.decrypt_bool(&res);
            let expected_res = clear_fn(lhs.p, rhs.p);

            let res_ct: RadixCiphertext = sks.cast_to_unsigned(
                res.clone().into_radix::<RadixCiphertext>(1, sks),
                NB_CTXT_LONG_RUN,
            );
            datagen.put_op_result_random_side(expected_res as u64, &res_ct, fn_name, idx);

            sanity_check_op_sequence_result_bool(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
                expected_res,
                lhs.p,
                rhs.p,
            );
        } else if select_op_range.contains(&i) {
            let index = i - select_op_range.start;
            let (select_op_executor, clear_fn, fn_name) = &mut select_op[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            let (clear_bool, bool_input) = datagen.gen_encrypted_bool();

            let res = select_op_executor.execute((&bool_input, &lhs.c, &rhs.c));
            // Determinism check
            let res_1 = select_op_executor.execute((&bool_input, &lhs.c, &rhs.c));

            let decrypted_res: u64 = cks.decrypt(&res);
            let expected_res = clear_fn(clear_bool, lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
                expected_res,
                lhs.p,
                rhs.p,
            );
        } else if div_rem_op_range.contains(&i) {
            let index = i - div_rem_op_range.start;
            let (div_rem_op_executor, clear_fn, fn_name) = &mut div_rem_op[index];

            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            if rhs.p == 0 {
                println!("{idx}: {fn_name} execution skipped because scalar is 0.");
                continue;
            }
            let (res_q, res_r) = div_rem_op_executor.execute((&lhs.c, &rhs.c));
            // Check carries are empty and noise level is lower or equal to nominal

            // Determinism check
            let (res_q1, res_r1) = div_rem_op_executor.execute((&lhs.c, &rhs.c));

            let decrypted_res_q: u64 = cks.decrypt(&res_q);
            let decrypted_res_r: u64 = cks.decrypt(&res_r);
            let (expected_res_q, expected_res_r) = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res_q, &res_q, fn_name, idx);

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res_r,
                &res_r1,
                decrypted_res_r,
                expected_res_r,
                lhs.p,
                rhs.p,
            );

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res_q,
                &res_q1,
                decrypted_res_q,
                expected_res_q,
                lhs.p,
                rhs.p,
            );
        } else if scalar_div_rem_op_range.contains(&i) {
            let index = i - scalar_div_rem_op_range.start;
            let (scalar_div_rem_op_executor, clear_fn, fn_name) = &mut scalar_div_rem_op[index];
            let (lhs, rhs) = datagen.gen_op_operands(idx, fn_name);

            if rhs.p == 0 {
                println!("{idx}: {fn_name} execution skipped because scalar is 0.");
                continue;
            }
            let (res_q, res_r) = scalar_div_rem_op_executor.execute((&lhs.c, rhs.p));
            // Check carries are empty and noise level is lower or equal to nominal

            // Determinism check
            let (res_q1, res_r1) = scalar_div_rem_op_executor.execute((&lhs.c, rhs.p));

            let decrypted_res_q: u64 = cks.decrypt(&res_q);
            let decrypted_res_r: u64 = cks.decrypt(&res_r);
            let (expected_res_q, expected_res_r) = clear_fn(lhs.p, rhs.p);

            datagen.put_op_result_random_side(expected_res_r, &res_r, fn_name, idx);

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res_r,
                &res_r1,
                decrypted_res_r,
                expected_res_r,
                lhs.p,
                rhs.p,
            );

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res_q,
                &res_q1,
                decrypted_res_q,
                expected_res_q,
                lhs.p,
                rhs.p,
            );
        } else if log2_ops_range.contains(&i) {
            let index = i - log2_ops_range.start;
            let (log2_executor, clear_fn, fn_name) = &mut log2_ops[index];

            let mut operand = datagen.gen_op_single_operand(idx, fn_name);

            let mut iters = 0;
            while operand.p == 0 && iters < 10 {
                operand = datagen.gen_op_single_operand(idx, fn_name);
                iters += 1;
            }

            if operand.p == 0 {
                println!("{idx}: {fn_name} execution skipped because input is 0.");
                continue;
            }

            let res = log2_executor.execute(&operand.c);
            // Determinism check
            let res_1 = log2_executor.execute(&operand.c);

            let cast_res = sks.cast_to_unsigned(res.clone(), NB_CTXT_LONG_RUN);
            let decrypted_res: u64 = cks.decrypt(&cast_res);
            let expected_res = clear_fn(operand.p);

            datagen.put_op_result_random_side(expected_res, &cast_res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
                idx,
                fn_name,
                fn_index,
                &res,
                &res_1,
                decrypted_res,
                expected_res,
                operand.p,
                operand.p,
            );
        } else if oprf_ops_range.contains(&i) {
            let index = i - oprf_ops_range.start;
            let (op_executor, fn_name) = &mut oprf_ops[index];
            let seed = datagen.gen_seed();
            let num_blocks = NB_CTXT_LONG_RUN as u64;

            println!(
                "{idx}: Start {fn_name} with seed={:?}, num_blocks={num_blocks}",
                seed.0
            );

            let res = op_executor.execute((seed, num_blocks));
            let res_1 = op_executor.execute((seed, num_blocks));

            let decrypted_res: u64 = cks.decrypt(&res);

            let bits_per_block = sks.message_modulus().0.ilog2();
            let total_bits = num_blocks * bits_per_block as u64;
            let upper_bound = 1u128 << total_bits;
            assert!((decrypted_res as u128) < upper_bound);

            datagen.put_op_result_random_side(decrypted_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
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
        } else if oprf_bounded_ops_range.contains(&i) {
            let index = i - oprf_bounded_ops_range.start;
            let (op_executor, fn_name) = &mut oprf_bounded_ops[index];
            let seed = datagen.gen_seed();
            let num_blocks = NB_CTXT_LONG_RUN as u64;
            let bits_per_block = sks.message_modulus().0.ilog2();
            let max_bits = num_blocks * bits_per_block as u64;
            let random_bits_count = datagen.gen_random_bits_count(max_bits);

            println!(
                "{idx}: Start {fn_name} with seed={:?}, bits={random_bits_count}, num_blocks={num_blocks}",
                seed.0
            );

            let res = op_executor.execute((seed, random_bits_count, num_blocks));
            let res_1 = op_executor.execute((seed, random_bits_count, num_blocks));

            let decrypted_res: u64 = cks.decrypt(&res);

            let upper_bound = 1u64 << random_bits_count;
            assert!(decrypted_res < upper_bound);

            datagen.put_op_result_random_side(decrypted_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
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
        } else if oprf_custom_range_ops_range.contains(&i) {
            let index = i - oprf_custom_range_ops_range.start;
            let (op_executor, fn_name) = &mut oprf_custom_range_ops[index];
            let seed = datagen.gen_seed();
            let num_blocks_output = NB_CTXT_LONG_RUN as u64;
            let excluded_upper_bound = datagen.gen_excluded_upper_bound();
            let bits_per_block = sks.message_modulus().0.ilog2();
            let max_bits = num_blocks_output * bits_per_block as u64;
            let num_input_random_bits = datagen.gen_random_bits_count(max_bits);

            println!(
                "{idx}: Start {fn_name} with seed={:?}, input_bits={num_input_random_bits}, bound={excluded_upper_bound}",
                seed.0
            );

            let res = op_executor.execute((
                seed,
                num_input_random_bits,
                excluded_upper_bound,
                num_blocks_output,
            ));
            let res_1 = op_executor.execute((
                seed,
                num_input_random_bits,
                excluded_upper_bound,
                num_blocks_output,
            ));

            let decrypted_res: u64 = cks.decrypt(&res);

            assert!(decrypted_res < excluded_upper_bound);

            datagen.put_op_result_random_side(decrypted_res, &res, fn_name, idx);

            sanity_check_op_sequence_result_u64(
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

pub(crate) fn random_op_sequence_data_generator<P>(param: P)
where
    P: Into<TestParameters> + Clone,
{
    let param = param.into();
    let (cks, _sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT_LONG_RUN));

    let datagen = RandomOpSequenceDataGenerator::<u64, RadixCiphertext>::new(1000, &cks);

    let datagen2 = RandomOpSequenceDataGenerator::<u64, RadixCiphertext>::new_with_seed(
        1000,
        datagen.get_seed(),
        &cks,
    );

    for (v1, v2) in datagen.lhs.iter().zip(datagen2.lhs.iter()) {
        assert_eq!(v1.p, v2.p);
    }

    for (v1, v2) in datagen.rhs.iter().zip(datagen2.rhs.iter()) {
        assert_eq!(v1.p, v2.p);
    }

    let datagen = RandomOpSequenceDataGenerator::<u64, RadixCiphertext>::new(1000, &cks);

    for (v1, v2) in datagen.lhs.iter().zip(datagen2.lhs.iter()) {
        assert_ne!(v1.p, v2.p);
    }

    for (v1, v2) in datagen.rhs.iter().zip(datagen2.rhs.iter()) {
        assert_ne!(v1.p, v2.p);
    }
}
