use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_long_run::{
    NB_CTXT_LONG_RUN, NB_TESTS_LONG_RUN,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::*;
use rand::Rng;
use std::cmp::{max, min};
use std::sync::Arc;

create_parameterized_test!(random_op_sequence {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

pub(crate) type BinaryOpExecutor =
    Box<dyn for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>>;
pub(crate) type UnaryOpExecutor =
    Box<dyn for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>>;

pub(crate) type ScalarBinaryOpExecutor =
    Box<dyn for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>>;
pub(crate) type OverflowingOpExecutor = Box<
    dyn for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
>;
pub(crate) type ScalarOverflowingOpExecutor =
    Box<dyn for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), (RadixCiphertext, BooleanBlock)>>;
pub(crate) type ComparisonOpExecutor =
    Box<dyn for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>>;
pub(crate) type ScalarComparisonOpExecutor =
    Box<dyn for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), BooleanBlock>>;
pub(crate) type SelectOpExecutor = Box<
    dyn for<'a> FunctionExecutor<
        (&'a BooleanBlock, &'a RadixCiphertext, &'a RadixCiphertext),
        RadixCiphertext,
    >,
>;
pub(crate) type DivRemOpExecutor = Box<
    dyn for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, RadixCiphertext),
    >,
>;
pub(crate) type ScalarDivRemOpExecutor = Box<
    dyn for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), (RadixCiphertext, RadixCiphertext)>,
>;
pub(crate) type Log2OpExecutor =
    Box<dyn for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>>;
fn random_op_sequence<P>(param: P)
where
    P: Into<TestParameters> + Clone,
{
    // Binary Ops Executors
    let add_executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    let sub_executor = CpuFunctionExecutor::new(&ServerKey::sub_parallelized);
    let bitwise_and_executor = CpuFunctionExecutor::new(&ServerKey::bitand_parallelized);
    let bitwise_or_executor = CpuFunctionExecutor::new(&ServerKey::bitor_parallelized);
    let bitwise_xor_executor = CpuFunctionExecutor::new(&ServerKey::bitxor_parallelized);
    let mul_executor = CpuFunctionExecutor::new(&ServerKey::mul_parallelized);
    let rotate_left_executor = CpuFunctionExecutor::new(&ServerKey::rotate_left_parallelized);
    let left_shift_executor = CpuFunctionExecutor::new(&ServerKey::left_shift_parallelized);
    let rotate_right_executor = CpuFunctionExecutor::new(&ServerKey::rotate_right_parallelized);
    let right_shift_executor = CpuFunctionExecutor::new(&ServerKey::right_shift_parallelized);
    let max_executor = CpuFunctionExecutor::new(&ServerKey::max_parallelized);
    let min_executor = CpuFunctionExecutor::new(&ServerKey::min_parallelized);

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
    let neg_executor = CpuFunctionExecutor::new(&ServerKey::neg_parallelized);
    let bitnot_executor = CpuFunctionExecutor::new(&ServerKey::bitnot);
    let reverse_bits_executor = CpuFunctionExecutor::new(&ServerKey::reverse_bits_parallelized);
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
    let scalar_add_executor = CpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized);
    let scalar_sub_executor = CpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized);
    let scalar_bitwise_and_executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_bitand_parallelized);
    let scalar_bitwise_or_executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_bitor_parallelized);
    let scalar_bitwise_xor_executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_bitxor_parallelized);
    let scalar_mul_executor = CpuFunctionExecutor::new(&ServerKey::scalar_mul_parallelized);
    let scalar_rotate_left_executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_rotate_left_parallelized);
    let scalar_left_shift_executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_left_shift_parallelized);
    let scalar_rotate_right_executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_rotate_right_parallelized);
    let scalar_right_shift_executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_right_shift_parallelized);

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
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_add_parallelized);
    let overflowing_sub_executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_sub_parallelized);
    let overflowing_mul_executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_mul_parallelized);

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
    let overflowing_scalar_add_executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_add_parallelized);
    let overflowing_scalar_sub_executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_sub_parallelized);

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
    let gt_executor = CpuFunctionExecutor::new(&ServerKey::gt_parallelized);
    let ge_executor = CpuFunctionExecutor::new(&ServerKey::ge_parallelized);
    let lt_executor = CpuFunctionExecutor::new(&ServerKey::lt_parallelized);
    let le_executor = CpuFunctionExecutor::new(&ServerKey::le_parallelized);
    let eq_executor = CpuFunctionExecutor::new(&ServerKey::eq_parallelized);
    let ne_executor = CpuFunctionExecutor::new(&ServerKey::ne_parallelized);

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
    let scalar_gt_executor = CpuFunctionExecutor::new(&ServerKey::scalar_gt_parallelized);
    let scalar_ge_executor = CpuFunctionExecutor::new(&ServerKey::scalar_ge_parallelized);
    let scalar_lt_executor = CpuFunctionExecutor::new(&ServerKey::scalar_lt_parallelized);
    let scalar_le_executor = CpuFunctionExecutor::new(&ServerKey::scalar_le_parallelized);
    let scalar_eq_executor = CpuFunctionExecutor::new(&ServerKey::scalar_eq_parallelized);
    let scalar_ne_executor = CpuFunctionExecutor::new(&ServerKey::scalar_ne_parallelized);

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
    let select_executor = CpuFunctionExecutor::new(&ServerKey::cmux_parallelized);

    // Select
    let clear_select = |b: bool, x: u64, y: u64| if b { x } else { y };

    #[allow(clippy::type_complexity)]
    let mut select_op: Vec<(SelectOpExecutor, &dyn Fn(bool, u64, u64) -> u64, String)> = vec![(
        Box::new(select_executor),
        &clear_select,
        "select".to_string(),
    )];

    // Div executor
    let div_rem_executor = CpuFunctionExecutor::new(&ServerKey::div_rem_parallelized);
    // Div Rem Clear functions
    let clear_div_rem = |x: u64, y: u64| -> (u64, u64) { (x.wrapping_div(y), x.wrapping_rem(y)) };
    #[allow(clippy::type_complexity)]
    let mut div_rem_op: Vec<(DivRemOpExecutor, &dyn Fn(u64, u64) -> (u64, u64), String)> = vec![(
        Box::new(div_rem_executor),
        &clear_div_rem,
        "div rem".to_string(),
    )];

    // Scalar Div executor
    let scalar_div_rem_executor = CpuFunctionExecutor::new(&ServerKey::scalar_div_rem_parallelized);
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
    let ilog2_executor = CpuFunctionExecutor::new(&ServerKey::ilog2_parallelized);
    let count_zeros_executor = CpuFunctionExecutor::new(&ServerKey::count_zeros_parallelized);
    let count_ones_executor = CpuFunctionExecutor::new(&ServerKey::count_ones_parallelized);
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

    random_op_sequence_test(
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
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn random_op_sequence_test<P>(
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
) where
    P: Into<TestParameters>,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT_LONG_RUN));

    let mut rng = rand::thread_rng();

    for x in binary_ops.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
    for x in unary_ops.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
    for x in scalar_binary_ops.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
    for x in overflowing_ops.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
    for x in scalar_overflowing_ops.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
    for x in comparison_ops.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
    for x in scalar_comparison_ops.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
    for x in select_op.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
    for x in div_rem_op.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
    for x in scalar_div_rem_op.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
    for x in log2_ops.iter_mut() {
        x.0.setup(&cks, sks.clone());
    }
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
        + log2_ops.len();
    println!("Total num ops {total_num_ops}");

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

    let mut clear_left_vec: Vec<u64> = (0..total_num_ops)
        .map(|_| rng.gen()) // Generate random u64 values
        .collect();
    let mut clear_right_vec: Vec<u64> = (0..total_num_ops)
        .map(|_| rng.gen()) // Generate random u64 values
        .collect();
    let mut left_vec: Vec<RadixCiphertext> = clear_left_vec
        .iter()
        .map(|&m| cks.encrypt(m)) // Generate random u64 values
        .collect();
    let mut right_vec: Vec<RadixCiphertext> = clear_right_vec
        .iter()
        .map(|&m| cks.encrypt(m)) // Generate random u64 values
        .collect();
    for fn_index in 0..NB_TESTS_LONG_RUN {
        let i = rng.gen_range(0..total_num_ops);
        let j = rng.gen_range(0..total_num_ops);

        if binary_ops_range.contains(&i) {
            let index = i - binary_ops_range.start;
            let (binary_op_executor, clear_fn, fn_name) = &mut binary_ops[index];
            println!("Execute {fn_name}");

            let clear_left = clear_left_vec[i];
            let clear_right = clear_right_vec[i];

            let res = binary_op_executor.execute((&left_vec[i], &right_vec[i]));
            // Check carries are empty and noise level is nominal
            assert!(
                res.block_carries_are_empty(),
                "Non empty carries on op {fn_name}"
            );
            res.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            // Determinism check
            let res_1 = binary_op_executor.execute((&left_vec[i], &right_vec[i]));
            assert_eq!(
                res, res_1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
            let input_degrees_left: Vec<u64> =
                left_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let input_degrees_right: Vec<u64> =
                right_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let decrypted_res: u64 = cks.decrypt(&res);
            let expected_res: u64 = clear_fn(clear_left, clear_right);

            if i % 2 == 0 {
                left_vec[j] = res.clone();
                clear_left_vec[j] = expected_res;
            } else {
                right_vec[j] = res.clone();
                clear_right_vec[j] = expected_res;
            }

            // Correctness check
            assert_eq!(
                decrypted_res, expected_res,
                "Invalid result on binary op {fn_name} with clear inputs {clear_left} and {clear_right} at iteration {fn_index}. \
                with input degrees {input_degrees_left:?} and {input_degrees_right:?}",
            );
        } else if unary_ops_range.contains(&i) {
            let index = i - unary_ops_range.start;
            let (unary_op_executor, clear_fn, fn_name) = &mut unary_ops[index];
            println!("Execute {fn_name}");

            let input = if i % 2 == 0 {
                &left_vec[i]
            } else {
                &right_vec[i]
            };
            let clear_input = if i % 2 == 0 {
                clear_left_vec[i]
            } else {
                clear_right_vec[i]
            };

            let res = unary_op_executor.execute(input);
            // Check carries are empty and noise level is nominal
            assert!(
                res.block_carries_are_empty(),
                "Non empty carries on op {fn_name}",
            );
            res.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            // Determinism check
            let res_1 = unary_op_executor.execute(input);
            assert_eq!(
                res, res_1,
                "Determinism check failed on unary op {fn_name} with clear input {clear_input}.",
            );
            let input_degrees: Vec<u64> = input.blocks.iter().map(|b| b.degree.0).collect();
            let decrypted_res: u64 = cks.decrypt(&res);
            let expected_res: u64 = clear_fn(clear_input);
            if i % 2 == 0 {
                left_vec[j] = res.clone();
                clear_left_vec[j] = expected_res;
            } else {
                right_vec[j] = res.clone();
                clear_right_vec[j] = expected_res;
            }

            // Correctness check
            assert_eq!(
                decrypted_res, expected_res,
                "Invalid result on unary op {fn_name} with clear input {clear_input} at iteration {fn_index}, with input degree {input_degrees:?}.",
            );
        } else if scalar_binary_ops_range.contains(&i) {
            let index = i - scalar_binary_ops_range.start;
            let (scalar_binary_op_executor, clear_fn, fn_name) = &mut scalar_binary_ops[index];
            println!("Execute {fn_name}");

            let clear_left = clear_left_vec[i];
            let clear_right = clear_right_vec[i];

            let res = scalar_binary_op_executor.execute((&left_vec[i], clear_right_vec[i]));
            // Check carries are empty and noise level is lower or equal to nominal
            assert!(
                res.block_carries_are_empty(),
                "Non empty carries on op {fn_name}",
            );
            res.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            // Determinism check
            let res_1 = scalar_binary_op_executor.execute((&left_vec[i], clear_right_vec[i]));
            assert_eq!(
                res, res_1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
            let decrypted_res: u64 = cks.decrypt(&res);
            let expected_res: u64 = clear_fn(clear_left, clear_right);
            let input_degrees_left: Vec<u64> =
                left_vec[i].blocks.iter().map(|b| b.degree.0).collect();

            if i % 2 == 0 {
                left_vec[j] = res.clone();
                clear_left_vec[j] = expected_res;
            } else {
                right_vec[j] = res.clone();
                clear_right_vec[j] = expected_res;
            }

            // Correctness check
            assert_eq!(
                decrypted_res, expected_res,
                "Invalid result on binary op {fn_name} with clear inputs {clear_left} and {clear_right} at iteration {fn_index} and input degree {input_degrees_left:?}",
            );
        } else if overflowing_ops_range.contains(&i) {
            let index = i - overflowing_ops_range.start;
            let (overflowing_op_executor, clear_fn, fn_name) = &mut overflowing_ops[index];
            println!("Execute {fn_name}");

            let clear_left = clear_left_vec[i];
            let clear_right = clear_right_vec[i];

            let (res, overflow) = overflowing_op_executor.execute((&left_vec[i], &right_vec[i]));
            // Check carries are empty and noise level is lower or equal to nominal
            assert!(
                res.block_carries_are_empty(),
                "Non empty carries on op {fn_name}",
            );
            res.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            assert!(
                overflow.0.noise_level() <= NoiseLevel::NOMINAL,
                "Noise level greater than nominal value on overflow for op {fn_name}",
            );
            // Determinism check
            let (res_1, overflow_1) =
                overflowing_op_executor.execute((&left_vec[i], &right_vec[i]));
            assert_eq!(
                res, res_1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
            assert_eq!(
                overflow, overflow_1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right} on the overflow.",
            );
            let input_degrees_left: Vec<u64> =
                left_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let input_degrees_right: Vec<u64> =
                right_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let decrypted_res: u64 = cks.decrypt(&res);
            let decrypted_overflow = cks.decrypt_bool(&overflow);
            let (expected_res, expected_overflow) = clear_fn(clear_left, clear_right);

            if i % 2 == 0 {
                left_vec[j] = res.clone();
                clear_left_vec[j] = expected_res;
            } else {
                right_vec[j] = res.clone();
                clear_right_vec[j] = expected_res;
            }

            // Correctness check
            assert_eq!(
                decrypted_res, expected_res,
                "Invalid result on op {fn_name} with clear inputs {clear_left} and {clear_right} at iteration {fn_index}, with input degrees {input_degrees_left:?} and {input_degrees_right:?}.",
            );
            assert_eq!(
                decrypted_overflow, expected_overflow,
                "Invalid overflow on op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
        } else if scalar_overflowing_ops_range.contains(&i) {
            let index = i - scalar_overflowing_ops_range.start;
            let (scalar_overflowing_op_executor, clear_fn, fn_name) =
                &mut scalar_overflowing_ops[index];
            println!("Execute {fn_name}");

            let clear_left = clear_left_vec[i];
            let clear_right = clear_right_vec[i];

            let (res, overflow) =
                scalar_overflowing_op_executor.execute((&left_vec[i], clear_right_vec[i]));
            // Check carries are empty and noise level is lower or equal to nominal
            assert!(
                res.block_carries_are_empty(),
                "Non empty carries on op {fn_name}",
            );
            res.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            assert!(
                overflow.0.noise_level() <= NoiseLevel::NOMINAL,
                "Noise level greater than nominal value on overflow for op {fn_name}",
            );
            let input_degrees_left: Vec<u64> =
                left_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            // Determinism check
            let (res_1, overflow_1) =
                scalar_overflowing_op_executor.execute((&left_vec[i], clear_right_vec[i]));
            assert_eq!(
                res, res_1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right} with input degrees {input_degrees_left:?}.",
            );
            assert_eq!(
                overflow, overflow_1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right} on the overflow.",
            );
            let decrypted_res: u64 = cks.decrypt(&res);
            let decrypted_overflow = cks.decrypt_bool(&overflow);
            let (expected_res, expected_overflow) = clear_fn(clear_left, clear_right);

            if i % 2 == 0 {
                left_vec[j] = res.clone();
                clear_left_vec[j] = expected_res;
            } else {
                right_vec[j] = res.clone();
                clear_right_vec[j] = expected_res;
            }

            // Correctness check
            assert_eq!(
                decrypted_res, expected_res,
                "Invalid result on op {fn_name} with clear inputs {clear_left} and {clear_right} at iteration {fn_index}.",
            );
            assert_eq!(
                decrypted_overflow, expected_overflow,
                "Invalid overflow on op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
        } else if comparison_ops_range.contains(&i) {
            let index = i - comparison_ops_range.start;
            let (comparison_op_executor, clear_fn, fn_name) = &mut comparison_ops[index];
            println!("Execute {fn_name}");

            let clear_left = clear_left_vec[i];
            let clear_right = clear_right_vec[i];

            let res = comparison_op_executor.execute((&left_vec[i], &right_vec[i]));
            assert!(
                res.0.noise_level() <= NoiseLevel::NOMINAL,
                "Noise level greater than nominal value on op {fn_name}",
            );
            // Determinism check
            let res_1 = comparison_op_executor.execute((&left_vec[i], &right_vec[i]));
            assert_eq!(
                res, res_1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
            let input_degrees_left: Vec<u64> =
                left_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let input_degrees_right: Vec<u64> =
                right_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let decrypted_res = cks.decrypt_bool(&res);
            let expected_res = clear_fn(clear_left, clear_right);

            // Correctness check
            assert_eq!(
                decrypted_res, expected_res,
                "Invalid result on binary op {fn_name} with clear inputs {clear_left} and {clear_right} at iteration {fn_index} with input degrees {input_degrees_left:?} and {input_degrees_right:?}.",
            );

            let res_ct: RadixCiphertext = res.into_radix(1, &sks);
            if i % 2 == 0 {
                left_vec[j] = sks.cast_to_unsigned(res_ct, NB_CTXT_LONG_RUN);
                clear_left_vec[j] = expected_res as u64;
            } else {
                right_vec[j] = sks.cast_to_unsigned(res_ct, NB_CTXT_LONG_RUN);
                clear_right_vec[j] = expected_res as u64;
            }
        } else if scalar_comparison_ops_range.contains(&i) {
            let index = i - scalar_comparison_ops_range.start;
            let (scalar_comparison_op_executor, clear_fn, fn_name) =
                &mut scalar_comparison_ops[index];
            println!("Execute {fn_name}");

            let clear_left = clear_left_vec[i];
            let clear_right = clear_right_vec[i];

            let res = scalar_comparison_op_executor.execute((&left_vec[i], clear_right_vec[i]));
            assert!(
                res.0.noise_level() <= NoiseLevel::NOMINAL,
                "Noise level greater than nominal value on op {fn_name}",
            );
            // Determinism check
            let res_1 = scalar_comparison_op_executor.execute((&left_vec[i], clear_right_vec[i]));
            assert_eq!(
                res, res_1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
            let input_degrees_left: Vec<u64> =
                left_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let decrypted_res = cks.decrypt_bool(&res);
            let expected_res = clear_fn(clear_left, clear_right);

            // Correctness check
            assert_eq!(
                decrypted_res, expected_res,
                "Invalid result on binary op {fn_name} with clear inputs {clear_left} and {clear_right} at iteration {fn_index} with input degrees {input_degrees_left:?}.",
            );
            let res_ct: RadixCiphertext = res.into_radix(1, &sks);
            if i % 2 == 0 {
                left_vec[j] = sks.cast_to_unsigned(res_ct, NB_CTXT_LONG_RUN);
                clear_left_vec[j] = expected_res as u64;
            } else {
                right_vec[j] = sks.cast_to_unsigned(res_ct, NB_CTXT_LONG_RUN);
                clear_right_vec[j] = expected_res as u64;
            }
        } else if select_op_range.contains(&i) {
            let index = i - select_op_range.start;
            let (select_op_executor, clear_fn, fn_name) = &mut select_op[index];
            println!("Execute {fn_name}");

            let clear_left = clear_left_vec[i];
            let clear_right = clear_right_vec[i];
            let clear_bool: bool = rng.gen_bool(0.5);
            let bool_input = cks.encrypt_bool(clear_bool);

            let res = select_op_executor.execute((&bool_input, &left_vec[i], &right_vec[i]));
            // Check carries are empty and noise level is lower or equal to nominal
            assert!(
                res.block_carries_are_empty(),
                "Non empty carries on op {fn_name}",
            );
            res.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            // Determinism check
            let res_1 = select_op_executor.execute((&bool_input, &left_vec[i], &right_vec[i]));
            assert_eq!(
                res, res_1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left}, {clear_right} and {clear_bool}.",
            );
            let input_degrees_left: Vec<u64> =
                left_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let input_degrees_right: Vec<u64> =
                right_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let decrypted_res: u64 = cks.decrypt(&res);
            let expected_res = clear_fn(clear_bool, clear_left, clear_right);

            // Correctness check
            assert_eq!(
                decrypted_res, expected_res,
                "Invalid result on op {fn_name} with clear inputs {clear_left}, {clear_right} and {clear_bool} at iteration {fn_index} with input degrees {input_degrees_left:?} and {input_degrees_right:?}.",
            );
            if i % 2 == 0 {
                left_vec[j] = res.clone();
                clear_left_vec[j] = expected_res;
            } else {
                right_vec[j] = res.clone();
                clear_right_vec[j] = expected_res;
            }
        } else if div_rem_op_range.contains(&i) {
            let index = i - div_rem_op_range.start;
            let (div_rem_op_executor, clear_fn, fn_name) = &mut div_rem_op[index];
            println!("Execute {fn_name}");

            let clear_left = clear_left_vec[i];
            let clear_right = clear_right_vec[i];
            if clear_right == 0 {
                continue;
            }
            let (res_q, res_r) = div_rem_op_executor.execute((&left_vec[i], &right_vec[i]));
            // Check carries are empty and noise level is lower or equal to nominal
            assert!(
                res_q.block_carries_are_empty(),
                "Non empty carries on op {fn_name}",
            );
            assert!(
                res_r.block_carries_are_empty(),
                "Non empty carries on op {fn_name}",
            );
            res_q.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            res_r.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            // Determinism check
            let (res_q1, res_r1) = div_rem_op_executor.execute((&left_vec[i], &right_vec[i]));
            assert_eq!(
                res_q, res_q1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
            assert_eq!(
                res_r, res_r1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
            let input_degrees_left: Vec<u64> =
                left_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let input_degrees_right: Vec<u64> =
                right_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let decrypted_res_q: u64 = cks.decrypt(&res_q);
            let decrypted_res_r: u64 = cks.decrypt(&res_r);
            let (expected_res_q, expected_res_r) = clear_fn(clear_left, clear_right);

            // Correctness check
            assert_eq!(
                decrypted_res_q, expected_res_q,
                "Invalid result on op {fn_name} with clear inputs {clear_left}, {clear_right} at iteration {fn_index} with input degrees {input_degrees_left:?} and {input_degrees_right:?}",
            );
            assert_eq!(
                decrypted_res_r, expected_res_r,
                "Invalid result on op {fn_name} with clear inputs {clear_left}, {clear_right} at iteration {fn_index} with input degrees {input_degrees_left:?} and {input_degrees_right:?}",
            );
            if i % 2 == 0 {
                left_vec[j] = res_q.clone();
                clear_left_vec[j] = expected_res_q;
            } else {
                right_vec[j] = res_q.clone();
                clear_right_vec[j] = expected_res_q;
            }
        } else if scalar_div_rem_op_range.contains(&i) {
            let index = i - scalar_div_rem_op_range.start;
            let (scalar_div_rem_op_executor, clear_fn, fn_name) = &mut scalar_div_rem_op[index];
            println!("Execute {fn_name}");

            let clear_left = clear_left_vec[i];
            let clear_right = clear_right_vec[i];
            if clear_right == 0 {
                continue;
            }
            let (res_q, res_r) =
                scalar_div_rem_op_executor.execute((&left_vec[i], clear_right_vec[i]));
            // Check carries are empty and noise level is lower or equal to nominal
            assert!(
                res_q.block_carries_are_empty(),
                "Non empty carries on op {fn_name}",
            );
            assert!(
                res_r.block_carries_are_empty(),
                "Non empty carries on op {fn_name}",
            );
            res_q.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            res_r.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            // Determinism check
            let (res_q1, res_r1) =
                scalar_div_rem_op_executor.execute((&left_vec[i], clear_right_vec[i]));
            assert_eq!(
                res_q, res_q1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
            assert_eq!(
                res_r, res_r1,
                "Determinism check failed on binary op {fn_name} with clear inputs {clear_left} and {clear_right}.",
            );
            let input_degrees_left: Vec<u64> =
                left_vec[i].blocks.iter().map(|b| b.degree.0).collect();
            let decrypted_res_q: u64 = cks.decrypt(&res_q);
            let decrypted_res_r: u64 = cks.decrypt(&res_r);
            let (expected_res_q, expected_res_r) = clear_fn(clear_left, clear_right);

            // Correctness check
            assert_eq!(
                decrypted_res_q, expected_res_q,
                "Invalid result on op {fn_name} with clear inputs {clear_left}, {clear_right} at iteration {fn_index} with input degrees {input_degrees_left:?}.",
            );
            assert_eq!(
                decrypted_res_r, expected_res_r,
                "Invalid result on op {fn_name} with clear inputs {clear_left}, {clear_right} at iteration {fn_index} with input degrees {input_degrees_left:?}.",
            );
            if i % 2 == 0 {
                left_vec[j] = res_r.clone();
                clear_left_vec[j] = expected_res_r;
            } else {
                right_vec[j] = res_r.clone();
                clear_right_vec[j] = expected_res_r;
            }
        } else if log2_ops_range.contains(&i) {
            let index = i - log2_ops_range.start;
            let (log2_executor, clear_fn, fn_name) = &mut log2_ops[index];
            println!("Execute {fn_name}");

            let input = if i % 2 == 0 {
                &left_vec[i]
            } else {
                &right_vec[i]
            };
            let clear_input = if i % 2 == 0 {
                clear_left_vec[i]
            } else {
                clear_right_vec[i]
            };
            if clear_input == 0 {
                continue;
            }

            let res = log2_executor.execute(input);
            // Check carries are empty and noise level is lower or equal to nominal
            assert!(
                res.block_carries_are_empty(),
                "Non empty carries on op {fn_name}",
            );
            res.blocks.iter().enumerate().for_each(|(k, b)| {
                assert!(
                    b.noise_level() <= NoiseLevel::NOMINAL,
                    "Noise level greater than nominal value on op {fn_name} for block {k}",
                )
            });
            // Determinism check
            let res_1 = log2_executor.execute(input);
            assert_eq!(
                res, res_1,
                "Determinism check failed on op {fn_name} with clear input {clear_input}.",
            );
            let input_degrees: Vec<u64> = input.blocks.iter().map(|b| b.degree.0).collect();
            let cast_res = sks.cast_to_unsigned(res, NB_CTXT_LONG_RUN);
            let decrypted_res: u64 = cks.decrypt(&cast_res);
            let expected_res = clear_fn(clear_input);

            // Correctness check
            assert_eq!(
                decrypted_res, expected_res,
                "Invalid result on op {fn_name} with clear input {clear_input} at iteration {fn_index} with input degrees {input_degrees:?}.",
            );
            if i % 2 == 0 {
                left_vec[j] = cast_res.clone();
                clear_left_vec[j] = expected_res;
            } else {
                right_vec[j] = cast_res.clone();
                clear_right_vec[j] = expected_res;
            }
        }
    }
}
