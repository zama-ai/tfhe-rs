use crate::integer::gpu::server_key::radix::tests_long_run::GpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_long_run::test_random_op_sequence::{
    random_op_sequence_test, BinaryOpExecutor, ComparisonOpExecutor, DivRemOpExecutor,
    Log2OpExecutor, OverflowingOpExecutor, ScalarBinaryOpExecutor, ScalarComparisonOpExecutor,
    ScalarDivRemOpExecutor, ScalarOverflowingOpExecutor, SelectOpExecutor, UnaryOpExecutor,
};
use crate::shortint::parameters::*;
use std::cmp::{max, min};

create_gpu_parameterized_test!(random_op_sequence {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
fn random_op_sequence<P>(param: P)
where
    P: Into<TestParameters> + Clone,
{
    // Binary Ops Executors
    let add_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::add);
    let sub_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::sub);
    let bitwise_and_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitand);
    let bitwise_or_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitor);
    let bitwise_xor_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitxor);
    let mul_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::mul);
    let rotate_left_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::rotate_left);
    let left_shift_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::left_shift);
    let rotate_right_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::rotate_right);
    let right_shift_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::right_shift);
    let max_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::max);
    let min_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::min);

    // Binary Ops Clear functions
    let clear_add = |x, y| x + y;
    let clear_sub = |x, y| x - y;
    let clear_bitwise_and = |x, y| x & y;
    let clear_bitwise_or = |x, y| x | y;
    let clear_bitwise_xor = |x, y| x ^ y;
    let clear_mul = |x, y| x * y;
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
    let neg_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::neg);
    let bitnot_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitnot);
    //let reverse_bits_executor =
    // GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::reverse_bits); Unary Ops Clear
    // functions
    let clear_neg = |x: u64| x.wrapping_neg();
    let clear_bitnot = |x: u64| !x;
    //let clear_reverse_bits = |x: u64| x.reverse_bits();
    #[allow(clippy::type_complexity)]
    let mut unary_ops: Vec<(UnaryOpExecutor, &dyn Fn(u64) -> u64, String)> = vec![
        (Box::new(neg_executor), &clear_neg, "neg".to_string()),
        (
            Box::new(bitnot_executor),
            &clear_bitnot,
            "bitnot".to_string(),
        ),
        //(
        //    Box::new(reverse_bits_executor),
        //    &clear_reverse_bits,
        //    "reverse bits".to_string(),
        //),
    ];

    // Scalar binary Ops Executors
    let scalar_add_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_add);
    let scalar_sub_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_sub);
    let scalar_bitwise_and_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_bitand);
    let scalar_bitwise_or_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_bitor);
    let scalar_bitwise_xor_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_bitxor);
    let scalar_mul_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_mul);
    let scalar_rotate_left_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_rotate_left);
    let scalar_left_shift_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_left_shift);
    let scalar_rotate_right_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_rotate_right);
    let scalar_right_shift_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_right_shift);

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
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_add);
    let overflowing_sub_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_sub);
    //let overflowing_mul_executor =
    //    GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_mul);

    // Overflowing Ops Clear functions
    let clear_overflowing_add = |x: u64, y: u64| -> (u64, bool) { x.overflowing_add(y) };
    let clear_overflowing_sub = |x: u64, y: u64| -> (u64, bool) { x.overflowing_sub(y) };
    //let clear_overflowing_mul = |x: u64, y: u64| -> (u64, bool) { x.overflowing_mul(y) };

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
        //(
        //    Box::new(overflowing_mul_executor),
        //    &clear_overflowing_mul,
        //    "overflowing mul".to_string(),
        //),
    ];

    // Scalar Overflowing Ops Executors
    let overflowing_scalar_add_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_scalar_add);
    //    let overflowing_scalar_sub_executor =
    //        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_scalar_sub);

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
        //(
        //    Box::new(overflowing_scalar_sub_executor),
        //    &clear_overflowing_sub,
        //    "overflowing scalar sub".to_string(),
        //),
    ];

    // Comparison Ops Executors
    let gt_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::gt);
    let ge_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ge);
    let lt_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::lt);
    let le_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::le);
    let eq_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::eq);
    let ne_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ne);

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
    let scalar_gt_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_gt);
    let scalar_ge_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_ge);
    let scalar_lt_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_lt);
    let scalar_le_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_le);
    let scalar_eq_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_eq);
    let scalar_ne_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_ne);

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
    let select_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::if_then_else);

    // Select
    let clear_select = |b: bool, x: u64, y: u64| if b { x } else { y };

    #[allow(clippy::type_complexity)]
    let mut select_op: Vec<(SelectOpExecutor, &dyn Fn(bool, u64, u64) -> u64, String)> = vec![(
        Box::new(select_executor),
        &clear_select,
        "select".to_string(),
    )];

    // Div executor
    let div_rem_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::div_rem);
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
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_div_rem);
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
    let ilog2_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ilog2);
    //let count_zeros_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::count_zeros);
    //let count_ones_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::count_ones);
    let clear_ilog2 = |x: u64| x.ilog2() as u64;
    //let clear_count_zeros = |x: u64| x.count_zeros() as u64;
    //let clear_count_ones = |x: u64| x.count_ones() as u64;

    #[allow(clippy::type_complexity)]
    let mut log2_ops: Vec<(Log2OpExecutor, &dyn Fn(u64) -> u64, String)> = vec![
        (Box::new(ilog2_executor), &clear_ilog2, "ilog2".to_string()),
        //(
        //    Box::new(count_zeros_executor),
        //    &clear_count_zeros,
        //    "count zeros".to_string(),
        //),
        //(
        //    Box::new(count_ones_executor),
        //    &clear_count_ones,
        //    "count ones".to_string(),
        //),
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
