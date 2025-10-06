use crate::integer::gpu::server_key::radix::tests_long_run::OpSequenceGpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::CudaServerKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_long_run::test_signed_random_op_sequence::{
    signed_random_op_sequence_test, SignedBinaryOpExecutor, SignedComparisonOpExecutor,
    SignedDivRemOpExecutor, SignedLog2OpExecutor, SignedOprfBoundedExecutor, SignedOprfExecutor,
    SignedOverflowingOpExecutor, SignedScalarBinaryOpExecutor, SignedScalarComparisonOpExecutor,
    SignedScalarDivRemOpExecutor, SignedScalarOverflowingOpExecutor,
    SignedScalarShiftRotateExecutor, SignedSelectOpExecutor, SignedShiftRotateExecutor,
    SignedUnaryOpExecutor,
};
use crate::integer::server_key::radix_parallel::tests_long_run::{
    get_user_defined_seed, RandomOpSequenceDataGenerator, NB_CTXT_LONG_RUN,
};
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
use crate::shortint::parameters::*;
use crate::{ClientKey, CompressedServerKey, Tag};
use std::cmp::{max, min};
use std::sync::Arc;

create_gpu_parameterized_test!(signed_random_op_sequence {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

#[allow(clippy::too_many_arguments)]
pub(crate) fn signed_random_op_sequence_test_init_gpu<P>(
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
    let param = param.into();
    let (cks0, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

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

    let cks = ClientKey::from_raw_parts(cks0.clone(), None, None, None, None, None, Tag::default());
    let comp_sks = CompressedServerKey::new(&cks);

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks0, NB_CTXT_LONG_RUN));

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

fn signed_random_op_sequence<P>(param: P)
where
    P: Into<TestParameters> + Clone,
{
    // Binary Ops Executors
    let add_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::add);
    let sub_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::sub);
    let bitwise_and_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitand);
    let bitwise_or_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitor);
    let bitwise_xor_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitxor);
    let mul_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::mul);
    let max_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::max);
    let min_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::min);

    // Binary Ops Clear functions
    let clear_add = |x, y| x + y;
    let clear_sub = |x, y| x - y;
    let clear_bitwise_and = |x, y| x & y;
    let clear_bitwise_or = |x, y| x | y;
    let clear_bitwise_xor = |x, y| x ^ y;
    let clear_mul = |x, y| x * y;
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
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::rotate_left);
    let left_shift_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::left_shift);
    let rotate_right_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::rotate_right);
    let right_shift_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::right_shift);
    // Warning this rotate definition only works with 64-bit ciphertexts
    let clear_rotate_left = |x: i64, y: u64| x.rotate_left(y as u32);
    let clear_left_shift = |x: i64, y: u64| x << y;
    // Warning this rotate definition only works with 64-bit ciphertexts
    let clear_rotate_right = |x: i64, y: u64| x.rotate_right(y as u32);
    let clear_right_shift = |x: i64, y: u64| x >> y;
    #[allow(clippy::type_complexity)]
    let mut shift_rotate_ops: Vec<(
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
    let neg_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::neg);
    let bitnot_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitnot);
    let abs_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::abs);
    //let reverse_bits_executor =
    // OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::reverse_bits); Unary Ops Clear
    // functions
    let clear_neg = |x: i64| x.wrapping_neg();
    let clear_abs = |x: i64| x.wrapping_abs();

    let clear_bitnot = |x: i64| !x;
    //let clear_reverse_bits = |x: i64| x.reverse_bits();
    #[allow(clippy::type_complexity)]
    let mut unary_ops: Vec<(SignedUnaryOpExecutor, &dyn Fn(i64) -> i64, String)> = vec![
        (Box::new(neg_executor), &clear_neg, "neg".to_string()),
        (Box::new(abs_executor), &clear_abs, "abs".to_string()),
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
    let scalar_add_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_add);
    let scalar_sub_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_sub);
    let scalar_bitwise_and_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_bitand);
    let scalar_bitwise_or_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_bitor);
    let scalar_bitwise_xor_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_bitxor);
    let scalar_mul_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_mul);

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
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_rotate_left);
    let scalar_left_shift_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_left_shift);
    let scalar_rotate_right_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_rotate_right);
    let scalar_right_shift_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_right_shift);
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
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::signed_overflowing_add);
    let overflowing_sub_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::signed_overflowing_sub);
    //let overflowing_mul_executor =
    //    OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::signed_overflowing_mul);

    // Overflowing Ops Clear functions
    let clear_overflowing_add = |x: i64, y: i64| -> (i64, bool) { x.overflowing_add(y) };
    let clear_overflowing_sub = |x: i64, y: i64| -> (i64, bool) { x.overflowing_sub(y) };
    //let clear_overflowing_mul = |x: i64, y: i64| -> (i64, bool) { x.overflowing_mul(y) };

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
        //(
        //    Box::new(overflowing_mul_executor),
        //    &clear_overflowing_mul,
        //    "overflowing mul".to_string(),
        //),
    ];

    // Scalar Overflowing Ops Executors
    let overflowing_scalar_add_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::signed_overflowing_scalar_add,
    );
    //    let overflowing_scalar_sub_executor =
    //        OpSequenceGpuMultiDeviceFunctionExecutor::new(&
    // CudaServerKey::signed_overflowing_scalar_sub);

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
        //(
        //    Box::new(overflowing_scalar_sub_executor),
        //    &clear_overflowing_sub,
        //    "overflowing scalar sub".to_string(),
        //),
    ];

    // Comparison Ops Executors
    let gt_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::gt);
    let ge_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ge);
    let lt_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::lt);
    let le_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::le);
    let eq_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::eq);
    let ne_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ne);

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
    let scalar_gt_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_gt);
    let scalar_ge_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_ge);
    let scalar_lt_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_lt);
    let scalar_le_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_le);
    let scalar_eq_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_eq);
    let scalar_ne_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_ne);

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
    let select_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::if_then_else);

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
    let div_rem_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::div_rem);
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
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::signed_scalar_div_rem);
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
    let ilog2_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ilog2);
    //let count_zeros_executor =
    // OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::count_zeros);
    // let count_ones_executor =
    // OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::count_ones);
    let clear_ilog2 = |x: i64| x.ilog2() as u64;
    //let clear_count_zeros = |x: i64| x.count_zeros() as i64;
    //let clear_count_ones = |x: i64| x.count_ones() as i64;

    #[allow(clippy::type_complexity)]
    let mut log2_ops: Vec<(SignedLog2OpExecutor, &dyn Fn(i64) -> u64, String)> = vec![
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

    let signed_oprf_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::par_generate_oblivious_pseudo_random_signed_integer,
    );
    let signed_oprf_bounded_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::par_generate_oblivious_pseudo_random_signed_integer_bounded,
    );

    let mut signed_oprf_ops: Vec<(SignedOprfExecutor, String)> = vec![(
        Box::new(signed_oprf_executor),
        "par_generate_oblivious_pseudo_random_signed_integer".to_string(),
    )];

    let mut signed_oprf_bounded_ops: Vec<(SignedOprfBoundedExecutor, String)> = vec![(
        Box::new(signed_oprf_bounded_executor),
        "par_generate_oblivious_pseudo_random_signed_integer_bounded".to_string(),
    )];

    let (cks, sks, mut datagen) = signed_random_op_sequence_test_init_gpu(
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
        &mut shift_rotate_ops,
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
        &mut shift_rotate_ops,
        &mut scalar_shift_rotate_ops,
        &mut signed_oprf_ops,
        &mut signed_oprf_bounded_ops,
    );
}
