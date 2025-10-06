use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_long_run::OpSequenceGpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::CudaServerKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_long_run::test_random_op_sequence::{
    random_op_sequence_test, BinaryOpExecutor, ComparisonOpExecutor, DivRemOpExecutor,
    Log2OpExecutor, OprfBoundedExecutor, OprfCustomRangeExecutor, OprfExecutor,
    OverflowingOpExecutor, ScalarBinaryOpExecutor, ScalarComparisonOpExecutor,
    ScalarDivRemOpExecutor, ScalarOverflowingOpExecutor, SelectOpExecutor, UnaryOpExecutor,
};
use crate::integer::server_key::radix_parallel::tests_long_run::{
    get_user_defined_seed, RandomOpSequenceDataGenerator, NB_CTXT_LONG_RUN,
};
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::*;
use crate::{ClientKey, CompressedServerKey, Tag};
use std::sync::Arc;

create_gpu_parameterized_test!(random_op_sequence {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

#[cfg(feature = "gpu-debug-fake-multi-gpu")]
create_gpu_parameterized_test!(short_random_op_sequence {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

#[allow(clippy::too_many_arguments)]
pub(crate) fn random_op_sequence_test_init_gpu<P>(
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
    let (cks0, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let cks = ClientKey::from_raw_parts(cks0.clone(), None, None, None, None, None, Tag::default());
    let comp_sks = CompressedServerKey::new(&cks);
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    println!("Setting up operations");
    let cks = RadixClientKey::from((cks0, NB_CTXT_LONG_RUN));

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

mod clear_functions {
    #![allow(non_upper_case_globals)]

    // Overflowing Ops Clear functions
    pub(crate) const clear_add: fn(u64, u64) -> u64 = |x, y| x.wrapping_add(y);
    pub(crate) const clear_sub: fn(u64, u64) -> u64 = |x, y| x.wrapping_sub(y);
    pub(crate) const clear_bitwise_and: fn(u64, u64) -> u64 = |x, y| x & y;
    pub(crate) const clear_bitwise_or: fn(u64, u64) -> u64 = |x, y| x | y;
    pub(crate) const clear_bitwise_xor: fn(u64, u64) -> u64 = |x, y| x ^ y;
    pub(crate) const clear_mul: fn(u64, u64) -> u64 = |x, y| x.wrapping_mul(y);
    // Warning this rotate definition only works with 64-bit ciphertexts
    pub(crate) const clear_rotate_left: fn(u64, u64) -> u64 =
        |x: u64, y: u64| x.rotate_left(y as u32);
    pub(crate) const clear_left_shift: fn(u64, u64) -> u64 = |x, y| x.wrapping_shl(y as u32);
    // Warning this rotate definition only works with 64-bit ciphertexts
    pub(crate) const clear_rotate_right: fn(u64, u64) -> u64 =
        |x: u64, y: u64| x.rotate_right(y as u32);
    pub(crate) const clear_right_shift: fn(u64, u64) -> u64 = |x, y| x.wrapping_shr(y as u32);
    pub(crate) const clear_max: fn(u64, u64) -> u64 = |x: u64, y: u64| std::cmp::max(x, y);
    pub(crate) const clear_min: fn(u64, u64) -> u64 = |x: u64, y: u64| std::cmp::min(x, y);
    pub(crate) const clear_neg: fn(u64) -> u64 = |x: u64| x.wrapping_neg();
    pub(crate) const clear_bitnot: fn(u64) -> u64 = |x: u64| !x;
    //pub(crate) const clear_reverse_bits = |x: u64| x.reverse_bits();
    pub(crate) const clear_overflowing_add: fn(u64, u64) -> (u64, bool) =
        |x: u64, y: u64| -> (u64, bool) { x.overflowing_add(y) };
    pub(crate) const clear_overflowing_sub: fn(u64, u64) -> (u64, bool) =
        |x: u64, y: u64| -> (u64, bool) { x.overflowing_sub(y) };
    //pub(crate) const clear_overflowing_mul: fn(u64, u64) -> u64 = |x: u64, y: u64| -> (u64, bool)
    // { x.overflowing_mul(y) }; Comparison Ops Clear functions
    pub(crate) const clear_gt: fn(u64, u64) -> bool = |x: u64, y: u64| -> bool { x > y };
    pub(crate) const clear_ge: fn(u64, u64) -> bool = |x: u64, y: u64| -> bool { x >= y };
    pub(crate) const clear_lt: fn(u64, u64) -> bool = |x: u64, y: u64| -> bool { x < y };
    pub(crate) const clear_le: fn(u64, u64) -> bool = |x: u64, y: u64| -> bool { x <= y };
    pub(crate) const clear_eq: fn(u64, u64) -> bool = |x: u64, y: u64| -> bool { x == y };
    pub(crate) const clear_ne: fn(u64, u64) -> bool = |x: u64, y: u64| -> bool { x != y };
    // Select
    pub(crate) const clear_select: fn(bool, u64, u64) -> u64 =
        |b: bool, x: u64, y: u64| if b { x } else { y };
    // Div Rem Clear functions
    pub(crate) const clear_div_rem: fn(u64, u64) -> (u64, u64) =
        |x: u64, y: u64| -> (u64, u64) { (x.wrapping_div(y), x.wrapping_rem(y)) };
    pub(crate) const clear_ilog2: fn(u64) -> u64 = |x: u64| x.ilog2() as u64;
}

#[cfg(feature = "gpu-debug-fake-multi-gpu")]
fn short_random_op_sequence<P>(param: P)
where
    P: Into<TestParameters> + Clone,
{
    use clear_functions;
    println!("Running short random op sequence test");

    // Binary Ops Executors
    let add_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::add);
    let sub_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::sub);
    let bitwise_and_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitand);
    let bitwise_or_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitor);
    let bitwise_xor_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitxor);
    let mul_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::mul);

    // Binary Ops Clear functions
    #[allow(clippy::type_complexity)]
    let mut binary_ops: Vec<(BinaryOpExecutor, &dyn Fn(u64, u64) -> u64, String)> = vec![
        (
            Box::new(add_executor),
            &clear_functions::clear_add,
            "add".to_string(),
        ),
        (
            Box::new(sub_executor),
            &clear_functions::clear_sub,
            "sub".to_string(),
        ),
        (
            Box::new(bitwise_and_executor),
            &clear_functions::clear_bitwise_and,
            "bitand".to_string(),
        ),
        (
            Box::new(bitwise_or_executor),
            &clear_functions::clear_bitwise_or,
            "bitor".to_string(),
        ),
        (
            Box::new(bitwise_xor_executor),
            &clear_functions::clear_bitwise_xor,
            "bitxor".to_string(),
        ),
        (
            Box::new(mul_executor),
            &clear_functions::clear_mul,
            "mul".to_string(),
        ),
    ];

    let mut unary_ops: Vec<(UnaryOpExecutor, &dyn Fn(u64) -> u64, String)> = vec![];
    let mut scalar_binary_ops: Vec<(ScalarBinaryOpExecutor, &dyn Fn(u64, u64) -> u64, String)> =
        vec![];
    let mut overflowing_ops: Vec<(
        OverflowingOpExecutor,
        &dyn Fn(u64, u64) -> (u64, bool),
        String,
    )> = vec![];
    let mut scalar_overflowing_ops: Vec<(
        ScalarOverflowingOpExecutor,
        &dyn Fn(u64, u64) -> (u64, bool),
        String,
    )> = vec![];
    let mut comparison_ops: Vec<(ComparisonOpExecutor, &dyn Fn(u64, u64) -> bool, String)> = vec![];
    let mut scalar_comparison_ops: Vec<(
        ScalarComparisonOpExecutor,
        &dyn Fn(u64, u64) -> bool,
        String,
    )> = vec![];

    // Select Executor
    let select_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::if_then_else);

    #[allow(clippy::type_complexity)]
    let mut select_op: Vec<(SelectOpExecutor, &dyn Fn(bool, u64, u64) -> u64, String)> = vec![(
        Box::new(select_executor),
        &clear_functions::clear_select,
        "select".to_string(),
    )];

    // Div executor
    let div_rem_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::div_rem);
    #[allow(clippy::type_complexity)]
    let mut div_rem_op: Vec<(DivRemOpExecutor, &dyn Fn(u64, u64) -> (u64, u64), String)> = vec![(
        Box::new(div_rem_executor),
        &clear_functions::clear_div_rem,
        "div rem".to_string(),
    )];

    // Scalar Div executor
    let scalar_div_rem_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_div_rem);
    #[allow(clippy::type_complexity)]
    let mut scalar_div_rem_op: Vec<(
        ScalarDivRemOpExecutor,
        &dyn Fn(u64, u64) -> (u64, u64),
        String,
    )> = vec![(
        Box::new(scalar_div_rem_executor),
        &clear_functions::clear_div_rem,
        "scalar div rem".to_string(),
    )];

    // Log2/Hamming weight ops
    let ilog2_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ilog2);

    #[allow(clippy::type_complexity)]
    let mut log2_ops: Vec<(Log2OpExecutor, &dyn Fn(u64) -> u64, String)> = vec![(
        Box::new(ilog2_executor),
        &clear_functions::clear_ilog2,
        "ilog2".to_string(),
    )];

    let mut oprf_ops: Vec<(OprfExecutor, String)> = vec![];
    let mut oprf_bounded_ops: Vec<(OprfBoundedExecutor, String)> = vec![];
    let mut oprf_custom_range_ops: Vec<(OprfCustomRangeExecutor, String)> = vec![];

    let (cks, sks, mut datagen) = random_op_sequence_test_init_gpu(
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

fn random_op_sequence<P>(param: P)
where
    P: Into<TestParameters> + Clone,
{
    use clear_functions;

    println!("Running random op sequence test");

    // Binary Ops Executors
    let add_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::add);
    let sub_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::sub);
    let bitwise_and_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitand);
    let bitwise_or_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitor);
    let bitwise_xor_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitxor);
    let mul_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::mul);
    let rotate_left_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::rotate_left);
    let left_shift_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::left_shift);
    let rotate_right_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::rotate_right);
    let right_shift_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::right_shift);
    let max_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::max);
    let min_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::min);

    // Binary Ops Clear functions
    #[allow(clippy::type_complexity)]
    let mut binary_ops: Vec<(BinaryOpExecutor, &dyn Fn(u64, u64) -> u64, String)> = vec![
        (
            Box::new(add_executor),
            &clear_functions::clear_add,
            "add".to_string(),
        ),
        (
            Box::new(sub_executor),
            &clear_functions::clear_sub,
            "sub".to_string(),
        ),
        (
            Box::new(bitwise_and_executor),
            &clear_functions::clear_bitwise_and,
            "bitand".to_string(),
        ),
        (
            Box::new(bitwise_or_executor),
            &clear_functions::clear_bitwise_or,
            "bitor".to_string(),
        ),
        (
            Box::new(bitwise_xor_executor),
            &clear_functions::clear_bitwise_xor,
            "bitxor".to_string(),
        ),
        (
            Box::new(mul_executor),
            &clear_functions::clear_mul,
            "mul".to_string(),
        ),
        (
            Box::new(rotate_left_executor),
            &clear_functions::clear_rotate_left,
            "rotate left".to_string(),
        ),
        (
            Box::new(left_shift_executor),
            &clear_functions::clear_left_shift,
            "left shift".to_string(),
        ),
        (
            Box::new(rotate_right_executor),
            &clear_functions::clear_rotate_right,
            "rotate right".to_string(),
        ),
        (
            Box::new(right_shift_executor),
            &clear_functions::clear_right_shift,
            "right shift".to_string(),
        ),
        (
            Box::new(max_executor),
            &clear_functions::clear_max,
            "max".to_string(),
        ),
        (
            Box::new(min_executor),
            &clear_functions::clear_min,
            "min".to_string(),
        ),
    ];

    // Unary Ops Executors
    let neg_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::neg::<CudaUnsignedRadixCiphertext>,
    );
    let bitnot_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::bitnot::<CudaUnsignedRadixCiphertext>,
    );
    //let reverse_bits_executor =
    // OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::reverse_bits); Unary Ops Clear
    // functions

    #[allow(clippy::type_complexity)]
    let mut unary_ops: Vec<(UnaryOpExecutor, &dyn Fn(u64) -> u64, String)> = vec![
        (
            Box::new(neg_executor),
            &clear_functions::clear_neg,
            "neg".to_string(),
        ),
        (
            Box::new(bitnot_executor),
            &clear_functions::clear_bitnot,
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
    let scalar_rotate_left_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_rotate_left);
    let scalar_left_shift_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_left_shift);
    let scalar_rotate_right_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_rotate_right);
    let scalar_right_shift_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_right_shift);

    #[allow(clippy::type_complexity)]
    let mut scalar_binary_ops: Vec<(ScalarBinaryOpExecutor, &dyn Fn(u64, u64) -> u64, String)> = vec![
        (
            Box::new(scalar_add_executor),
            &clear_functions::clear_add,
            "scalar add".to_string(),
        ),
        (
            Box::new(scalar_sub_executor),
            &clear_functions::clear_sub,
            "scalar sub".to_string(),
        ),
        (
            Box::new(scalar_bitwise_and_executor),
            &clear_functions::clear_bitwise_and,
            "scalar bitand".to_string(),
        ),
        (
            Box::new(scalar_bitwise_or_executor),
            &clear_functions::clear_bitwise_or,
            "scalar bitor".to_string(),
        ),
        (
            Box::new(scalar_bitwise_xor_executor),
            &clear_functions::clear_bitwise_xor,
            "scalar bitxor".to_string(),
        ),
        (
            Box::new(scalar_mul_executor),
            &clear_functions::clear_mul,
            "scalar mul".to_string(),
        ),
        (
            Box::new(scalar_rotate_left_executor),
            &clear_functions::clear_rotate_left,
            "scalar rotate left".to_string(),
        ),
        (
            Box::new(scalar_left_shift_executor),
            &clear_functions::clear_left_shift,
            "scalar left shift".to_string(),
        ),
        (
            Box::new(scalar_rotate_right_executor),
            &clear_functions::clear_rotate_right,
            "scalar rotate right".to_string(),
        ),
        (
            Box::new(scalar_right_shift_executor),
            &clear_functions::clear_right_shift,
            "scalar right shift".to_string(),
        ),
    ];

    // Overflowing Ops Executors
    let overflowing_add_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_add);
    let overflowing_sub_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_sub);
    //let overflowing_mul_executor =
    //    OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_mul);

    #[allow(clippy::type_complexity)]
    let mut overflowing_ops: Vec<(
        OverflowingOpExecutor,
        &dyn Fn(u64, u64) -> (u64, bool),
        String,
    )> = vec![
        (
            Box::new(overflowing_add_executor),
            &clear_functions::clear_overflowing_add,
            "overflowing add".to_string(),
        ),
        (
            Box::new(overflowing_sub_executor),
            &clear_functions::clear_overflowing_sub,
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
        &CudaServerKey::unsigned_overflowing_scalar_add,
    );
    //    let overflowing_scalar_sub_executor =
    //        OpSequenceGpuMultiDeviceFunctionExecutor::new(&
    // CudaServerKey::unsigned_overflowing_scalar_sub);

    #[allow(clippy::type_complexity)]
    let mut scalar_overflowing_ops: Vec<(
        ScalarOverflowingOpExecutor,
        &dyn Fn(u64, u64) -> (u64, bool),
        String,
    )> = vec![
        (
            Box::new(overflowing_scalar_add_executor),
            &clear_functions::clear_overflowing_add,
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

    #[allow(clippy::type_complexity)]
    let mut comparison_ops: Vec<(ComparisonOpExecutor, &dyn Fn(u64, u64) -> bool, String)> = vec![
        (
            Box::new(gt_executor),
            &clear_functions::clear_gt,
            "gt".to_string(),
        ),
        (
            Box::new(ge_executor),
            &clear_functions::clear_ge,
            "ge".to_string(),
        ),
        (
            Box::new(lt_executor),
            &clear_functions::clear_lt,
            "lt".to_string(),
        ),
        (
            Box::new(le_executor),
            &clear_functions::clear_le,
            "le".to_string(),
        ),
        (
            Box::new(eq_executor),
            &clear_functions::clear_eq,
            "eq".to_string(),
        ),
        (
            Box::new(ne_executor),
            &clear_functions::clear_ne,
            "ne".to_string(),
        ),
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
        ScalarComparisonOpExecutor,
        &dyn Fn(u64, u64) -> bool,
        String,
    )> = vec![
        (
            Box::new(scalar_gt_executor),
            &clear_functions::clear_gt,
            "scalar gt".to_string(),
        ),
        (
            Box::new(scalar_ge_executor),
            &clear_functions::clear_ge,
            "scalar ge".to_string(),
        ),
        (
            Box::new(scalar_lt_executor),
            &clear_functions::clear_lt,
            "scalar lt".to_string(),
        ),
        (
            Box::new(scalar_le_executor),
            &clear_functions::clear_le,
            "scalar le".to_string(),
        ),
        (
            Box::new(scalar_eq_executor),
            &clear_functions::clear_eq,
            "scalar eq".to_string(),
        ),
        (
            Box::new(scalar_ne_executor),
            &clear_functions::clear_ne,
            "scalar ne".to_string(),
        ),
    ];

    // Select Executor
    let select_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::if_then_else);

    #[allow(clippy::type_complexity)]
    let mut select_op: Vec<(SelectOpExecutor, &dyn Fn(bool, u64, u64) -> u64, String)> = vec![(
        Box::new(select_executor),
        &clear_functions::clear_select,
        "select".to_string(),
    )];

    // Div executor
    let div_rem_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::div_rem);
    #[allow(clippy::type_complexity)]
    let mut div_rem_op: Vec<(DivRemOpExecutor, &dyn Fn(u64, u64) -> (u64, u64), String)> = vec![(
        Box::new(div_rem_executor),
        &clear_functions::clear_div_rem,
        "div rem".to_string(),
    )];

    // Scalar Div executor
    let scalar_div_rem_executor =
        OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::scalar_div_rem);
    #[allow(clippy::type_complexity)]
    let mut scalar_div_rem_op: Vec<(
        ScalarDivRemOpExecutor,
        &dyn Fn(u64, u64) -> (u64, u64),
        String,
    )> = vec![(
        Box::new(scalar_div_rem_executor),
        &clear_functions::clear_div_rem,
        "scalar div rem".to_string(),
    )];

    // Log2/Hamming weight ops
    let ilog2_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ilog2);
    //let count_zeros_executor =
    // OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::count_zeros);
    // let count_ones_executor =
    // OpSequenceGpuMultiDeviceFunctionExecutor::new(&CudaServerKey::count_ones);
    //let clear_count_zeros = |x: u64| x.count_zeros() as u64;
    //let clear_count_ones = |x: u64| x.count_ones() as u64;

    #[allow(clippy::type_complexity)]
    let mut log2_ops: Vec<(Log2OpExecutor, &dyn Fn(u64) -> u64, String)> = vec![
        (
            Box::new(ilog2_executor),
            &clear_functions::clear_ilog2,
            "ilog2".to_string(),
        ),
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

    // OPRF Executors
    let oprf_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::par_generate_oblivious_pseudo_random_unsigned_integer,
    );
    let oprf_bounded_executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::par_generate_oblivious_pseudo_random_unsigned_integer_bounded,
    );

    let mut oprf_ops: Vec<(OprfExecutor, String)> = vec![(
        Box::new(oprf_executor),
        "par_generate_oblivious_pseudo_random_unsigned_integer".to_string(),
    )];

    let mut oprf_bounded_ops: Vec<(OprfBoundedExecutor, String)> = vec![(
        Box::new(oprf_bounded_executor),
        "par_generate_oblivious_pseudo_random_unsigned_integer_bounded".to_string(),
    )];

    // The custom_range variant is not yet implemented on GPU
    let mut oprf_custom_range_ops: Vec<(OprfCustomRangeExecutor, String)> = vec![];

    let (cks, sks, mut datagen) = random_op_sequence_test_init_gpu(
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
