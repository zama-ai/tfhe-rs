use benchmark::high_level_api::bench_wait::*;
use benchmark::high_level_api::benchmark_op::*;
use benchmark::utilities::{
    bench_backend_from_cfg, will_this_bench_run, write_to_json, OperatorType,
};
use benchmark_spec::{get_bench_type, BenchmarkSpec, BenchmarkType, HlIntegerOp, OperandType};
use criterion::{black_box, Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::ClientKey;

#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn bench_fhe_type_op<FheType, Op>(
    c: &mut Criterion,
    client_key: &ClientKey,
    hlapi_op: HlIntegerOp,
    operand_type: OperandType,
    type_name: &str,
    bit_size: usize,
    op: Op,
) where
    Op: BenchmarkOp<FheType> + Sync,
    FheType: FheWait + Send + Sync,
{
    let mut bench_group = c.benchmark_group(type_name);

    let mut rng = thread_rng();

    let param = client_key.computation_parameters();
    let param_name = param.name();
    let bit_size = bit_size as u32;

    let inputs = op.setup_inputs(client_key, &mut rng);

    let bench_type = get_bench_type();
    let benchmark_spec = BenchmarkSpec::new_hlapi_ops(
        hlapi_op,
        &param_name,
        &operand_type,
        Some(type_name),
        *bench_type,
        bench_backend_from_cfg(),
    );
    let bench_id = benchmark_spec.to_string();

    match bench_type {
        BenchmarkType::Latency => {
            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    let res = op.execute(&inputs);
                    res.wait_bench();
                    black_box(res)
                })
            });
        }
        BenchmarkType::Throughput => {
            let setup = |batch_size: usize| {
                (0..batch_size)
                    .into_par_iter()
                    .map(|_| op.setup_inputs(client_key, &mut thread_rng()))
                    .collect::<Vec<_>>()
            };

            let elements = if will_this_bench_run(type_name, &bench_id) {
                #[cfg(any(feature = "gpu", feature = "hpu"))]
                {
                    use benchmark::utilities::throughput_num_threads;
                    use std::cmp::max;
                    use tfhe::{get_pbs_count, reset_pbs_count};
                    reset_pbs_count();
                    let res = op.execute(&inputs);
                    res.wait_bench();
                    let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default
                    let num_block = (bit_size as f64 / (param.message_modulus().0 as f64).log(2.0))
                        .ceil() as usize;
                    throughput_num_threads(num_block, pbs_count)
                }
                #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                {
                    use benchmark::find_optimal_batch::find_optimal_batch;
                    let run = |inputs: &mut Vec<_>, batch_size: usize| {
                        inputs.par_iter().take(batch_size).for_each(|input| {
                            let res = op.execute(input);
                            res.wait_bench();
                            black_box(res);
                        });
                    };
                    find_optimal_batch(run, setup) as u64
                }
            } else {
                0
            };

            bench_group
                .sample_size(10)
                .measurement_time(std::time::Duration::from_secs(30));

            bench_group.throughput(Throughput::Elements(elements));

            bench_group.bench_function(&bench_id, |b| {
                let setup_encrypted_inputs = || setup(elements as usize);
                b.iter_batched(
                    setup_encrypted_inputs,
                    |inputs_vec| {
                        inputs_vec.par_iter().for_each(|inputs| {
                            let res = op.execute(inputs);
                            res.wait_bench();
                            black_box(res);
                        })
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }
    }

    write_to_json::<u64, _>(
        &benchmark_spec,
        param,
        hlapi_op.to_string(),
        &OperatorType::Atomic,
        bit_size,
        vec![],
    );
}

macro_rules! bench_type_binary_op {
    (
        type_name: $fhe_type:ident,
        right_type_name: $fhe_right_type:ident,
        left_type: $left_type:ty,
        right_type: $right_type:ty,
        hlapi_op: $hlapi_op:expr,
        operation: $op:ident
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    $hlapi_op,
                    OperandType::CipherText,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    BinaryOp {
                        func: |lhs: &$fhe_type, rhs: &$fhe_right_type| lhs.$op(rhs),
                        _encrypt_lhs: PhantomData::<$left_type>,
                        _encrypt_rhs: PhantomData::<$right_type>,
                        _rhs_type: PhantomData::<$fhe_right_type>,
                    }
                );
            }
        }
    };
}

macro_rules! bench_type_binary_scalar_op {
    (
        type_name: $fhe_type:ident,
        integer_type: $integer_type:ty,
        scalar_type: $scalar_ty:ty,
        hlapi_op: $hlapi_op:expr,
        operation: $op:ident,
        rng: $rng_fn:expr
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<bench_ $fhe_type:snake _scalar_ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    $hlapi_op,
                    OperandType::PlainText,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    ScalarBinaryOp {
                        func: |lhs: &$fhe_type, rhs: &$scalar_ty| lhs.$op(*rhs),
                        rng_function: $rng_fn,
                        _encrypt: PhantomData::<$integer_type>,
                    }
                );
            }
        }
    };
}

macro_rules! bench_type_unary_op {
    (
        type_name: $fhe_type:ident,
        integer_type: $integer_type:ty,
        hlapi_op: $hlapi_op:expr,
        operation: $op:ident
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    $hlapi_op,
                    OperandType::CipherText,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    UnaryOp {
                        func: |lhs: &$fhe_type| lhs.$op(),
                        _encrypt: PhantomData::<$integer_type>
                    }
                );
            }
        }
    };
}

macro_rules! bench_type_ternary_op {
    (
        type_name: $fhe_type:ident,
        integer_type: $integer_type:ty,
        hlapi_op: $hlapi_op:expr,
        operation: $op:ident
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    $hlapi_op,
                    OperandType::CipherText,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    TernaryOp {
                        func: |cond: &FheBool, lhs: &$fhe_type, rhs: &$fhe_type| cond.$op(lhs, rhs),
                        _encrypt: PhantomData::<$integer_type>
                    }
                );
            }
        }
    };
}

macro_rules! bench_type_array_op {
    (
        type_name: $fhe_type:ident,
        integer_type: $integer_type:ty,
        hlapi_op: $hlapi_op:expr,
        operation: $op:ident
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    $hlapi_op,
                    OperandType::CipherText,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    ArrayOp {
                        func: |iter: std::slice::Iter<'_, $fhe_type>| iter.$op(),
                        array_size: 64,
                        _encrypt: PhantomData::<$integer_type>,
                    }
                );
            }
        }
    };
}

macro_rules! generate_typed_benches {
    (
        $fhe_type:ident,
        $integer_type:ty
    ) => {
        bench_type_array_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::Sum,
            operation: sum
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Add,
            operation: add
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Bitand,
            operation: bitand
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Bitor,
            operation: bitor
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Bitxor,
            operation: bitxor
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Div,
            operation: div
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::DivRem,
            operation: div_rem
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Eq,
            operation: eq
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Ge,
            operation: ge
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Gt,
            operation: gt
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Le,
            operation: le
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: FheUint8,
            left_type: $integer_type,
            right_type: u8,
            hlapi_op: HlIntegerOp::LeftRotate,
            operation: rotate_left
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: FheUint8,
            left_type: $integer_type,
            right_type: u8,
            hlapi_op: HlIntegerOp::LeftShift,
            operation: shl
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Lt,
            operation: lt
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Max,
            operation: max
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Min,
            operation: min
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Mul,
            operation: mul
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Ne,
            operation: ne
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::OverflowingAdd,
            operation: overflowing_add
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::OverflowingMul,
            operation: overflowing_mul
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::OverflowingSub,
            operation: overflowing_sub
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Rem,
            operation: rem
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: FheUint8,
            left_type: $integer_type,
            right_type: u8,
            hlapi_op: HlIntegerOp::RightRotate,
            operation: rotate_right
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: FheUint8,
            left_type: $integer_type,
            right_type: u8,
            hlapi_op: HlIntegerOp::RightShift,
            operation: shr
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            hlapi_op: HlIntegerOp::Sub,
            operation: sub
        );
        bench_type_ternary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::Flip,
            operation: flip
        );
        bench_type_ternary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::IfThenElse,
            operation: if_then_else
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::CheckedIlog2,
            operation: checked_ilog2
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::CountOnes,
            operation: count_ones
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::CountZeros,
            operation: count_zeros
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::Ilog2,
            operation: ilog2
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::IsEven,
            operation: is_even
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::IsOdd,
            operation: is_odd
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::LeadingOnes,
            operation: leading_ones
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::LeadingZeros,
            operation: leading_zeros
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::Neg,
            operation: neg
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::Not,
            operation: not
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::OverflowingNeg,
            operation: overflowing_neg
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::ReverseBits,
            operation: reverse_bits
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::TrailingOnes,
            operation: trailing_ones
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            hlapi_op: HlIntegerOp::TrailingZeros,
            operation: trailing_zeros
        );
    };
}

macro_rules! generate_typed_scalar_benches {
    (
        $fhe_type:ident,
        $integer_type:ty,
        $scalar_ty:ty,
        $specific_ty:ty
    ) => {
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Add,
            operation: add,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Bitand,
            operation: bitand,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Bitor,
            operation: bitor,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Bitxor,
            operation: bitxor,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Div,
            operation: div,
            rng: || random_non_zero::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Eq,
            operation: eq,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Ge,
            operation: ge,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Gt,
            operation: gt,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Le,
            operation: le,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Lt,
            operation: lt,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Max,
            operation: max,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Min,
            operation: min,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Mul,
            operation: mul,
            rng: || random_not_power_of_two::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Ne,
            operation: ne,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::OverflowingAdd,
            operation: overflowing_add,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::OverflowingSub,
            operation: overflowing_sub,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Rem,
            operation: rem,
            rng: || random_non_zero::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $specific_ty,
            hlapi_op: HlIntegerOp::LeftRotate,
            operation: rotate_left,
            rng: || rand::random::<$specific_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $specific_ty,
            hlapi_op: HlIntegerOp::RightRotate,
            operation: rotate_right,
            rng: || rand::random::<$specific_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $specific_ty,
            hlapi_op: HlIntegerOp::LeftShift,
            operation: shl,
            rng: || <$specific_ty>::ONE
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $specific_ty,
            hlapi_op: HlIntegerOp::RightShift,
            operation: shr,
            rng: || <$specific_ty>::ONE
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            hlapi_op: HlIntegerOp::Sub,
            operation: sub,
            rng: || rand::random::<$scalar_ty>()
        );
    };
}

macro_rules! run_benches {
    (
        $c:expr,
        $cks:expr,
        $($fhe_type:ident),
        + $(,)?
    ) => {
        $(
            ::paste::paste! {
                [<bench_ $fhe_type:snake _add>]($c, $cks);
                [<bench_ $fhe_type:snake _bitand>]($c, $cks);
                [<bench_ $fhe_type:snake _bitor>]($c, $cks);
                [<bench_ $fhe_type:snake _bitxor>]($c, $cks);
                [<bench_ $fhe_type:snake _checked_ilog2>]($c, $cks);
                [<bench_ $fhe_type:snake _count_ones>]($c, $cks);
                [<bench_ $fhe_type:snake _count_zeros>]($c, $cks);
                [<bench_ $fhe_type:snake _div>]($c, $cks);
                [<bench_ $fhe_type:snake _div_rem>]($c, $cks);
                [<bench_ $fhe_type:snake _eq>]($c, $cks);
                [<bench_ $fhe_type:snake _flip>]($c, $cks);
                [<bench_ $fhe_type:snake _ge>]($c, $cks);
                [<bench_ $fhe_type:snake _gt>]($c, $cks);
                [<bench_ $fhe_type:snake _if_then_else>]($c, $cks);
                [<bench_ $fhe_type:snake _ilog2>]($c, $cks);
                [<bench_ $fhe_type:snake _is_even>]($c, $cks);
                [<bench_ $fhe_type:snake _is_odd>]($c, $cks);
                [<bench_ $fhe_type:snake _le>]($c, $cks);
                [<bench_ $fhe_type:snake _leading_ones>]($c, $cks);
                [<bench_ $fhe_type:snake _leading_zeros>]($c, $cks);
                [<bench_ $fhe_type:snake _lt>]($c, $cks);
                [<bench_ $fhe_type:snake _max>]($c, $cks);
                [<bench_ $fhe_type:snake _min>]($c, $cks);
                [<bench_ $fhe_type:snake _mul>]($c, $cks);
                [<bench_ $fhe_type:snake _ne>]($c, $cks);
                [<bench_ $fhe_type:snake _neg>]($c, $cks);
                [<bench_ $fhe_type:snake _not>]($c, $cks);
                [<bench_ $fhe_type:snake _overflowing_add>]($c, $cks);
                [<bench_ $fhe_type:snake _overflowing_mul>]($c, $cks);
                [<bench_ $fhe_type:snake _overflowing_neg>]($c, $cks);
                [<bench_ $fhe_type:snake _overflowing_sub>]($c, $cks);
                [<bench_ $fhe_type:snake _rem>]($c, $cks);
                [<bench_ $fhe_type:snake _reverse_bits>]($c, $cks);
                [<bench_ $fhe_type:snake _rotate_left>]($c, $cks);
                [<bench_ $fhe_type:snake _rotate_right>]($c, $cks);
                [<bench_ $fhe_type:snake _shl>]($c, $cks);
                [<bench_ $fhe_type:snake _shr>]($c, $cks);
                [<bench_ $fhe_type:snake _sub>]($c, $cks);
                [<bench_ $fhe_type:snake _sum>]($c, $cks);
                [<bench_ $fhe_type:snake _trailing_ones>]($c, $cks);
                [<bench_ $fhe_type:snake _trailing_zeros>]($c, $cks);
            }
        )+
    };
}

macro_rules! run_benches_dedup {
    (
        $c:expr,
        $cks:expr,
        $($fhe_type:ident),
        + $(,)?
    ) => {
        $(
            ::paste::paste! {
                [<bench_ $fhe_type:snake _add>]($c, $cks);
                [<bench_ $fhe_type:snake _bitand>]($c, $cks);
                [<bench_ $fhe_type:snake _checked_ilog2>]($c, $cks);
                [<bench_ $fhe_type:snake _count_ones>]($c, $cks);
                [<bench_ $fhe_type:snake _div_rem>]($c, $cks);
                [<bench_ $fhe_type:snake _eq>]($c, $cks);
                [<bench_ $fhe_type:snake _flip>]($c, $cks);
                [<bench_ $fhe_type:snake _gt>]($c, $cks);
                [<bench_ $fhe_type:snake _if_then_else>]($c, $cks);
                [<bench_ $fhe_type:snake _ilog2>]($c, $cks);
                [<bench_ $fhe_type:snake _is_even>]($c, $cks);
                [<bench_ $fhe_type:snake _leading_zeros>]($c, $cks);
                [<bench_ $fhe_type:snake _max>]($c, $cks);
                [<bench_ $fhe_type:snake _mul>]($c, $cks);
                [<bench_ $fhe_type:snake _neg>]($c, $cks);
                [<bench_ $fhe_type:snake _not>]($c, $cks);
                [<bench_ $fhe_type:snake _overflowing_add>]($c, $cks);
                [<bench_ $fhe_type:snake _overflowing_mul>]($c, $cks);
                [<bench_ $fhe_type:snake _overflowing_neg>]($c, $cks);
                [<bench_ $fhe_type:snake _reverse_bits>]($c, $cks);
                [<bench_ $fhe_type:snake _rotate_left>]($c, $cks);
                [<bench_ $fhe_type:snake _shl>]($c, $cks);
                [<bench_ $fhe_type:snake _sum>]($c, $cks);
            }
        )+
    };
}

macro_rules! run_scalar_benches {
    (
        $c:expr,
        $cks:expr,
        $($fhe_type:ident),
        + $(,)?
    ) => {
        $(
            ::paste::paste! {
                [<bench_ $fhe_type:snake _scalar_add>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_bitand>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_bitor>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_bitxor>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_div>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_eq>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_ge>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_gt>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_le>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_lt>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_max>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_min>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_mul>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_ne>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_overflowing_add>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_overflowing_sub>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_rem>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_rotate_left>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_rotate_right>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_shl>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_shr>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_sub>]($c, $cks);
            }
        )+
    };
}

macro_rules! run_scalar_benches_dedup {
    (
        $c:expr,
        $cks:expr,
        $($fhe_type:ident),
        + $(,)?
    ) => {
        $(
            ::paste::paste! {
                [<bench_ $fhe_type:snake _scalar_add>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_bitand>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_div>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_eq>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_gt>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_max>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_mul>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_overflowing_add>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_rem>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_rotate_left>]($c, $cks);
                [<bench_ $fhe_type:snake _scalar_shl>]($c, $cks);
            }
        )+
    };
}
