use benchmark::high_level_api::bench_wait::*;
use benchmark::high_level_api::benchmark_op::*;
use benchmark::utilities::{
    get_bench_type, will_this_bench_run, write_to_json, BenchmarkType, OperandType, OperatorType,
};
use criterion::{black_box, Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::ClientKey;

pub struct BenchConfig<'a> {
    pub type_name: &'a str,
    pub display_name: &'a str,
    pub operand_type: OperandType,
    pub func_name: &'a str,
    pub bit_size: usize,
}

#[inline(never)]
pub fn bench_fhe_type_op<FheType, Op>(
    c: &mut Criterion,
    client_key: &ClientKey,
    config: BenchConfig,
    op: Op,
) where
    Op: BenchmarkOp<FheType> + Sync,
    FheType: FheWait + Send + Sync,
{
    let group_name = config.type_name;
    let mut bench_group = c.benchmark_group(group_name);
    let mut bench_prefix = "hlapi".to_string();
    if cfg!(feature = "gpu") {
        bench_prefix = format!("{}::cuda", bench_prefix);
    } else if cfg!(feature = "hpu") {
        bench_prefix = format!("{}::hpu", bench_prefix);
    }

    bench_prefix = format!("{}::ops", bench_prefix);

    let mut rng = thread_rng();

    let param = client_key.computation_parameters();
    let param_name = param.name();
    let bit_size = config.bit_size as u32;

    let inputs = op.setup_inputs(client_key, &mut rng);
    let bench_id;

    match get_bench_type() {
        BenchmarkType::Latency => {
            bench_id = match config.operand_type {
                OperandType::PlainText => {
                    format!(
                        "{bench_prefix}::{}::{param_name}::scalar::{}",
                        config.func_name, config.type_name
                    )
                }
                OperandType::CipherText => {
                    format!(
                        "{bench_prefix}::{}::{param_name}::{}",
                        config.func_name, config.type_name
                    )
                }
            };
            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    let res = op.execute(&inputs);
                    res.wait_bench();
                    black_box(res)
                })
            });
        }
        BenchmarkType::Throughput => {
            bench_id = match config.operand_type {
                OperandType::PlainText => {
                    format!(
                        "{bench_prefix}::{}::throughput::{param_name}::scalar::{}",
                        config.func_name, config.type_name
                    )
                }
                OperandType::CipherText => {
                    format!(
                        "{bench_prefix}::{}::throughput::{param_name}::{}",
                        config.func_name, config.type_name
                    )
                }
            };

            let elements = if will_this_bench_run(group_name, &bench_id) {
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
                    use benchmark::high_level_api::find_optimal_batch::find_optimal_batch;
                    let setup = |batch_size: usize| {
                        (0..batch_size)
                            .into_par_iter()
                            .map(|_| op.setup_inputs(client_key, &mut thread_rng()))
                            .collect::<Vec<_>>()
                    };
                    let run = |inputs: &Vec<_>, batch_size: usize| {
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
                let setup_encrypted_inputs = || {
                    (0..elements)
                        .into_par_iter()
                        .map(|_| op.setup_inputs(client_key, &mut thread_rng()))
                        .collect::<Vec<_>>()
                };
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
        &bench_id,
        param,
        &param_name,
        config.display_name,
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
        display_name: $display_name:literal,
        operation: $op:ident
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    BenchConfig {
                        type_name: stringify!($fhe_type),
                        bit_size: $fhe_type::num_bits(),
                        display_name: $display_name,
                        operand_type: OperandType::CipherText,
                        func_name: stringify!($op),
                    },
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
        display_name: $display_name:literal,
        operation: $op:ident,
        rng: $rng_fn:expr
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<bench_ $fhe_type:snake _scalar_ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    BenchConfig {
                        type_name: stringify!($fhe_type),
                        bit_size: $fhe_type::num_bits(),
                        display_name: $display_name,
                        operand_type: OperandType::PlainText,
                        func_name: stringify!($op),
                    },
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
        display_name: $display_name:literal,
        operation: $op:ident
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    BenchConfig {
                        type_name: stringify!($fhe_type),
                        bit_size: $fhe_type::num_bits(),
                        display_name: $display_name,
                        operand_type: OperandType::CipherText,
                        func_name: stringify!($op),
                    },
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
        display_name: $display_name:literal,
        operation: $op:ident
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    BenchConfig {
                        type_name: stringify!($fhe_type),
                        bit_size: $fhe_type::num_bits(),
                        display_name: $display_name,
                        operand_type: OperandType::CipherText,
                        func_name: stringify!($op),
                    },
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
        display_name: $display_name:literal,
        operation: $op:ident
    ) => {
        ::paste::paste! {
            #[inline(never)]
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    BenchConfig {
                        type_name: stringify!($fhe_type),
                        bit_size: $fhe_type::num_bits(),
                        display_name: $display_name,
                        operand_type: OperandType::CipherText,
                        func_name: stringify!($op),
                    },
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
            display_name: "sum",
            operation: sum
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "add",
            operation:
            add
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "bitand",
            operation: bitand
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "bitor",
            operation: bitor
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "bitxor",
            operation: bitxor
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "div",
            operation: div
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "div_rem",
            operation: div_rem
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "eq",
            operation: eq
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "ge",
            operation: ge
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "gt",
            operation: gt
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "le",
            operation: le
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: FheUint8,
            left_type: $integer_type,
            right_type: u8,
            display_name: "left_rotate",
            operation: rotate_left
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: FheUint8,
            left_type: $integer_type,
            right_type: u8,
            display_name: "left_shift",
            operation: shl
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "lt",
            operation: lt
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "max",
            operation: max
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "min",
            operation: min
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "mul",
            operation: mul
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "ne",
            operation: ne
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "overflowing_add",
            operation: overflowing_add
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "overflowing_mul",
            operation: overflowing_mul
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "overflowing_sub",
            operation: overflowing_sub
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "rem",
            operation: rem
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: FheUint8,
            left_type: $integer_type,
            right_type: u8,
            display_name: "right_rotate",
            operation: rotate_right
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: FheUint8,
            left_type: $integer_type,
            right_type: u8,
            display_name: "right_shift",
            operation: shr
        );
        bench_type_binary_op!(
            type_name: $fhe_type,
            right_type_name: $fhe_type,
            left_type: $integer_type,
            right_type: $integer_type,
            display_name: "sub",
            operation: sub
        );
        bench_type_ternary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "flip",
            operation: flip
        );
        bench_type_ternary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "if_then_else",
            operation: if_then_else
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "checked_ilog2",
            operation: checked_ilog2
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "count_ones",
            operation: count_ones
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "count_zeros",
            operation: count_zeros
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "ilog2",
            operation: ilog2
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "is_even",
            operation: is_even
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "is_odd",
            operation: is_odd
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "leading_ones",
            operation: leading_ones
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "leading_zeros",
            operation: leading_zeros
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "neg",
            operation: neg
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "not",
            operation: not
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "overflowing_neg",
            operation: overflowing_neg
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "reverse_bits",
            operation: reverse_bits
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "trailing_ones",
            operation: trailing_ones
        );
        bench_type_unary_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            display_name: "trailing_zeros",
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
            display_name: "add",
            operation: add,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "bitand",
            operation: bitand,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "bitor",
            operation: bitor,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "bitxor",
            operation: bitxor,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "div",
            operation: div,
            rng: || random_non_zero::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "eq",
            operation: eq,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "ge",
            operation: ge,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "gt",
            operation: gt,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "le",
            operation: le,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "lt",
            operation: lt,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "max",
            operation: max,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "min",
            operation: min,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "mul",
            operation: mul,
            rng: || random_not_power_of_two::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "ne",
            operation: ne,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "overflowing_add",
            operation: overflowing_add,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "overflowing_sub",
            operation: overflowing_sub,
            rng: || rand::random::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "rem",
            operation: rem,
            rng: || random_non_zero::<$scalar_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $specific_ty,
            display_name: "rotate_left",
            operation: rotate_left,
            rng: || rand::random::<$specific_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $specific_ty,
            display_name: "rotate_right",
            operation: rotate_right,
            rng: || rand::random::<$specific_ty>()
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $specific_ty,
            display_name: "shift_left",
            operation: shl,
            rng: || <$specific_ty>::ONE
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $specific_ty,
            display_name: "shift_right",
            operation: shr,
            rng: || <$specific_ty>::ONE
        );
        bench_type_binary_scalar_op!(
            type_name: $fhe_type,
            integer_type: $integer_type,
            scalar_type: $scalar_ty,
            display_name: "sub",
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
