use benchmark::high_level_api::bench_wait::*;
use benchmark::high_level_api::benchmark_op::*;

use benchmark::utilities::{hlapi_throughput_num_ops, write_to_json, BenchmarkType, OperatorType};
use criterion::{black_box, Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use std::marker::PhantomData;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::integer::block_decomposition::DecomposableInto;
use tfhe::keycache::NamedParam;
use tfhe::named::Named;
use tfhe::prelude::*;
use tfhe::{ClientKey, FheIntegerType, FheUintId, IntegerId, KVStore};

pub fn bench_fhe_type_op<FheType, Op>(
    c: &mut Criterion,
    client_key: &ClientKey,
    type_name: &str,
    bit_size: usize,
    display_name: &str,
    func_name: &str,
    op: Op,
) where
    Op: BenchmarkOp<FheType>,
    FheType: FheWait,
{
    let mut bench_group = c.benchmark_group(type_name);
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
    let bit_size = bit_size as u32;

    let inputs = op.setup_inputs(client_key, &mut rng);
    let bench_id = format!("{bench_prefix}::{func_name}::{param_name}::{type_name}");

    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = op.execute(&inputs);
            res.wait_bench();
            black_box(res)
        })
    });

    write_to_json::<u64, _>(
        &bench_id,
        param,
        &param_name,
        display_name,
        &OperatorType::Atomic,
        bit_size,
        vec![],
    );
}

macro_rules! bench_type_binary_op {
    (type_name: $fhe_type:ident, right_type_name: $fhe_right_type:ident,left_type: $left_type:ty, right_type: $right_type:ty, display_name: $display_name:literal, operation: $op:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    $display_name,
                    stringify!($op),
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
            fn [<bench_ $fhe_type:snake _scalar_ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    $display_name,
                    stringify!($op),
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
    (type_name: $fhe_type:ident, integer_type: $integer_type:ty, display_name: $display_name:literal, operation: $op:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    $display_name,
                    stringify!($op),
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
    (type_name: $fhe_type:ident, integer_type: $integer_type:ty, display_name: $display_name:literal, operation: $op:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    $display_name,
                    stringify!($op),
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
    (type_name: $fhe_type:ident, integer_type: $integer_type:ty, display_name: $display_name:literal, operation: $op:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op(
                    c,
                    cks,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    $display_name,
                    stringify!($op),
                    ArrayOp {
                        func: |iter: std::iter::Cloned<std::slice::Iter<'_, $fhe_type>>| iter.$op(),
                        array_size: 10,
                        _encrypt: PhantomData::<$integer_type>,
                    }
                );
            }
        }
    };
}

macro_rules! generate_typed_benches {
    ($fhe_type:ident, $integer_type:ty) => {
        // bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "bitnot", operation: bitnot);
        bench_type_array_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "sum", operation: sum);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "add", operation: add);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "bitand", operation: bitand);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "bitor", operation: bitor);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "bitxor", operation: bitxor);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "div", operation: div);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "div_rem", operation: div_rem);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "eq", operation: eq);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "ge", operation: ge);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "gt", operation: gt);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "le", operation: le);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: FheUint8, left_type: $integer_type, right_type: u8, display_name: "left_rotate", operation: rotate_left);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: FheUint8, left_type: $integer_type, right_type: u8, display_name: "left_shift", operation: shl);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "lt", operation: lt);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "max", operation: max);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "min", operation: min);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "mul", operation: mul);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "ne", operation: ne);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "overflowing_add", operation: overflowing_add);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "overflowing_mul", operation: overflowing_mul);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "overflowing_sub", operation: overflowing_sub);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "rem", operation: rem);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: FheUint8, left_type: $integer_type, right_type: u8, display_name: "right_rotate", operation: rotate_right);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: FheUint8, left_type: $integer_type, right_type: u8, display_name: "right_shift", operation: shr);
        bench_type_binary_op!(type_name: $fhe_type, right_type_name: $fhe_type, left_type: $integer_type, right_type: $integer_type, display_name: "sub", operation: sub);
        bench_type_ternary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "flip", operation: flip);
        bench_type_ternary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "if_then_else", operation: if_then_else);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "checked_ilog2", operation: checked_ilog2);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "count_ones", operation: count_ones);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "count_zeros", operation: count_zeros);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "ilog2", operation: ilog2);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "is_even", operation: is_even);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "is_odd", operation: is_odd);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "leading_ones", operation: leading_ones);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "leading_zeros", operation: leading_zeros);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "neg", operation: neg);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "not", operation: not);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "overflowing_neg", operation: overflowing_neg);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "reverse_bits", operation: reverse_bits);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "trailing_ones", operation: trailing_ones);
        bench_type_unary_op!(type_name: $fhe_type, integer_type: $integer_type, display_name: "trailing_zeros", operation: trailing_zeros);
    };
}

macro_rules! generate_typed_scalar_benches {
    ($fhe_type:ident, $integer_type:ty, $scalar_ty:ty, $specific_ty:ty) => {
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "add_scalar", operation: add, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "bitand_scalar", operation: bitand, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "bitor_scalar", operation: bitor, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "bitxor_scalar", operation: bitxor, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "div_scalar", operation: div, rng: || random_non_zero::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "eq_scalar", operation: eq, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "ge_scalar", operation: ge, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "gt_scalar", operation: gt, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "le_scalar", operation: le, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "lt_scalar", operation: lt, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "max_scalar", operation: max, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "min_scalar", operation: min, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "mul_scalar", operation: mul, rng: || random_not_power_of_two::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "ne_scalar", operation: ne, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "overflowing_add_scalar", operation: overflowing_add, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "overflowing_sub_scalar", operation: overflowing_sub, rng: || random::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "rem_scalar", operation: rem, rng: || random_non_zero::<$scalar_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $specific_ty, display_name: "rotate_left_scalar", operation: rotate_left, rng: || random::<$specific_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $specific_ty, display_name: "rotate_right_scalar", operation: rotate_right, rng: || random::<$specific_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $specific_ty, display_name: "shift_left_scalar", operation: shl, rng: || get_one::<$specific_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $specific_ty, display_name: "shift_right_scalar", operation: shr, rng: || get_one::<$specific_ty>());
        bench_type_binary_scalar_op!(type_name: $fhe_type, integer_type: $integer_type, scalar_type: $scalar_ty, display_name: "sub_scalar", operation: sub, rng: || random::<$scalar_ty>());
    };
}

// Generate benches for all FheUint types
// generate_typed_benches!(FheUint2, u128);
// generate_typed_benches!(FheUint4, u128);
// generate_typed_benches!(FheUint8, u128);
// generate_typed_benches!(FheUint16, u128);
// generate_typed_benches!(FheUint32, u128);
// generate_typed_benches!(FheUint64, u128);
// generate_typed_benches!(FheUint128, u128);

// generate_typed_benches!(FheInt2, i128);
// generate_typed_benches!(FheInt4, i128);
// generate_typed_benches!(FheInt8, i128);
// generate_typed_benches!(FheInt16, i128);
// generate_typed_benches!(FheInt32, i128);
// generate_typed_benches!(FheInt64, i128);
// generate_typed_benches!(FheInt128, i128);

// generate_typed_scalar_benches!(FheUint2, u128, u8, u8);
// generate_typed_scalar_benches!(FheUint4, u128, u8, u8);
// generate_typed_scalar_benches!(FheUint8, u128, u8, u8);
// generate_typed_scalar_benches!(FheUint16, u128, u16, u16);
// generate_typed_scalar_benches!(FheUint32, u128, u32, u32);
// generate_typed_scalar_benches!(FheUint64, u128, u64, u64);
// generate_typed_scalar_benches!(FheUint128, u128, u128, u128);

// generate_typed_scalar_benches!(FheInt2, i128, i8, u8);
// generate_typed_scalar_benches!(FheInt4, i128, i8, u8);
// generate_typed_scalar_benches!(FheInt8, i128, i8, u8);
// generate_typed_scalar_benches!(FheInt16, i128, i16, u16);
// generate_typed_scalar_benches!(FheInt32, i128, i32, u32);
// generate_typed_scalar_benches!(FheInt64, i128, i64, u64);
// generate_typed_scalar_benches!(FheInt128, i128, i128, u128);

macro_rules! run_benches {
    ($c:expr, $cks:expr, $($fhe_type:ident),+ $(,)?) => {
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

macro_rules! run_scalar_benches {
    ($c:expr, $cks:expr, $($fhe_type:ident),+ $(,)?) => {
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

pub(crate) trait TypeDisplay {
    fn fmt(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = std::any::type_name::<Self>();
        let pos = name.rfind(":").map_or(0, |p| p + 1);
        write!(f, "{}", &name[pos..])
    }
}

impl TypeDisplay for u8 {}
impl TypeDisplay for u16 {}
impl TypeDisplay for u32 {}
impl TypeDisplay for u64 {}
impl TypeDisplay for u128 {}

impl TypeDisplay for i8 {}
impl TypeDisplay for i16 {}
impl TypeDisplay for i32 {}
impl TypeDisplay for i64 {}
impl TypeDisplay for i128 {}

impl<Id: FheUintId> TypeDisplay for tfhe::FheUint<Id> {
    fn fmt(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_fhe_type_name::<Self>(f)
    }
}

impl<Id: tfhe::FheIntId> TypeDisplay for tfhe::FheInt<Id> {
    fn fmt(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_fhe_type_name::<Self>(f)
    }
}

struct TypeDisplayer<T: TypeDisplay>(PhantomData<T>);

impl<T: TypeDisplay> Default for TypeDisplayer<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: TypeDisplay> std::fmt::Display for TypeDisplayer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        T::fmt(f)
    }
}

fn write_fhe_type_name<'a, FheType>(f: &mut std::fmt::Formatter<'a>) -> std::fmt::Result
where
    FheType: FheIntegerType + Named,
{
    let full_name = FheType::NAME;
    let i = full_name.rfind(":").map_or(0, |p| p + 1);

    write!(f, "{}{}", &full_name[i..], FheType::Id::num_bits())
}

pub fn bench_kv_store<Key, FheKey, Value>(c: &mut Criterion, cks: &ClientKey, num_elements: usize)
where
    rand::distributions::Standard: rand::distributions::Distribution<Key>,
    Key: Numeric + DecomposableInto<u64> + Ord + CastInto<usize> + TypeDisplay,
    Value: FheEncrypt<u128, ClientKey> + FheIntegerType + Clone + Send + Sync + TypeDisplay,
    Value::Id: FheUintId,
    FheKey: FheEncrypt<Key, ClientKey> + FheIntegerType + Send + Sync,
    FheKey::Id: FheUintId,
{
    let mut bench_group = c.benchmark_group("kv_store");
    bench_group.sample_size(10);

    let mut kv_store = KVStore::new();
    let mut rng = rand::thread_rng();

    let format_id_bench = |op_name: &str| -> String {
        format!(
            "hlapi::kv_store::<{}, {}>::{op_name}/{num_elements}",
            TypeDisplayer::<Key>::default(),
            TypeDisplayer::<Value>::default(),
        )
    };

    match BenchmarkType::from_env().unwrap() {
        BenchmarkType::Latency => {
            while kv_store.len() != num_elements {
                let key = rng.gen::<Key>();
                let value = rng.gen::<u128>();

                let encrypted_value = Value::encrypt(value, cks);
                kv_store.insert_with_clear_key(key, encrypted_value);
            }

            let key = rng.gen::<Key>();
            let encrypted_key = FheKey::encrypt(key, cks);

            let value = rng.gen::<u128>();
            let value_to_add = Value::encrypt(value, cks);

            bench_group.bench_function(format_id_bench("get"), |b| {
                b.iter(|| {
                    let _ = kv_store.get(&encrypted_key);
                })
            });

            bench_group.bench_function(format_id_bench("update"), |b| {
                b.iter(|| {
                    let _ = kv_store.update(&encrypted_key, &value_to_add);
                })
            });

            bench_group.bench_function(format_id_bench("map"), |b| {
                b.iter(|| {
                    kv_store.map(&encrypted_key, |v| v);
                })
            });
        }
        BenchmarkType::Throughput => {
            while kv_store.len() != num_elements {
                let key = rng.gen::<Key>();
                let value = rng.gen::<u128>();

                let encrypted_value = Value::encrypt(value, cks);
                kv_store.insert_with_clear_key(key, encrypted_value);
            }

            let key = rng.gen::<Key>();
            let encrypted_key = FheKey::encrypt(key, cks);

            let value = rng.gen::<u128>();
            let value_to_add = Value::encrypt(value, cks);

            let factor = hlapi_throughput_num_ops(
                || {
                    kv_store.map(&encrypted_key, |v| v);
                },
                cks,
            );

            let mut kv_stores = vec![];
            for _ in 0..factor.saturating_sub(1) {
                kv_stores.push(kv_store.clone());
            }
            kv_stores.push(kv_store);

            bench_group.throughput(Throughput::Elements(kv_stores.len() as u64));

            bench_group.bench_function(format_id_bench("map::throughput"), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.map(&encrypted_key, |v| v);
                    })
                })
            });

            bench_group.bench_function(format_id_bench("update::throughput"), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.update(&encrypted_key, &value_to_add);
                    })
                })
            });

            bench_group.bench_function(format_id_bench("get::throughput"), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.get(&encrypted_key);
                    })
                })
            });
        }
    }
    bench_group.finish();
}
