#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, EnvConfig, OperatorType};
use criterion::{criterion_group, Criterion};
use itertools::iproduct;
use rand::prelude::*;
use std::env;
use std::vec::IntoIter;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::{IntegerKeyKind, RadixCiphertext, ServerKey, SignedRadixCiphertext, I256};
use tfhe::keycache::NamedParam;
#[cfg(feature = "gpu")]
use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
#[cfg(not(feature = "gpu"))]
use tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS;

fn gen_random_i256(rng: &mut ThreadRng) -> I256 {
    let clearlow = rng.gen::<u128>();
    let clearhigh = rng.gen::<u128>();

    tfhe::integer::I256::from((clearlow, clearhigh))
}

/// An iterator that yields a succession of combinations
/// of parameters and a num_block to achieve a certain bit_size ciphertext
/// in radix decomposition
struct ParamsAndNumBlocksIter {
    params_and_bit_sizes:
        itertools::Product<IntoIter<tfhe::shortint::PBSParameters>, IntoIter<usize>>,
}

impl Default for ParamsAndNumBlocksIter {
    fn default() -> Self {
        let env_config = EnvConfig::new();

        if env_config.is_multi_bit {
            #[cfg(feature = "gpu")]
            let params = vec![PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS.into()];
            #[cfg(not(feature = "gpu"))]
            let params = vec![PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS.into()];

            let params_and_bit_sizes = iproduct!(params, env_config.bit_sizes());
            Self {
                params_and_bit_sizes,
            }
        } else {
            // FIXME One set of parameter is tested since we want to benchmark only quickest
            // operations.
            let params = vec![
                PARAM_MESSAGE_2_CARRY_2_KS_PBS.into(),
                // PARAM_MESSAGE_3_CARRY_3_KS_PBS.into(),
                // PARAM_MESSAGE_4_CARRY_4_KS_PBS.into(),
            ];

            let params_and_bit_sizes = iproduct!(params, env_config.bit_sizes());
            Self {
                params_and_bit_sizes,
            }
        }
    }
}

impl Iterator for ParamsAndNumBlocksIter {
    type Item = (tfhe::shortint::PBSParameters, usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let (param, bit_size) = self.params_and_bit_sizes.next()?;
        let num_block =
            (bit_size as f64 / param.message_modulus().0.ilog2() as f64).ceil() as usize;

        Some((param, num_block, bit_size))
    }
}

/// Base function to bench a server key function that is a binary operation, input ciphertext will
/// contain only zero carries
fn bench_server_key_signed_binary_function_clean_inputs<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
    sample_size: usize,
) where
    F: Fn(&ServerKey, &SignedRadixCiphertext, &SignedRadixCiphertext),
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(sample_size)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_two_values = || {
                let ct_0 = cks.encrypt_signed_radix(gen_random_i256(&mut rng), num_block);
                let ct_1 = cks.encrypt_signed_radix(gen_random_i256(&mut rng), num_block);

                (ct_0, ct_1)
            };

            b.iter_batched(
                encrypt_two_values,
                |(ct_0, ct_1)| {
                    binary_op(&sks, &ct_0, &ct_1);
                },
                criterion::BatchSize::SmallInput,
            )
        });

        write_to_json::<u64, _>(
            &bench_id,
            param,
            param.name(),
            display_name,
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_block],
        );
    }

    bench_group.finish()
}

/// Shifts and rotations require a special function as the rhs,
/// i.e. the shift amount has to be a positive radix type.
fn bench_server_key_signed_shift_function_clean_inputs<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
) where
    F: Fn(&ServerKey, &SignedRadixCiphertext, &RadixCiphertext),
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_two_values = || {
                let clear_1 = rng.gen_range(0u128..bit_size as u128);

                let ct_0 = cks.encrypt_signed_radix(gen_random_i256(&mut rng), num_block);
                let ct_1 = cks.encrypt_radix(clear_1, num_block);

                (ct_0, ct_1)
            };

            b.iter_batched(
                encrypt_two_values,
                |(ct_0, ct_1)| {
                    binary_op(&sks, &ct_0, &ct_1);
                },
                criterion::BatchSize::SmallInput,
            )
        });

        write_to_json::<u64, _>(
            &bench_id,
            param,
            param.name(),
            display_name,
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_block],
        );
    }

    bench_group.finish()
}

/// Base function to bench a server key function that is a unary operation, input ciphertext will
/// contain only zero carries
fn bench_server_key_unary_function_clean_inputs<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    unary_fn: F,
) where
    F: Fn(&ServerKey, &SignedRadixCiphertext),
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_one_value =
                || cks.encrypt_signed_radix(gen_random_i256(&mut rng), num_block);

            b.iter_batched(
                encrypt_one_value,
                |ct_0| {
                    unary_fn(&sks, &ct_0);
                },
                criterion::BatchSize::SmallInput,
            )
        });

        write_to_json::<u64, _>(
            &bench_id,
            param,
            param.name(),
            display_name,
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_block],
        );
    }

    bench_group.finish()
}

fn signed_if_then_else_parallelized(c: &mut Criterion) {
    let bench_name = "integer::signed::if_then_else_parallelized";
    let display_name = "if_then_else";

    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_tree_values = || {
                let ct_0 = cks.encrypt_signed_radix(gen_random_i256(&mut rng), num_block);
                let ct_1 = cks.encrypt_signed_radix(gen_random_i256(&mut rng), num_block);

                let cond = sks.create_trivial_boolean_block(rng.gen_bool(0.5));

                (cond, ct_0, ct_1)
            };

            b.iter_batched(
                encrypt_tree_values,
                |(condition, true_ct, false_ct)| {
                    sks.if_then_else_parallelized(&condition, &true_ct, &false_ct)
                },
                criterion::BatchSize::SmallInput,
            )
        });

        write_to_json::<u64, _>(
            &bench_id,
            param,
            param.name(),
            display_name,
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_block],
        );
    }

    bench_group.finish()
}

macro_rules! define_server_key_bench_binary_signed_clean_inputs_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident $(,)?) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_signed_binary_function_clean_inputs(
                c,
                concat!("integer::signed::", stringify!($server_key_method)),
                stringify!($name),
                |server_key, lhs, rhs| {
                    server_key.$server_key_method(lhs, rhs);
                },
                15 /* sample_size */
            )
        }
    };
    (
        method_name: $server_key_method:ident,
        display_name:$name:ident,
        sample_size: $sample_size:expr $(,)?
    ) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_signed_binary_function_clean_inputs(
                c,
                concat!("integer::signed::", stringify!($server_key_method)),
                stringify!($name),
                |server_key, lhs, rhs| {
                    server_key.$server_key_method(lhs, rhs);
                },
                $sample_size
            )
        }
    }
);

macro_rules! define_server_key_bench_unary_signed_clean_input_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident $(,)?) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_unary_function_clean_inputs(
                c,
                concat!("integer::signed::", stringify!($server_key_method)),
                stringify!($name),
                |server_key, lhs| {
                    server_key.$server_key_method(lhs);
                },
            )
        }
    };
);

define_server_key_bench_unary_signed_clean_input_fn!(
    method_name: neg_parallelized,
    display_name: negation
);
define_server_key_bench_unary_signed_clean_input_fn!(
    method_name: abs_parallelized,
    display_name: abs
);
define_server_key_bench_unary_signed_clean_input_fn!(method_name: leading_zeros_parallelized, display_name: leading_zeros);
define_server_key_bench_unary_signed_clean_input_fn!(method_name: leading_ones_parallelized, display_name: leading_ones);
define_server_key_bench_unary_signed_clean_input_fn!(method_name: trailing_zeros_parallelized, display_name: trailing_zeros);
define_server_key_bench_unary_signed_clean_input_fn!(method_name: trailing_ones_parallelized, display_name: trailing_ones);
define_server_key_bench_unary_signed_clean_input_fn!(method_name: ilog2_parallelized, display_name: ilog2);
define_server_key_bench_unary_signed_clean_input_fn!(method_name: checked_ilog2_parallelized, display_name: checked_ilog2);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: add_parallelized,
    display_name: add
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: signed_overflowing_add_parallelized,
    display_name: overflowing_add
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: sub_parallelized,
    display_name: sub
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: signed_overflowing_sub_parallelized,
    display_name: overflowing_sub
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: mul_parallelized,
    display_name: mul
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: signed_overflowing_mul_parallelized,
    display_name: overflowing_mul
);
// define_server_key_bench_binary_signed_clean_inputs_fn!(
//     method_name: div_parallelized,
//     display_name: div,
//     sample_size:10
// );
// define_server_key_bench_binary_signed_clean_inputs_fn!(
//     method_name: rem_parallelized,
//     display_name: modulo,
//     sample_size:10
// );
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: div_rem_parallelized,
    display_name: div_mod,
    sample_size:10
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: bitand_parallelized,
    display_name: bitand
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: bitxor_parallelized,
    display_name: bitxor
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: bitor_parallelized,
    display_name: bitor
);
define_server_key_bench_unary_signed_clean_input_fn!(
    method_name: bitnot,
    display_name: bitnot
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: max_parallelized,
    display_name: max
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: min_parallelized,
    display_name: min
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: eq_parallelized,
    display_name: equal
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: ne_parallelized,
    display_name: not_equal
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: lt_parallelized,
    display_name: less_than
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: le_parallelized,
    display_name: less_or_equal
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: gt_parallelized,
    display_name: greater_than
);
define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: ge_parallelized,
    display_name: greater_or_equal
);

fn left_shift_parallelized(c: &mut Criterion) {
    bench_server_key_signed_shift_function_clean_inputs(
        c,
        concat!("integer::signed::", "left_shift_parallelized"),
        "left_shift",
        |server_key, lhs, rhs| {
            server_key.left_shift_parallelized(lhs, rhs);
        },
    )
}

fn right_shift_parallelized(c: &mut Criterion) {
    bench_server_key_signed_shift_function_clean_inputs(
        c,
        concat!("integer::signed::", "right_shift_parallelized"),
        "right_shift",
        |server_key, lhs, rhs| {
            server_key.right_shift_parallelized(lhs, rhs);
        },
    )
}

fn rotate_left_parallelized(c: &mut Criterion) {
    bench_server_key_signed_shift_function_clean_inputs(
        c,
        concat!("integer::signed::", "rotate_left_parallelized"),
        "rotate_left",
        |server_key, lhs, rhs| {
            server_key.rotate_left_parallelized(lhs, rhs);
        },
    )
}

fn rotate_right_parallelized(c: &mut Criterion) {
    bench_server_key_signed_shift_function_clean_inputs(
        c,
        concat!("integer::signed::", "rotate_right_parallelized"),
        "rotate_right",
        |server_key, lhs, rhs| {
            server_key.rotate_right_parallelized(lhs, rhs);
        },
    )
}

criterion_group!(
    default_parallelized_ops,
    neg_parallelized,
    abs_parallelized,
    add_parallelized,
    signed_overflowing_add_parallelized,
    sub_parallelized,
    signed_overflowing_sub_parallelized,
    mul_parallelized,
    signed_overflowing_mul_parallelized,
    // div_parallelized,
    // rem_parallelized,
    div_rem_parallelized, // For ciphertext div == rem == div_rem
    bitand_parallelized,
    bitnot,
    bitor_parallelized,
    bitxor_parallelized,
    left_shift_parallelized,
    right_shift_parallelized,
    rotate_left_parallelized,
    rotate_right_parallelized,
    leading_zeros_parallelized,
    leading_ones_parallelized,
    trailing_zeros_parallelized,
    trailing_ones_parallelized,
    ilog2_parallelized,
    checked_ilog2_parallelized,
);

criterion_group!(
    default_parallelized_ops_comp,
    max_parallelized,
    min_parallelized,
    eq_parallelized,
    ne_parallelized,
    lt_parallelized,
    le_parallelized,
    gt_parallelized,
    ge_parallelized,
    signed_if_then_else_parallelized,
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_signed_overflowing_add_parallelized,
    display_name: overflowing_add
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_signed_overflowing_sub_parallelized,
    display_name: overflowing_sub
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_mul_parallelized,
    display_name: mul
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_bitand_parallelized,
    display_name: bitand
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_bitor_parallelized,
    display_name: bitand
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_bitxor_parallelized,
    display_name: bitand
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_eq_parallelized,
    display_name: equal
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_ne_parallelized,
    display_name: not_equal
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_le_parallelized,
    display_name: less_or_equal
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_lt_parallelized,
    display_name: less_than
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_ge_parallelized,
    display_name: greater_or_equal
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_gt_parallelized,
    display_name: greater_than
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_max_parallelized,
    display_name: max
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_min_parallelized,
    display_name: min
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_div_rem_parallelized,
    display_name: div_mod,
    sample_size: 10,
);

define_server_key_bench_binary_signed_clean_inputs_fn!(
    method_name: unchecked_div_rem_floor_parallelized,
    display_name: div_mod_floor,
    sample_size: 10,
);

fn unchecked_left_shift_parallelized(c: &mut Criterion) {
    bench_server_key_signed_shift_function_clean_inputs(
        c,
        concat!("integer::signed::", "unchecked_left_shift_parallelized"),
        "left_shift",
        |server_key, lhs, rhs| {
            server_key.unchecked_left_shift_parallelized(lhs, rhs);
        },
    )
}

fn unchecked_right_shift_parallelized(c: &mut Criterion) {
    bench_server_key_signed_shift_function_clean_inputs(
        c,
        concat!("integer::signed::", "unchecked_right_shift_parallelized"),
        "right_shift",
        |server_key, lhs, rhs| {
            server_key.unchecked_right_shift_parallelized(lhs, rhs);
        },
    )
}

fn unchecked_rotate_left_parallelized(c: &mut Criterion) {
    bench_server_key_signed_shift_function_clean_inputs(
        c,
        concat!("integer::signed::", "unchecked_rotate_left_parallelized"),
        "rotate_left",
        |server_key, lhs, rhs| {
            server_key.unchecked_rotate_left_parallelized(lhs, rhs);
        },
    )
}

fn unchecked_rotate_right_parallelized(c: &mut Criterion) {
    bench_server_key_signed_shift_function_clean_inputs(
        c,
        concat!("integer::signed::", "unchecked_rotate_right_parallelized"),
        "rotate_right",
        |server_key, lhs, rhs| {
            server_key.unchecked_rotate_right_parallelized(lhs, rhs);
        },
    )
}

define_server_key_bench_unary_signed_clean_input_fn!(
    method_name: unchecked_abs_parallelized,
    display_name: abs,
);

criterion_group!(
    unchecked_ops,
    unchecked_signed_overflowing_add_parallelized,
    unchecked_signed_overflowing_sub_parallelized,
    unchecked_mul_parallelized,
    unchecked_left_shift_parallelized,
    unchecked_right_shift_parallelized,
    unchecked_rotate_left_parallelized,
    unchecked_rotate_right_parallelized,
    unchecked_bitand_parallelized,
    unchecked_bitor_parallelized,
    unchecked_bitxor_parallelized,
    unchecked_abs_parallelized,
    unchecked_div_rem_parallelized,
    unchecked_div_rem_floor_parallelized,
);

criterion_group!(
    unchecked_ops_comp,
    unchecked_eq_parallelized,
    unchecked_ne_parallelized,
    unchecked_ge_parallelized,
    unchecked_gt_parallelized,
    unchecked_le_parallelized,
    unchecked_lt_parallelized,
    unchecked_max_parallelized,
    unchecked_min_parallelized,
);

//================================================================================
//     Scalar Benches
//================================================================================

type ScalarType = I256;

fn bench_server_key_binary_scalar_function_clean_inputs<F, G>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
    rng_func: G,
) where
    F: Fn(&ServerKey, &mut SignedRadixCiphertext, ScalarType),
    G: Fn(&mut ThreadRng, usize) -> ScalarType,
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        if bit_size > ScalarType::BITS as usize {
            break;
        }
        let param_name = param.name();

        let range = range_for_signed_bit_size(bit_size);

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits_scalar_{bit_size}");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_one_value = || {
                let ct_0 = cks.encrypt_signed_radix(gen_random_i256(&mut rng), num_block);

                let clear_1 = rng_func(&mut rng, bit_size);
                assert!(
                    range.contains(&clear_1),
                    "{:?} is not within the range {:?}",
                    clear_1,
                    range
                );

                (ct_0, clear_1)
            };

            b.iter_batched(
                encrypt_one_value,
                |(mut ct_0, clear_1)| {
                    binary_op(&sks, &mut ct_0, clear_1);
                },
                criterion::BatchSize::SmallInput,
            )
        });

        write_to_json::<u64, _>(
            &bench_id,
            param,
            param.name(),
            display_name,
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_block],
        );
    }

    bench_group.finish()
}

fn range_for_signed_bit_size(bit_size: usize) -> std::ops::RangeInclusive<ScalarType> {
    assert!(bit_size <= ScalarType::BITS as usize);
    assert!(bit_size > 0);
    let modulus = ScalarType::ONE << (bit_size - 1);
    // if clear_bit_size == ScalarType::BITS then modulus==T::MIN
    // -T::MIN = -T::MIN so we sill have our correct lower value
    // (in two's complement which rust uses)
    let lowest = modulus.wrapping_neg();
    // if clear_bit_size == 128 then modulus==T::MIN
    // T::MIN - 1 = T::MAX (in two's complement which rust uses)
    let highest = modulus.wrapping_sub(ScalarType::ONE);

    lowest..=highest
}

/// Creates a bitmask where bit_size bits are 1s, rest are 0s
/// Only works if ScalarType in signed
fn positive_bit_mask_for_bit_size(bit_size: usize) -> ScalarType {
    assert!(bit_size <= ScalarType::BITS as usize);
    assert!(bit_size > 0);
    let minus_one = -ScalarType::ONE; // (In two's complement this is full of 1s)
                                      // The last bit of bit_size can only be set for when value is positive
    let bitmask = (minus_one) >> (ScalarType::BITS as usize - bit_size - 1);
    // flib msb as they would still be one due to '>>' being arithmetic shift
    bitmask ^ ((minus_one) << (bit_size - 1))
}

fn negative_bit_mask_for_bit_size(bit_size: usize) -> ScalarType {
    assert!(bit_size <= ScalarType::BITS as usize);
    assert!(bit_size > 0);
    let minus_one = -ScalarType::ONE; // (In two's complement this is full of 1s)
    let bitmask = (minus_one) >> (ScalarType::BITS as usize - bit_size);
    // flib msb as they would still be one due to '>>' being arithmetic shift
    bitmask ^ ((minus_one) << bit_size)
}

// We have to do this complex stuff because we cannot impl
// rand::distributions::Distribution<I256> because benches are considered out of the crate
// so neither I256 nor rand::distributions::Distribution belong to the benches.
//
// rand::distributions::Distribution can't be implemented in tfhe sources
// in a way that it becomes available to the benches, because rand is a dev dependency
fn gen_random_i256_in_range(rng: &mut ThreadRng, bit_size: usize) -> I256 {
    let value = gen_random_i256(rng);
    if value >= I256::ZERO {
        value & positive_bit_mask_for_bit_size(bit_size)
    } else {
        (value & negative_bit_mask_for_bit_size(bit_size)) | -I256::ONE
    }
}

// Functions used to apply different way of selecting a scalar based on the context.
fn default_scalar(rng: &mut ThreadRng, clear_bit_size: usize) -> ScalarType {
    gen_random_i256_in_range(rng, clear_bit_size)
}

fn shift_scalar(_rng: &mut ThreadRng, _clear_bit_size: usize) -> ScalarType {
    // Shifting by one is the worst case scenario.
    ScalarType::ONE
}

fn div_scalar(rng: &mut ThreadRng, clear_bit_size: usize) -> ScalarType {
    loop {
        let scalar = gen_random_i256_in_range(rng, clear_bit_size);
        if scalar != ScalarType::ZERO {
            return scalar;
        }
    }
}

macro_rules! define_server_key_bench_binary_scalar_clean_inputs_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident, rng_func:$($rng_fn:tt)*) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_binary_scalar_function_clean_inputs(
                c,
                concat!("integer::", stringify!($server_key_method)),
                stringify!($name),
                |server_key, lhs, rhs| {
                    server_key.$server_key_method(lhs, rhs);
                }, $($rng_fn)*)
        }
    }
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_add_parallelized,
    display_name: add,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: signed_overflowing_scalar_add_parallelized,
    display_name: overflowing_add,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_sub_parallelized,
    display_name: sub,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: signed_overflowing_scalar_sub_parallelized,
    display_name: overflowing_sub,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_mul_parallelized,
    display_name: mul,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: signed_scalar_div_parallelized,
    display_name: div,
    rng_func: div_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: signed_scalar_rem_parallelized,
    display_name: modulo,
    rng_func: div_scalar
);
// define_server_key_bench_binary_scalar_clean_inputs_fn!(
//     method_name: signed_scalar_div_rem_parallelized,
//     display_name: div_mod,
//     rng_func: div_scalar
// );
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_bitand_parallelized,
    display_name: bitand,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_bitxor_parallelized,
    display_name: bitxor,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_bitor_parallelized,
    display_name: bitor,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_left_shift_parallelized,
    display_name: left_shift,
    rng_func: shift_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_right_shift_parallelized,
    display_name: right_shift,
    rng_func: shift_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_rotate_left_parallelized,
    display_name: rotate_left,
    rng_func: shift_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_rotate_right_parallelized,
    display_name: rotate_right,
    rng_func: shift_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_max_parallelized,
    display_name: max,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_min_parallelized,
    display_name: min,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_eq_parallelized,
    display_name: equal,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_ne_parallelized,
    display_name: not_equal,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_lt_parallelized,
    display_name: less_than,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_le_parallelized,
    display_name: less_or_equal,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_gt_parallelized,
    display_name: greater_than,
    rng_func: default_scalar
);
define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: scalar_ge_parallelized,
    display_name: greater_or_equal,
    rng_func: default_scalar
);

criterion_group!(
    default_scalar_parallelized_ops,
    scalar_add_parallelized,
    signed_overflowing_scalar_add_parallelized,
    scalar_sub_parallelized,
    signed_overflowing_scalar_sub_parallelized,
    scalar_mul_parallelized,
    signed_scalar_div_parallelized,
    signed_scalar_rem_parallelized, // For scalar rem == div_rem
    // signed_scalar_div_rem_parallelized,
    scalar_bitand_parallelized,
    scalar_bitor_parallelized,
    scalar_bitxor_parallelized,
    scalar_left_shift_parallelized,
    scalar_right_shift_parallelized,
    scalar_rotate_left_parallelized,
    scalar_rotate_right_parallelized,
);

criterion_group!(
    default_scalar_parallelized_ops_comp,
    scalar_max_parallelized,
    scalar_min_parallelized,
    scalar_eq_parallelized,
    scalar_ne_parallelized,
    scalar_lt_parallelized,
    scalar_le_parallelized,
    scalar_gt_parallelized,
    scalar_ge_parallelized,
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_left_shift_parallelized,
    display_name: left_shift,
    rng_func: shift_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_right_shift_parallelized,
    display_name: right_shift,
    rng_func: shift_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_rotate_right_parallelized,
    display_name: rotate_right,
    rng_func: shift_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_rotate_left_parallelized,
    display_name: rotate_left,
    rng_func: shift_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_mul_parallelized,
    display_name: mul,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_bitand_parallelized,
    display_name: bitand,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_bitor_parallelized,
    display_name: bitor,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_bitxor_parallelized,
    display_name: bitxor,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_eq_parallelized,
    display_name: equal,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_ne_parallelized,
    display_name: not_equal,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_le_parallelized,
    display_name: less_or_equal,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_lt_parallelized,
    display_name: less_than,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_ge_parallelized,
    display_name: greater_or_equal,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_gt_parallelized,
    display_name: greater_than,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_max_parallelized,
    display_name: max,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_scalar_min_parallelized,
    display_name: min,
    rng_func: default_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_signed_scalar_div_rem_parallelized,
    display_name: div_mod,
    rng_func: div_scalar
);

define_server_key_bench_binary_scalar_clean_inputs_fn!(
    method_name: unchecked_signed_scalar_div_parallelized,
    display_name: div,
    rng_func: div_scalar
);

criterion_group!(
    unchecked_scalar_ops,
    unchecked_scalar_left_shift_parallelized,
    unchecked_scalar_right_shift_parallelized,
    unchecked_scalar_rotate_right_parallelized,
    unchecked_scalar_rotate_left_parallelized,
    unchecked_scalar_bitand_parallelized,
    unchecked_scalar_bitor_parallelized,
    unchecked_scalar_bitxor_parallelized,
    unchecked_scalar_mul_parallelized,
    unchecked_signed_scalar_div_rem_parallelized,
    unchecked_signed_scalar_div_parallelized,
    unchecked_div_rem_floor_parallelized,
);

criterion_group!(
    unchecked_scalar_ops_comp,
    unchecked_scalar_eq_parallelized,
    unchecked_scalar_ne_parallelized,
    unchecked_scalar_le_parallelized,
    unchecked_scalar_lt_parallelized,
    unchecked_scalar_ge_parallelized,
    unchecked_scalar_gt_parallelized,
    unchecked_scalar_max_parallelized,
    unchecked_scalar_min_parallelized,
);

fn bench_server_key_signed_cast_function<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    cast_op: F,
) where
    F: Fn(&ServerKey, SignedRadixCiphertext, usize),
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));
    let mut rng = rand::thread_rng();

    let env_config = EnvConfig::new();

    for (param, num_blocks, bit_size) in ParamsAndNumBlocksIter::default() {
        let all_num_blocks = env_config
            .bit_sizes()
            .iter()
            .copied()
            .map(|bit| bit.div_ceil(param.message_modulus().0.ilog2() as usize))
            .collect::<Vec<_>>();
        let param_name = param.name();

        for target_num_blocks in all_num_blocks.iter().copied() {
            let target_bit_size = target_num_blocks * param.message_modulus().0.ilog2() as usize;
            let bench_id = format!("{bench_name}::{param_name}::{bit_size}_to_{target_bit_size}");
            bench_group.bench_function(&bench_id, |b| {
                let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                let encrypt_one_value =
                    || cks.encrypt_signed_radix(gen_random_i256(&mut rng), num_blocks);

                b.iter_batched(
                    encrypt_one_value,
                    |ct| {
                        cast_op(&sks, ct, target_num_blocks);
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            write_to_json::<u64, _>(
                &bench_id,
                param,
                param.name(),
                display_name,
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus().0.ilog2(); num_blocks],
            );
        }
    }

    bench_group.finish()
}

macro_rules! define_server_key_bench_cast_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_signed_cast_function(
                c,
                concat!("integer::signed::", stringify!($server_key_method)),
                stringify!($name),
                |server_key, lhs, rhs| {
                    server_key.$server_key_method(lhs, rhs);
            })
        }
    }
);

define_server_key_bench_cast_fn!(method_name: cast_to_unsigned, display_name: cast_to_unsigned);
define_server_key_bench_cast_fn!(method_name: cast_to_signed, display_name: cast_to_signed);

criterion_group!(cast_ops, cast_to_unsigned, cast_to_signed);

#[cfg(feature = "gpu")]
mod cuda {
    use super::*;
    use criterion::criterion_group;
    use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    use tfhe::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    use tfhe::integer::gpu::server_key::CudaServerKey;

    /// Base function to bench a server key function that is a binary operation, input ciphertext
    /// will contain only zero carries
    fn bench_cuda_server_key_binary_signed_function_clean_inputs<F>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        binary_op: F,
    ) where
        F: Fn(
            &CudaServerKey,
            &mut CudaSignedRadixCiphertext,
            &mut CudaSignedRadixCiphertext,
            &CudaStream,
        ),
    {
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));
        let mut rng = rand::thread_rng();

        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            let param_name = param.name();

            let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");

            bench_group.bench_function(&bench_id, |b| {
                let (cks, _cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                let gpu_sks = CudaServerKey::new(&cks, &stream);

                let encrypt_two_values = || {
                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_0 = tfhe::integer::I256::from((clearlow, clearhigh));
                    let ct_0 = cks.encrypt_signed_radix(clear_0, num_block);

                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_1 = tfhe::integer::I256::from((clearlow, clearhigh));
                    let ct_1 = cks.encrypt_signed_radix(clear_1, num_block);

                    let d_ctxt_1 =
                        CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct_0, &stream);
                    let d_ctxt_2 =
                        CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct_1, &stream);

                    (d_ctxt_1, d_ctxt_2)
                };

                b.iter_batched(
                    encrypt_two_values,
                    |(mut ct_0, mut ct_1)| {
                        binary_op(&gpu_sks, &mut ct_0, &mut ct_1, &stream);
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            write_to_json::<u64, _>(
                &bench_id,
                param,
                param.name(),
                display_name,
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus().0.ilog2(); num_block],
            );
        }

        bench_group.finish()
    }

    macro_rules! define_cuda_server_key_bench_clean_input_signed_fn (
        (method_name: $server_key_method:ident, display_name:$name:ident) => {
            ::paste::paste!{
                fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                    bench_cuda_server_key_binary_signed_function_clean_inputs(
                        c,
                        concat!("integer::cuda::signed::", stringify!($server_key_method)),
                        stringify!($name),
                        |server_key, lhs, rhs, stream| {
                            server_key.$server_key_method(lhs, rhs, stream);
                        }
                    )
                }
            }
        }
    );

    /// Base function to bench a server key function that is a unary operation, input ciphertext
    /// will contain only zero carries
    fn bench_cuda_server_key_unary_signed_function_clean_inputs<F>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        unary_op: F,
    ) where
        F: Fn(&CudaServerKey, &mut CudaSignedRadixCiphertext, &CudaStream),
    {
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));
        let mut rng = rand::thread_rng();

        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            let param_name = param.name();

            let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");

            bench_group.bench_function(&bench_id, |b| {
                let (cks, _cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                let gpu_sks = CudaServerKey::new(&cks, &stream);

                let encrypt_one_value = || {
                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear = tfhe::integer::I256::from((clearlow, clearhigh));
                    let ct = cks.encrypt_signed_radix(clear, num_block);

                    CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &stream)
                };

                b.iter_batched(
                    encrypt_one_value,
                    |mut ct| {
                        unary_op(&gpu_sks, &mut ct, &stream);
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            write_to_json::<u64, _>(
                &bench_id,
                param,
                param.name(),
                display_name,
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus().0.ilog2(); num_block],
            );
        }

        bench_group.finish()
    }

    macro_rules! define_cuda_server_key_bench_clean_input_signed_unary_fn (
        (method_name: $server_key_method:ident, display_name:$name:ident) => {
            ::paste::paste!{
                fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                    bench_cuda_server_key_unary_signed_function_clean_inputs(
                        c,
                        concat!("integer::cuda::signed::", stringify!($server_key_method)),
                        stringify!($name),
                        |server_key, input, stream| {
                            server_key.$server_key_method(input, stream);
                        }
                    )
                }
            }
        }
    );

    fn bench_cuda_server_key_binary_scalar_signed_function_clean_inputs<F, G>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        binary_op: F,
        rng_func: G,
    ) where
        F: Fn(&CudaServerKey, &mut CudaSignedRadixCiphertext, ScalarType, &CudaStream),
        G: Fn(&mut ThreadRng, usize) -> ScalarType,
    {
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));
        let mut rng = rand::thread_rng();

        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            if bit_size > ScalarType::BITS as usize {
                break;
            }
            let param_name = param.name();

            let max_value_for_bit_size = ScalarType::MAX >> (ScalarType::BITS as usize - bit_size);

            let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits_scalar_{bit_size}");
            bench_group.bench_function(&bench_id, |b| {
                let (cks, _cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                let gpu_sks = CudaServerKey::new(&cks, &stream);

                let encrypt_one_value = || {
                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_0 = tfhe::integer::I256::from((clearlow, clearhigh));
                    let ct_0 = cks.encrypt_signed_radix(clear_0, num_block);
                    let d_ct_0 =
                        CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct_0, &stream);

                    let clear_1 = rng_func(&mut rng, bit_size) & max_value_for_bit_size;

                    (d_ct_0, clear_1)
                };

                b.iter_batched(
                    encrypt_one_value,
                    |(mut ct_0, clear_1)| {
                        binary_op(&gpu_sks, &mut ct_0, clear_1, &stream);
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            write_to_json::<u64, _>(
                &bench_id,
                param,
                param.name(),
                display_name,
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus().0.ilog2(); num_block],
            );
        }

        bench_group.finish()
    }

    macro_rules! define_cuda_server_key_bench_clean_input_scalar_signed_fn (
        (method_name: $server_key_method:ident, display_name:$name:ident, rng_func:$($rng_fn:tt)*) => {
            ::paste::paste!{
                fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                    bench_cuda_server_key_binary_scalar_signed_function_clean_inputs(
                        c,
                        concat!("integer::cuda::signed::", stringify!($server_key_method)),
                        stringify!($name),
                        |server_key, lhs, rhs, stream| {
                            server_key.$server_key_method(lhs, rhs, stream);
                        },
                        $($rng_fn)*
                    )
                }
            }
        }
    );

    /// Base function to bench a server key function that is a binary operation for shift/rotate,
    /// input ciphertext will contain only zero carries
    fn bench_cuda_server_key_shift_rotate_signed_function_clean_inputs<F>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        binary_op: F,
    ) where
        F: Fn(
            &CudaServerKey,
            &mut CudaSignedRadixCiphertext,
            &mut CudaUnsignedRadixCiphertext,
            &CudaStream,
        ),
    {
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));
        let mut rng = rand::thread_rng();

        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            let param_name = param.name();

            let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");

            bench_group.bench_function(&bench_id, |b| {
                let (cks, _cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                let gpu_sks = CudaServerKey::new(&cks, &stream);

                let encrypt_two_values = || {
                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_0 = tfhe::integer::I256::from((clearlow, clearhigh));
                    let ct_0 = cks.encrypt_signed_radix(clear_0, num_block);

                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_1 = tfhe::integer::U256::from((clearlow, clearhigh));
                    let ct_1 = cks.encrypt_radix(clear_1, num_block);

                    let d_ctxt_1 =
                        CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct_0, &stream);
                    let d_ctxt_2 =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_1, &stream);

                    (d_ctxt_1, d_ctxt_2)
                };

                b.iter_batched(
                    encrypt_two_values,
                    |(mut ct_0, mut ct_1)| {
                        binary_op(&gpu_sks, &mut ct_0, &mut ct_1, &stream);
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            write_to_json::<u64, _>(
                &bench_id,
                param,
                param.name(),
                display_name,
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus().0.ilog2(); num_block],
            );
        }

        bench_group.finish()
    }

    macro_rules! define_cuda_server_key_bench_clean_input_signed_shift_rotate (
        (method_name: $server_key_method:ident, display_name:$name:ident) => {
            ::paste::paste!{
                fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                    bench_cuda_server_key_shift_rotate_signed_function_clean_inputs(
                        c,
                        concat!("integer::cuda::signed::", stringify!($server_key_method)),
                        stringify!($name),
                        |server_key, lhs, rhs, stream| {
                            server_key.$server_key_method(lhs, rhs, stream);
                        }
                    )
                }
            }
        }
    );

    fn cuda_if_then_else(c: &mut Criterion) {
        let mut bench_group = c.benchmark_group("integer::cuda::signed::if_then_else");
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));
        let mut rng = rand::thread_rng();

        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            if bit_size > ScalarType::BITS as usize {
                break;
            }

            let param_name = param.name();

            let bench_id = format!("if_then_else:{param_name}::{bit_size}_bits_scalar_{bit_size}");
            bench_group.bench_function(&bench_id, |b| {
                let (cks, _cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                let gpu_sks = CudaServerKey::new(&cks, &stream);

                let encrypt_tree_values = || {
                    let clear_cond = rng.gen::<bool>();
                    let ct_then = cks.encrypt_signed_radix(gen_random_i256(&mut rng), num_block);
                    let ct_else = cks.encrypt_signed_radix(gen_random_i256(&mut rng), num_block);
                    let ct_cond = cks.encrypt_bool(clear_cond);

                    let d_ct_cond = CudaBooleanBlock::from_boolean_block(&ct_cond, &stream);
                    let d_ct_then =
                        CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct_then, &stream);
                    let d_ct_else =
                        CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct_else, &stream);

                    (d_ct_cond, d_ct_then, d_ct_else)
                };

                b.iter_batched(
                    encrypt_tree_values,
                    |(ct_cond, ct_then, ct_else)| {
                        let _ = gpu_sks.if_then_else(&ct_cond, &ct_then, &ct_else, &stream);
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            write_to_json::<u64, _>(
                &bench_id,
                param,
                param.name(),
                "if_then_else",
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus().0.ilog2(); num_block],
            );
        }

        bench_group.finish()
    }
    // Functions used to apply different way of selecting a scalar based on the context.
    fn default_signed_scalar(rng: &mut ThreadRng, _clear_bit_size: usize) -> ScalarType {
        let clearlow = rng.gen::<u128>();
        let clearhigh = rng.gen::<u128>();
        tfhe::integer::I256::from((clearlow, clearhigh))
    }

    fn mul_signed_scalar(rng: &mut ThreadRng, _clear_bit_size: usize) -> ScalarType {
        loop {
            let clearlow = rng.gen::<u128>();
            let clearhigh = rng.gen::<u128>();
            let scalar = tfhe::integer::I256::from((clearlow, clearhigh));
            // If scalar is power of two, it is just a shit, which is a happy path.
            if !scalar.is_power_of_two() {
                return scalar;
            }
        }
    }

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_add,
        display_name: add
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_sub,
        display_name: sub
    );

    define_cuda_server_key_bench_clean_input_signed_unary_fn!(
        method_name: unchecked_neg,
        display_name: neg
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_mul,
        display_name: mul
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_bitand,
        display_name: bitand
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_bitor,
        display_name: bitor
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_bitxor,
        display_name: bitxor
    );

    define_cuda_server_key_bench_clean_input_signed_unary_fn!(
        method_name: unchecked_bitnot,
        display_name: bitnot
    );

    define_cuda_server_key_bench_clean_input_signed_shift_rotate!(
        method_name: unchecked_rotate_left,
        display_name: rotate_left
    );

    define_cuda_server_key_bench_clean_input_signed_shift_rotate!(
        method_name: unchecked_rotate_right,
        display_name: rotate_right
    );

    define_cuda_server_key_bench_clean_input_signed_shift_rotate!(
        method_name: unchecked_left_shift,
        display_name: left_shift
    );

    define_cuda_server_key_bench_clean_input_signed_shift_rotate!(
        method_name: unchecked_right_shift,
        display_name: right_shift
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_eq,
        display_name: eq
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_ne,
        display_name: ne
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_gt,
        display_name: gt
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_ge,
        display_name: ge
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_lt,
        display_name: lt
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_le,
        display_name: le
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_min,
        display_name: min
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: unchecked_max,
        display_name: max
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: unchecked_scalar_add,
        display_name: add,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: unchecked_scalar_mul,
        display_name: mul,
        rng_func: mul_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: unchecked_scalar_sub,
        display_name: sub,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: unchecked_scalar_bitand,
        display_name: bitand,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: unchecked_scalar_bitor,
        display_name: bitor,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: unchecked_scalar_bitxor,
        display_name: bitxor,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: unchecked_scalar_right_shift,
        display_name: right_shift,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: unchecked_scalar_left_shift,
        display_name: left_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: unchecked_scalar_rotate_right,
        display_name: rotate_right,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: unchecked_scalar_rotate_left,
        display_name: rotate_left,
        rng_func: shift_scalar
    );

    //===========================================
    // Default
    //===========================================

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: add,
        display_name: add
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: sub,
        display_name: sub
    );

    define_cuda_server_key_bench_clean_input_signed_unary_fn!(
        method_name: neg,
        display_name: neg
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: mul,
        display_name: mul
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: bitand,
        display_name: bitand
    );

    define_cuda_server_key_bench_clean_input_signed_unary_fn!(
        method_name: bitnot,
        display_name: bitnot
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: bitor,
        display_name: bitor
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: bitxor,
        display_name: bitxor
    );

    define_cuda_server_key_bench_clean_input_signed_shift_rotate!(
        method_name: rotate_left,
        display_name: rotate_left
    );

    define_cuda_server_key_bench_clean_input_signed_shift_rotate!(
        method_name: rotate_right,
        display_name: rotate_right
    );

    define_cuda_server_key_bench_clean_input_signed_shift_rotate!(
        method_name: left_shift,
        display_name: left_shift
    );

    define_cuda_server_key_bench_clean_input_signed_shift_rotate!(
        method_name: right_shift,
        display_name: right_shift
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: eq,
        display_name: eq
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: ne,
        display_name: ne
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: gt,
        display_name: gt
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: ge,
        display_name: ge
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: lt,
        display_name: lt
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: le,
        display_name: le
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: min,
        display_name: min
    );

    define_cuda_server_key_bench_clean_input_signed_fn!(
        method_name: max,
        display_name: max
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: scalar_add,
        display_name: add,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: scalar_mul,
        display_name: mul,
        rng_func: mul_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: scalar_sub,
        display_name: sub,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: scalar_bitand,
        display_name: bitand,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: scalar_bitor,
        display_name: bitor,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: scalar_bitxor,
        display_name: bitxor,
        rng_func: default_signed_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: scalar_left_shift,
        display_name: left_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: scalar_right_shift,
        display_name: right_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: scalar_rotate_left,
        display_name: rotate_left,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_signed_fn!(
        method_name: scalar_rotate_right,
        display_name: rotate_right,
        rng_func: shift_scalar
    );

    criterion_group!(
        unchecked_cuda_ops,
        cuda_unchecked_add,
        cuda_unchecked_sub,
        cuda_unchecked_neg,
        cuda_unchecked_mul,
        cuda_unchecked_bitand,
        cuda_unchecked_bitnot,
        cuda_unchecked_bitor,
        cuda_unchecked_bitxor,
        cuda_unchecked_left_shift,
        cuda_unchecked_right_shift,
        cuda_unchecked_rotate_left,
        cuda_unchecked_rotate_right,
        cuda_unchecked_eq,
        cuda_unchecked_ne,
        cuda_unchecked_gt,
        cuda_unchecked_ge,
        cuda_unchecked_lt,
        cuda_unchecked_le,
        cuda_unchecked_min,
        cuda_unchecked_max,
    );

    criterion_group!(
        unchecked_scalar_cuda_ops,
        cuda_unchecked_scalar_add,
        cuda_unchecked_scalar_mul,
        cuda_unchecked_scalar_sub,
        cuda_unchecked_scalar_bitand,
        cuda_unchecked_scalar_bitor,
        cuda_unchecked_scalar_bitxor,
        cuda_unchecked_scalar_left_shift,
        cuda_unchecked_scalar_right_shift,
        cuda_unchecked_scalar_rotate_left,
        cuda_unchecked_scalar_rotate_right,
    );

    criterion_group!(
        default_cuda_ops,
        cuda_add,
        cuda_sub,
        cuda_neg,
        cuda_mul,
        cuda_bitand,
        cuda_bitnot,
        cuda_bitor,
        cuda_bitxor,
        cuda_left_shift,
        cuda_right_shift,
        cuda_rotate_left,
        cuda_rotate_right,
        cuda_eq,
        cuda_ne,
        cuda_gt,
        cuda_ge,
        cuda_lt,
        cuda_le,
        cuda_min,
        cuda_max,
        cuda_if_then_else,
    );

    criterion_group!(
        default_scalar_cuda_ops,
        cuda_scalar_add,
        cuda_scalar_mul,
        cuda_scalar_sub,
        cuda_scalar_bitand,
        cuda_scalar_bitor,
        cuda_scalar_bitxor,
        cuda_scalar_left_shift,
        cuda_scalar_right_shift,
        cuda_scalar_rotate_left,
        cuda_scalar_rotate_right,
    );
}

#[cfg(feature = "gpu")]
use cuda::{
    default_cuda_ops, default_scalar_cuda_ops, unchecked_cuda_ops, unchecked_scalar_cuda_ops,
};

#[cfg(feature = "gpu")]
fn go_through_gpu_bench_groups(val: &str) {
    match val.to_lowercase().as_str() {
        "default" => {
            default_cuda_ops();
            default_scalar_cuda_ops();
        }
        "unchecked" => {
            unchecked_cuda_ops();
            unchecked_scalar_cuda_ops();
        }
        _ => panic!("unknown benchmark operations flavor"),
    };
}

#[allow(dead_code)]
fn go_through_cpu_bench_groups(val: &str) {
    match val.to_lowercase().as_str() {
        "default" => {
            default_parallelized_ops();
            default_parallelized_ops_comp();
            default_scalar_parallelized_ops();
            default_scalar_parallelized_ops_comp();
            cast_ops()
        }
        "unchecked" => {
            unchecked_ops();
            unchecked_ops_comp();
            unchecked_scalar_ops();
            unchecked_scalar_ops_comp()
        }
        _ => panic!("unknown benchmark operations flavor"),
    };
}

fn main() {
    match env::var("__TFHE_RS_BENCH_OP_FLAVOR") {
        Ok(val) => {
            #[cfg(feature = "gpu")]
            go_through_gpu_bench_groups(&val);
            #[cfg(not(feature = "gpu"))]
            go_through_cpu_bench_groups(&val);
        }
        Err(_) => {
            default_parallelized_ops();
            default_parallelized_ops_comp();
            default_scalar_parallelized_ops();
            default_scalar_parallelized_ops_comp();
            cast_ops()
        }
    };

    Criterion::default().configure_from_args().final_summary();
}
