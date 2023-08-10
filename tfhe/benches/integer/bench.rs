#![allow(dead_code)]

#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, OperatorType};
use std::env;

use criterion::{criterion_group, Criterion};
use itertools::iproduct;
use rand::prelude::*;
use rand::Rng;
use std::vec::IntoIter;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::{RadixCiphertext, ServerKey};
use tfhe::keycache::NamedParam;

#[allow(unused_imports)]
use tfhe::shortint::parameters::{
    PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS, PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
};

/// An iterator that yields a succession of combinations
/// of parameters and a num_block to achieve a certain bit_size ciphertext
/// in radix decomposition
struct ParamsAndNumBlocksIter {
    params_and_bit_sizes:
        itertools::Product<IntoIter<tfhe::shortint::PBSParameters>, IntoIter<usize>>,
}

impl Default for ParamsAndNumBlocksIter {
    fn default() -> Self {
        let is_multi_bit = match env::var("__TFHE_RS_BENCH_TYPE") {
            Ok(val) => val.to_lowercase() == "multi_bit",
            Err(_) => false,
        };

        let is_fast_bench = match env::var("__TFHE_RS_FAST_BENCH") {
            Ok(val) => val.to_lowercase() == "true",
            Err(_) => false,
        };

        if is_multi_bit {
            let params = vec![PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS.into()];

            let bit_sizes = if is_fast_bench {
                vec![32]
            } else {
                vec![8, 16, 32, 40, 64]
            };

            let params_and_bit_sizes = iproduct!(params, bit_sizes);
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

            let bit_sizes = if is_fast_bench {
                vec![32]
            } else {
                vec![8, 16, 32, 40, 64, 128, 256]
            };

            let params_and_bit_sizes = iproduct!(params, bit_sizes);
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
            (bit_size as f64 / (param.message_modulus().0 as f64).log(2.0)).ceil() as usize;

        Some((param, num_block, bit_size))
    }
}

/// Base function to bench a server key function that is a binary operation, input ciphertexts will
/// contain non zero carries
fn bench_server_key_binary_function_dirty_inputs<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
) where
    F: Fn(&ServerKey, &mut RadixCiphertext, &mut RadixCiphertext),
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
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            let encrypt_two_values = || {
                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();
                let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();
                let clear_1 = tfhe::integer::U256::from((clearlow, clearhigh));
                let mut ct_1 = cks.encrypt_radix(clear_1, num_block);

                // Raise the degree, so as to ensure worst case path in operations
                let mut carry_mod = param.carry_modulus().0;
                while carry_mod > 0 {
                    // Raise the degree, so as to ensure worst case path in operations
                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_2 = tfhe::integer::U256::from((clearlow, clearhigh));
                    let ct_2 = cks.encrypt_radix(clear_2, num_block);
                    sks.unchecked_add_assign(&mut ct_0, &ct_2);
                    sks.unchecked_add_assign(&mut ct_1, &ct_2);

                    carry_mod -= 1;
                }

                (ct_0, ct_1)
            };

            b.iter_batched(
                encrypt_two_values,
                |(mut ct_0, mut ct_1)| {
                    binary_op(&sks, &mut ct_0, &mut ct_1);
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

/// Base function to bench a server key function that is a binary operation, input ciphertext will
/// contain only zero carries
fn bench_server_key_binary_function_clean_inputs<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
) where
    F: Fn(&ServerKey, &mut RadixCiphertext, &mut RadixCiphertext),
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
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            let encrypt_two_values = || {
                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();
                let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                let ct_0 = cks.encrypt_radix(clear_0, num_block);

                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();
                let clear_1 = tfhe::integer::U256::from((clearlow, clearhigh));
                let ct_1 = cks.encrypt_radix(clear_1, num_block);

                (ct_0, ct_1)
            };

            b.iter_batched(
                encrypt_two_values,
                |(mut ct_0, mut ct_1)| {
                    binary_op(&sks, &mut ct_0, &mut ct_1);
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

/// Base function to bench a server key function that is a unary operation, input ciphertexts will
/// contain non zero carries
fn bench_server_key_unary_function_dirty_inputs<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    unary_fn: F,
) where
    F: Fn(&ServerKey, &mut RadixCiphertext),
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
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            let encrypt_one_value = || {
                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();

                let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));

                let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

                // Raise the degree, so as to ensure worst case path in operations
                let mut carry_mod = param.carry_modulus().0;
                while carry_mod > 0 {
                    // Raise the degree, so as to ensure worst case path in operations
                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_2 = tfhe::integer::U256::from((clearlow, clearhigh));
                    let ct_2 = cks.encrypt_radix(clear_2, num_block);
                    sks.unchecked_add_assign(&mut ct_0, &ct_2);

                    carry_mod -= 1;
                }

                ct_0
            };

            b.iter_batched(
                encrypt_one_value,
                |mut ct_0| {
                    unary_fn(&sks, &mut ct_0);
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
    F: Fn(&ServerKey, &mut RadixCiphertext),
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
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            let encrypt_one_value = || {
                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();

                let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));

                cks.encrypt_radix(clear_0, num_block)
            };

            b.iter_batched(
                encrypt_one_value,
                |mut ct_0| {
                    unary_fn(&sks, &mut ct_0);
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

fn bench_server_key_binary_scalar_function_dirty_inputs<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
) where
    F: Fn(&ServerKey, &mut RadixCiphertext, u64),
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
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            let encrypt_one_value = || {
                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();

                let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

                // Raise the degree, so as to ensure worst case path in operations
                let mut carry_mod = param.carry_modulus().0;
                while carry_mod > 0 {
                    // Raise the degree, so as to ensure worst case path in operations
                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_2 = tfhe::integer::U256::from((clearlow, clearhigh));
                    let ct_2 = cks.encrypt_radix(clear_2, num_block);
                    sks.unchecked_add_assign(&mut ct_0, &ct_2);

                    carry_mod -= 1;
                }

                let clear_1 = rng.gen::<u64>();

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

fn bench_server_key_binary_scalar_function_clean_inputs<F, G>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
    rng_func: G,
) where
    F: Fn(&ServerKey, &mut RadixCiphertext, u64),
    G: Fn(&mut ThreadRng, usize) -> u64,
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        if bit_size > 64 {
            break;
        }
        let param_name = param.name();

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits_scalar_{bit_size}");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            let encrypt_one_value = || {
                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();

                let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                let ct_0 = cks.encrypt_radix(clear_0, num_block);

                // Avoid overflow issues for u64 where we would take values mod 1
                let clear_1 = (rng_func(&mut rng, bit_size) as u128 % (1u128 << bit_size)) as u64;

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

// Functions used to apply different way of selecting a scalar based on the context.
fn default_scalar(rng: &mut ThreadRng, _clear_bit_size: usize) -> u64 {
    rng.gen::<u64>()
}

fn shift_scalar(_rng: &mut ThreadRng, _clear_bit_size: usize) -> u64 {
    // Shifting by one is the worst case scenario.
    1
}

fn mul_scalar(rng: &mut ThreadRng, _clear_bit_size: usize) -> u64 {
    loop {
        let scalar = rng.gen_range(3u64..=u64::MAX);
        // If scalar is power of two, it is just a shit, which is an happy path.
        if !scalar.is_power_of_two() {
            return scalar;
        }
    }
}

fn div_scalar(rng: &mut ThreadRng, clear_bit_size: usize) -> u64 {
    loop {
        let scalar = rng.gen_range(1..=u64::MAX);
        // Avoid overflow issues for u64 where we would take values mod 1
        if (scalar as u128 % (1u128 << clear_bit_size)) != 0 {
            return scalar;
        }
    }
}

fn if_then_else_parallelized(c: &mut Criterion) {
    let bench_name = "integer::if_then_else_parallelized";
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
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            let encrypt_tree_values = || {
                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();
                let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                let ct_0 = cks.encrypt_radix(clear_0, num_block);

                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();
                let clear_1 = tfhe::integer::U256::from((clearlow, clearhigh));
                let ct_1 = cks.encrypt_radix(clear_1, num_block);

                let cond = sks.create_trivial_radix(rng.gen_bool(0.5) as u64, num_block);

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

macro_rules! define_server_key_bench_unary_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_unary_function_dirty_inputs(
                c,
                concat!("integer::", stringify!($server_key_method)),
                stringify!($name),
                |server_key, lhs| {
                  server_key.$server_key_method(lhs);
            })
        }
    }
);

macro_rules! define_server_key_bench_unary_default_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_unary_function_clean_inputs(
                c,
                concat!("integer::", stringify!($server_key_method)),
                stringify!($name),
                |server_key, lhs| {
                  server_key.$server_key_method(lhs);
            })
        }
    }
);

macro_rules! define_server_key_bench_fn (
  (method_name: $server_key_method:ident, display_name:$name:ident) => {
      fn $server_key_method(c: &mut Criterion) {
        bench_server_key_binary_function_dirty_inputs(
              c,
              concat!("integer::", stringify!($server_key_method)),
              stringify!($name),
              |server_key, lhs, rhs| {
                server_key.$server_key_method(lhs, rhs);
          })
      }
  }
);

macro_rules! define_server_key_bench_default_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_function_clean_inputs(
                c,
                concat!("integer::", stringify!($server_key_method)),
                stringify!($name),
                |server_key, lhs, rhs| {
                  server_key.$server_key_method(lhs, rhs);
            })
        }
    }
  );

macro_rules! define_server_key_bench_scalar_fn (
  (method_name: $server_key_method:ident, display_name:$name:ident) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_scalar_function_dirty_inputs(
              c,
              concat!("integer::", stringify!($server_key_method)),
              stringify!($name),
              |server_key, lhs, rhs| {
                server_key.$server_key_method(lhs, rhs);
          })
      }
  }
);

macro_rules! define_server_key_bench_scalar_default_fn (
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

define_server_key_bench_fn!(method_name: smart_add, display_name: add);
define_server_key_bench_fn!(method_name: smart_sub, display_name: sub);
define_server_key_bench_fn!(method_name: smart_mul, display_name: mul);
define_server_key_bench_fn!(method_name: smart_bitand, display_name: bitand);
define_server_key_bench_fn!(method_name: smart_bitor, display_name: bitor);
define_server_key_bench_fn!(method_name: smart_bitxor, display_name: bitxor);

define_server_key_bench_fn!(method_name: smart_add_parallelized, display_name: add);
define_server_key_bench_fn!(method_name: smart_sub_parallelized, display_name: sub);
define_server_key_bench_fn!(method_name: smart_mul_parallelized, display_name: mul);
define_server_key_bench_fn!(method_name: smart_bitand_parallelized, display_name: bitand);
define_server_key_bench_fn!(method_name: smart_bitxor_parallelized, display_name: bitxor);
define_server_key_bench_fn!(method_name: smart_bitor_parallelized, display_name: bitor);

define_server_key_bench_default_fn!(method_name: add_parallelized, display_name: add);
define_server_key_bench_default_fn!(method_name: sub_parallelized, display_name: sub);
define_server_key_bench_default_fn!(method_name: mul_parallelized, display_name: mul);
define_server_key_bench_default_fn!(method_name: bitand_parallelized, display_name: bitand);
define_server_key_bench_default_fn!(method_name: bitxor_parallelized, display_name: bitxor);
define_server_key_bench_default_fn!(method_name: bitor_parallelized, display_name: bitor);
define_server_key_bench_unary_default_fn!(method_name: bitnot_parallelized, display_name: bitnot);

define_server_key_bench_default_fn!(method_name: unchecked_add, display_name: add);
define_server_key_bench_default_fn!(method_name: unchecked_sub, display_name: sub);
define_server_key_bench_default_fn!(method_name: unchecked_mul, display_name: mul);
define_server_key_bench_default_fn!(method_name: unchecked_bitand, display_name: bitand);
define_server_key_bench_default_fn!(method_name: unchecked_bitor, display_name: bitor);
define_server_key_bench_default_fn!(method_name: unchecked_bitxor, display_name: bitxor);

define_server_key_bench_default_fn!(method_name: unchecked_mul_parallelized, display_name: mul);
define_server_key_bench_default_fn!(
    method_name: unchecked_bitand_parallelized,
    display_name: bitand
);
define_server_key_bench_default_fn!(
    method_name: unchecked_bitor_parallelized,
    display_name: bitor
);
define_server_key_bench_default_fn!(
    method_name: unchecked_bitxor_parallelized,
    display_name: bitxor
);

define_server_key_bench_scalar_fn!(method_name: smart_scalar_add, display_name: add);
define_server_key_bench_scalar_fn!(method_name: smart_scalar_sub, display_name: sub);
define_server_key_bench_scalar_fn!(method_name: smart_scalar_mul, display_name: mul);

define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_add_parallelized,
    display_name: add
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_sub_parallelized,
    display_name: sub
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_mul_parallelized,
    display_name: mul
);

define_server_key_bench_scalar_default_fn!(
    method_name: scalar_add_parallelized,
    display_name: add,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_sub_parallelized,
    display_name: sub,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_mul_parallelized,
    display_name: mul,
    rng_func: mul_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_div_parallelized,
    display_name: div,
    rng_func: div_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_rem_parallelized,
    display_name: modulo,
    rng_func: div_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_left_shift_parallelized,
    display_name: left_shift,
    rng_func: shift_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_right_shift_parallelized,
    display_name: right_shift,
    rng_func: shift_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_rotate_left_parallelized,
    display_name: rotate_left,
    rng_func: shift_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_rotate_right_parallelized,
    display_name: rotate_right,
    rng_func: shift_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_eq_parallelized,
    display_name: equal,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_ne_parallelized,
    display_name: not_equal,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_le_parallelized,
    display_name: less_or_equal,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_lt_parallelized,
    display_name: less_than,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_ge_parallelized,
    display_name: greater_or_equal,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_gt_parallelized,
    display_name: greater_than,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_max_parallelized,
    display_name: max,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_min_parallelized,
    display_name: min,
    rng_func: default_scalar
);

define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_add,
    display_name: add,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_sub,
    display_name: sub,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_small_scalar_mul,
    display_name: mul,
    rng_func: mul_scalar
);

define_server_key_bench_unary_fn!(method_name: smart_neg, display_name: negation);
define_server_key_bench_unary_fn!(method_name: smart_neg_parallelized, display_name: negation);
define_server_key_bench_unary_default_fn!(method_name: neg_parallelized, display_name: negation);

define_server_key_bench_unary_fn!(method_name: full_propagate, display_name: carry_propagation);
define_server_key_bench_unary_fn!(
    method_name: full_propagate_parallelized,
    display_name: carry_propagation
);

define_server_key_bench_default_fn!(method_name: unchecked_max, display_name: max);
define_server_key_bench_default_fn!(method_name: unchecked_min, display_name: min);
define_server_key_bench_default_fn!(method_name: unchecked_eq, display_name: equal);
define_server_key_bench_default_fn!(method_name: unchecked_lt, display_name: less_than);
define_server_key_bench_default_fn!(method_name: unchecked_le, display_name: less_or_equal);
define_server_key_bench_default_fn!(method_name: unchecked_gt, display_name: greater_than);
define_server_key_bench_default_fn!(method_name: unchecked_ge, display_name: greater_or_equal);

define_server_key_bench_default_fn!(method_name: unchecked_max_parallelized, display_name: max);
define_server_key_bench_default_fn!(method_name: unchecked_min_parallelized, display_name: min);
define_server_key_bench_default_fn!(method_name: unchecked_eq_parallelized, display_name: equal);
define_server_key_bench_default_fn!(
    method_name: unchecked_lt_parallelized,
    display_name: less_than
);
define_server_key_bench_default_fn!(
    method_name: unchecked_le_parallelized,
    display_name: less_or_equal
);
define_server_key_bench_default_fn!(
    method_name: unchecked_gt_parallelized,
    display_name: greater_than
);
define_server_key_bench_default_fn!(
    method_name: unchecked_ge_parallelized,
    display_name: greater_or_equal
);

define_server_key_bench_fn!(method_name: smart_max, display_name: max);
define_server_key_bench_fn!(method_name: smart_min, display_name: min);
define_server_key_bench_fn!(method_name: smart_eq, display_name: equal);
define_server_key_bench_fn!(method_name: smart_lt, display_name: less_than);
define_server_key_bench_fn!(method_name: smart_le, display_name: less_or_equal);
define_server_key_bench_fn!(method_name: smart_gt, display_name: greater_than);
define_server_key_bench_fn!(method_name: smart_ge, display_name: greater_or_equal);

define_server_key_bench_fn!(method_name: smart_max_parallelized, display_name: max);
define_server_key_bench_fn!(method_name: smart_min_parallelized, display_name: min);
define_server_key_bench_fn!(method_name: smart_eq_parallelized, display_name: equal);
define_server_key_bench_fn!(method_name: smart_lt_parallelized, display_name: less_than);
define_server_key_bench_fn!(
    method_name: smart_le_parallelized,
    display_name: less_or_equal
);
define_server_key_bench_fn!(
    method_name: smart_gt_parallelized,
    display_name: greater_than
);
define_server_key_bench_fn!(
    method_name: smart_ge_parallelized,
    display_name: greater_or_equal
);

define_server_key_bench_default_fn!(method_name: max_parallelized, display_name: max);
define_server_key_bench_default_fn!(method_name: min_parallelized, display_name: min);
define_server_key_bench_default_fn!(method_name: eq_parallelized, display_name: equal);
define_server_key_bench_default_fn!(method_name: ne_parallelized, display_name: not_equal);
define_server_key_bench_default_fn!(method_name: lt_parallelized, display_name: less_than);
define_server_key_bench_default_fn!(method_name: le_parallelized, display_name: less_or_equal);
define_server_key_bench_default_fn!(method_name: gt_parallelized, display_name: greater_than);
define_server_key_bench_default_fn!(method_name: ge_parallelized, display_name: greater_or_equal);

define_server_key_bench_default_fn!(
    method_name: left_shift_parallelized,
    display_name: left_shift
);
define_server_key_bench_default_fn!(
    method_name: right_shift_parallelized,
    display_name: right_shift
);
define_server_key_bench_default_fn!(
    method_name: rotate_left_parallelized,
    display_name: rotate_left
);
define_server_key_bench_default_fn!(
    method_name: rotate_right_parallelized,
    display_name: rotate_right
);

criterion_group!(
    smart_ops,
    smart_neg,
    smart_add,
    smart_mul,
    smart_bitand,
    smart_bitor,
    smart_bitxor,
);

criterion_group!(
    smart_ops_comp,
    smart_max,
    smart_min,
    smart_eq,
    smart_lt,
    smart_le,
    smart_gt,
    smart_ge,
);

criterion_group!(
    smart_parallelized_ops,
    smart_add_parallelized,
    smart_sub_parallelized,
    smart_mul_parallelized,
    smart_bitand_parallelized,
    smart_bitor_parallelized,
    smart_bitxor_parallelized,
);

criterion_group!(
    smart_parallelized_ops_comp,
    smart_max_parallelized,
    smart_min_parallelized,
    smart_eq_parallelized,
    smart_lt_parallelized,
    smart_le_parallelized,
    smart_gt_parallelized,
    smart_ge_parallelized,
);

criterion_group!(
    default_parallelized_ops,
    add_parallelized,
    sub_parallelized,
    mul_parallelized,
    neg_parallelized,
    bitand_parallelized,
    bitnot_parallelized,
    bitor_parallelized,
    bitxor_parallelized,
    left_shift_parallelized,
    right_shift_parallelized,
    rotate_left_parallelized,
    rotate_right_parallelized,
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
    if_then_else_parallelized,
);

criterion_group!(
    smart_scalar_ops,
    smart_scalar_add,
    smart_scalar_sub,
    smart_scalar_mul,
);

criterion_group!(
    smart_scalar_parallelized_ops,
    smart_scalar_add_parallelized,
    smart_scalar_sub_parallelized,
    smart_scalar_mul_parallelized,
);

criterion_group!(
    default_scalar_parallelized_ops,
    scalar_add_parallelized,
    scalar_sub_parallelized,
    scalar_mul_parallelized,
    scalar_div_parallelized,
    scalar_rem_parallelized,
    scalar_left_shift_parallelized,
    scalar_right_shift_parallelized,
    scalar_rotate_left_parallelized,
    scalar_rotate_right_parallelized,
);

criterion_group!(
    default_scalar_parallelized_ops_comp,
    scalar_eq_parallelized,
    scalar_ne_parallelized,
    scalar_lt_parallelized,
    scalar_le_parallelized,
    scalar_gt_parallelized,
    scalar_ge_parallelized,
    scalar_min_parallelized,
    scalar_max_parallelized,
);

criterion_group!(
    unchecked_ops,
    unchecked_add,
    unchecked_sub,
    unchecked_mul,
    unchecked_bitand,
    unchecked_bitor,
    unchecked_bitxor,
);

criterion_group!(
    unchecked_ops_comp,
    unchecked_max,
    unchecked_min,
    unchecked_eq,
    unchecked_lt,
    unchecked_le,
    unchecked_gt,
    unchecked_ge,
);

criterion_group!(
    unchecked_scalar_ops,
    unchecked_scalar_add,
    unchecked_scalar_sub,
    unchecked_small_scalar_mul,
    unchecked_bitand_parallelized,
    unchecked_bitor_parallelized,
    unchecked_bitxor_parallelized,
);

criterion_group!(
    unchecked_scalar_ops_comp,
    unchecked_max_parallelized,
    unchecked_min_parallelized,
    unchecked_eq_parallelized,
    unchecked_lt_parallelized,
    unchecked_le_parallelized,
    unchecked_gt_parallelized,
    unchecked_ge_parallelized,
);

criterion_group!(misc, full_propagate, full_propagate_parallelized);

fn main() {
    match env::var("__TFHE_RS_BENCH_OP_FLAVOR") {
        Ok(val) => {
            match val.to_lowercase().as_str() {
                "default" => default_parallelized_ops(),
                "default_comp" => default_parallelized_ops_comp(),
                "default_scalar" => default_scalar_parallelized_ops(),
                "default_scalar_comp" => default_scalar_parallelized_ops_comp(),
                "smart" => smart_ops(),
                "smart_comp" => smart_ops_comp(),
                "smart_scalar" => smart_scalar_ops(),
                "smart_parallelized" => smart_parallelized_ops(),
                "smart_parallelized_comp" => smart_parallelized_ops_comp(),
                "smart_scalar_parallelized" => smart_scalar_parallelized_ops(),
                "unchecked" => unchecked_ops(),
                "unchecked_comp" => unchecked_ops_comp(),
                "unchecked_scalar" => unchecked_scalar_ops(),
                "unchecked_scalar_comp" => unchecked_scalar_ops_comp(),
                "misc" => misc(),
                _ => panic!("unknown benchmark operations flavor"),
            };
        }
        Err(_) => {
            default_parallelized_ops();
            default_scalar_parallelized_ops()
        }
    };

    Criterion::default().configure_from_args().final_summary();
}
