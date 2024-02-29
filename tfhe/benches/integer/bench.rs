#![allow(dead_code)]

#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, EnvConfig, OperatorType};
use std::env;

use criterion::{criterion_group, Criterion};
use itertools::iproduct;
use rand::prelude::*;
use rand::Rng;
use std::vec::IntoIter;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::keycache::NamedParam;

use tfhe::integer::U256;

#[allow(unused_imports)]
use tfhe::shortint::parameters::{
    PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS, PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
};

/// The type used to hold scalar values
/// It must be as big as the largest bit size tested
type ScalarType = U256;

fn gen_random_u256(rng: &mut ThreadRng) -> U256 {
    let clearlow = rng.gen::<u128>();
    let clearhigh = rng.gen::<u128>();

    tfhe::integer::U256::from((clearlow, clearhigh))
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
            let params = vec![PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS.into()];
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
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_two_values = || {
                let clear_0 = gen_random_u256(&mut rng);
                let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

                let clear_1 = gen_random_u256(&mut rng);
                let mut ct_1 = cks.encrypt_radix(clear_1, num_block);

                // Raise the degree, so as to ensure worst case path in operations
                let mut carry_mod = param.carry_modulus().0;
                while carry_mod > 0 {
                    // Raise the degree, so as to ensure worst case path in operations
                    let clear_2 = gen_random_u256(&mut rng);
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
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_two_values = || {
                let clear_0 = gen_random_u256(&mut rng);
                let ct_0 = cks.encrypt_radix(clear_0, num_block);

                let clear_1 = gen_random_u256(&mut rng);
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
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_one_value = || {
                let clear_0 = gen_random_u256(&mut rng);
                let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

                // Raise the degree, so as to ensure worst case path in operations
                let mut carry_mod = param.carry_modulus().0;
                while carry_mod > 0 {
                    // Raise the degree, so as to ensure worst case path in operations
                    let clear_2 = gen_random_u256(&mut rng);
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
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_one_value = || {
                let clear_0 = gen_random_u256(&mut rng);

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

fn bench_server_key_binary_scalar_function_dirty_inputs<F, G>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
    rng_func: G,
) where
    F: Fn(&ServerKey, &mut RadixCiphertext, ScalarType),
    G: Fn(&mut ThreadRng, usize) -> ScalarType,
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let max_value_for_bit_size = ScalarType::MAX >> (ScalarType::BITS as usize - bit_size);

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_one_value = || {
                let clear_0 = gen_random_u256(&mut rng);
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

                let clear_1 = rng_func(&mut rng, bit_size) & max_value_for_bit_size;

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
    F: Fn(&ServerKey, &mut RadixCiphertext, ScalarType),
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

        let max_value_for_bit_size = ScalarType::MAX >> (ScalarType::BITS as usize - bit_size);

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits_scalar_{bit_size}");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_one_value = || {
                let clear_0 = gen_random_u256(&mut rng);
                let ct_0 = cks.encrypt_radix(clear_0, num_block);

                let clear_1 = rng_func(&mut rng, bit_size) & max_value_for_bit_size;

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
fn default_scalar(rng: &mut ThreadRng, _clear_bit_size: usize) -> ScalarType {
    gen_random_u256(rng)
}

fn shift_scalar(_rng: &mut ThreadRng, _clear_bit_size: usize) -> ScalarType {
    // Shifting by one is the worst case scenario.
    ScalarType::ONE
}

fn mul_scalar(rng: &mut ThreadRng, _clear_bit_size: usize) -> ScalarType {
    loop {
        let scalar = gen_random_u256(rng);
        // If scalar is power of two, it is just a shit, which is an happy path.
        if !scalar.is_power_of_two() {
            return scalar;
        }
    }
}

fn div_scalar(rng: &mut ThreadRng, clear_bit_size: usize) -> ScalarType {
    loop {
        let scalar = gen_random_u256(rng);
        let max_for_bit_size = ScalarType::MAX >> (ScalarType::BITS as usize - clear_bit_size);
        let scalar = scalar & max_for_bit_size;
        if scalar != ScalarType::ZERO {
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
            let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

            let encrypt_tree_values = || {
                let clear_0 = gen_random_u256(&mut rng);
                let ct_0 = cks.encrypt_radix(clear_0, num_block);

                let clear_1 = gen_random_u256(&mut rng);
                let ct_1 = cks.encrypt_radix(clear_1, num_block);

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

fn ciphertexts_sum_parallelized(c: &mut Criterion) {
    let bench_name = "integer::sum_ciphertexts_parallelized";
    let display_name = "sum_ctxts";

    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();
        let max_for_bit_size = ScalarType::MAX >> (ScalarType::BITS as usize - bit_size);

        for len in [5, 10, 20] {
            let bench_id = format!("{bench_name}_{len}_ctxts::{param_name}::{bit_size}_bits");
            bench_group.bench_function(&bench_id, |b| {
                let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                let nb_ctxt = bit_size.div_ceil(param.message_modulus().0.ilog2() as usize);
                let cks = RadixClientKey::from((cks, nb_ctxt));

                let encrypt_values = || {
                    let clears = (0..len)
                        .map(|_| gen_random_u256(&mut rng) & max_for_bit_size)
                        .collect::<Vec<_>>();

                    // encryption of integers
                    let ctxts = clears
                        .iter()
                        .copied()
                        .map(|clear| cks.encrypt(clear))
                        .collect::<Vec<_>>();

                    ctxts
                };

                b.iter_batched(
                    encrypt_values,
                    |ctxts| sks.sum_ciphertexts_parallelized(&ctxts),
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
    (method_name: $server_key_method:ident, display_name:$name:ident, rng_func:$($rng_fn:tt)*) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_scalar_function_dirty_inputs(
              c,
              concat!("integer::", stringify!($server_key_method)),
              stringify!($name),
              |server_key, lhs, rhs| {
                server_key.$server_key_method(lhs, rhs);
              },
              $($rng_fn)*
          )
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
                },
                $($rng_fn)*
            )
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
define_server_key_bench_fn!(method_name: smart_div_parallelized, display_name: div);
define_server_key_bench_fn!(method_name: smart_div_rem_parallelized, display_name: div_mod);
define_server_key_bench_fn!(method_name: smart_rem_parallelized, display_name: rem);
define_server_key_bench_fn!(method_name: smart_bitand_parallelized, display_name: bitand);
define_server_key_bench_fn!(method_name: smart_bitxor_parallelized, display_name: bitxor);
define_server_key_bench_fn!(method_name: smart_bitor_parallelized, display_name: bitor);
define_server_key_bench_fn!(method_name: smart_rotate_right_parallelized, display_name: rotate_right);
define_server_key_bench_fn!(method_name: smart_rotate_left_parallelized, display_name: rotate_left);
define_server_key_bench_fn!(method_name: smart_right_shift_parallelized, display_name: right_shift);
define_server_key_bench_fn!(method_name: smart_left_shift_parallelized, display_name: left_shift);

define_server_key_bench_default_fn!(method_name: add_parallelized, display_name: add);
define_server_key_bench_default_fn!(method_name: unsigned_overflowing_add_parallelized, display_name: overflowing_add);
define_server_key_bench_default_fn!(method_name: sub_parallelized, display_name: sub);
define_server_key_bench_default_fn!(method_name: unsigned_overflowing_sub_parallelized, display_name: overflowing_sub);
define_server_key_bench_default_fn!(method_name: mul_parallelized, display_name: mul);
define_server_key_bench_default_fn!(method_name: unsigned_overflowing_mul_parallelized, display_name: overflowing_mul);
define_server_key_bench_default_fn!(method_name: div_parallelized, display_name: div);
define_server_key_bench_default_fn!(method_name: rem_parallelized, display_name: modulo);
define_server_key_bench_default_fn!(method_name: div_rem_parallelized, display_name: div_mod);
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

define_server_key_bench_default_fn!(method_name: unchecked_add_parallelized, display_name: add);
define_server_key_bench_default_fn!(method_name: unchecked_mul_parallelized, display_name: mul);
define_server_key_bench_default_fn!(method_name: unchecked_div_parallelized, display_name: div);
define_server_key_bench_default_fn!(method_name: unchecked_rem_parallelized, display_name: modulo);
define_server_key_bench_default_fn!(method_name: unchecked_div_rem_parallelized, display_name: div_mod);
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
define_server_key_bench_default_fn!(
    method_name: unchecked_rotate_right_parallelized,
    display_name: rotate_right
);
define_server_key_bench_default_fn!(
    method_name: unchecked_rotate_left_parallelized,
    display_name: rotate_left
);
define_server_key_bench_default_fn!(
    method_name: unchecked_right_shift_parallelized,
    display_name: right_shift
);
define_server_key_bench_default_fn!(
    method_name: unchecked_left_shift_parallelized,
    display_name: left_shift
);

define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_bitand_parallelized,
    display_name: bitand,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_bitor_parallelized,
    display_name: bitor,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_bitxor_parallelized,
    display_name: bitxor,
    rng_func: default_scalar
);

define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_add,
    display_name: add,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_sub,
    display_name: sub,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_mul,
    display_name: mul,
    rng_func: mul_scalar
);

define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_add_parallelized,
    display_name: add,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_sub_parallelized,
    display_name: sub,
    rng_func: default_scalar,
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_mul_parallelized,
    display_name: mul,
    rng_func: mul_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_div_parallelized,
    display_name: div,
    rng_func: div_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_rem_parallelized,
    display_name: modulo,
    rng_func: div_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_div_rem_parallelized,
    display_name: div_mod,
    rng_func: div_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_bitand_parallelized,
    display_name: bitand,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_bitor_parallelized,
    display_name: bitor,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_bitxor_parallelized,
    display_name: bitxor,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_rotate_left_parallelized,
    display_name: rotate_left,
    rng_func: shift_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_rotate_right_parallelized,
    display_name: rotate_right,
    rng_func: shift_scalar
);

define_server_key_bench_scalar_default_fn!(
    method_name: scalar_add_parallelized,
    display_name: add,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unsigned_overflowing_scalar_add_parallelized,
    display_name: overflowing_add,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_sub_parallelized,
    display_name: sub,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unsigned_overflowing_scalar_sub_parallelized,
    display_name: overflowing_sub,
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
    method_name: scalar_div_rem_parallelized,
    display_name: div_mod,
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
    method_name: scalar_bitand_parallelized,
    display_name: bitand,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_bitor_parallelized,
    display_name: bitor,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: scalar_bitxor_parallelized,
    display_name: bitxor,
    rng_func: default_scalar
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

define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_eq_parallelized,
    display_name: equal,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_ne_parallelized,
    display_name: not_equal,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_le_parallelized,
    display_name: less_or_equal,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_lt_parallelized,
    display_name: less_than,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_ge_parallelized,
    display_name: greater_or_equal,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_gt_parallelized,
    display_name: greater_than,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_max_parallelized,
    display_name: max,
    rng_func: default_scalar
);
define_server_key_bench_scalar_fn!(
    method_name: smart_scalar_min_parallelized,
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
    method_name: unchecked_scalar_mul_parallelized,
    display_name: mul,
    rng_func: mul_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_div_parallelized,
    display_name: div,
    rng_func: div_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_rem_parallelized,
    display_name: modulo,
    rng_func: div_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_div_rem_parallelized,
    display_name: div_mod,
    rng_func: div_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_rotate_right_parallelized,
    display_name: rotate_right,
    rng_func: shift_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_rotate_left_parallelized,
    display_name: rotate_left,
    rng_func: shift_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_right_shift_parallelized,
    display_name: right_shift,
    rng_func: shift_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_left_shift_parallelized,
    display_name: left_shift,
    rng_func: shift_scalar
);

define_server_key_bench_unary_fn!(method_name: smart_neg, display_name: negation);
define_server_key_bench_unary_fn!(method_name: smart_neg_parallelized, display_name: negation);
define_server_key_bench_unary_fn!(method_name: smart_abs_parallelized, display_name: abs);

define_server_key_bench_unary_default_fn!(method_name: neg_parallelized, display_name: negation);
define_server_key_bench_unary_default_fn!(method_name: abs_parallelized, display_name: abs);
define_server_key_bench_unary_default_fn!(method_name: leading_zeros, display_name: leading_zeros);
define_server_key_bench_unary_default_fn!(method_name: leading_ones, display_name: leading_ones);
define_server_key_bench_unary_default_fn!(method_name: trailing_zeros, display_name: trailing_zeros);
define_server_key_bench_unary_default_fn!(method_name: trailing_ones, display_name: trailing_ones);
define_server_key_bench_unary_default_fn!(method_name: ilog2, display_name: ilog2);
define_server_key_bench_unary_default_fn!(method_name: checked_ilog2, display_name: checked_ilog2);

define_server_key_bench_unary_default_fn!(method_name: unchecked_abs_parallelized, display_name: abs);

define_server_key_bench_default_fn!(method_name: unchecked_max, display_name: max);
define_server_key_bench_default_fn!(method_name: unchecked_min, display_name: min);
define_server_key_bench_default_fn!(method_name: unchecked_eq, display_name: equal);
define_server_key_bench_default_fn!(method_name: unchecked_ne, display_name: not_equal);
define_server_key_bench_default_fn!(method_name: unchecked_lt, display_name: less_than);
define_server_key_bench_default_fn!(method_name: unchecked_le, display_name: less_or_equal);
define_server_key_bench_default_fn!(method_name: unchecked_gt, display_name: greater_than);
define_server_key_bench_default_fn!(method_name: unchecked_ge, display_name: greater_or_equal);

define_server_key_bench_default_fn!(method_name: unchecked_max_parallelized, display_name: max);
define_server_key_bench_default_fn!(method_name: unchecked_min_parallelized, display_name: min);
define_server_key_bench_default_fn!(method_name: unchecked_eq_parallelized, display_name: equal);
define_server_key_bench_default_fn!(method_name: unchecked_ne_parallelized, display_name: not_equal);
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

define_server_key_bench_scalar_default_fn!(method_name: unchecked_scalar_max_parallelized, display_name: max,rng_func: default_scalar);
define_server_key_bench_scalar_default_fn!(method_name: unchecked_scalar_min_parallelized, display_name: min,rng_func: default_scalar);
define_server_key_bench_scalar_default_fn!(method_name: unchecked_scalar_eq_parallelized, display_name: equal,rng_func: default_scalar);
define_server_key_bench_scalar_default_fn!(method_name: unchecked_scalar_ne_parallelized, display_name: not_equal,rng_func: default_scalar);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_lt_parallelized,
    display_name: less_than,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_le_parallelized,
    display_name: less_or_equal,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_gt_parallelized,
    display_name: greater_than,
    rng_func: default_scalar
);
define_server_key_bench_scalar_default_fn!(
    method_name: unchecked_scalar_ge_parallelized,
    display_name: greater_or_equal,
    rng_func: default_scalar
);

define_server_key_bench_fn!(method_name: smart_max, display_name: max);
define_server_key_bench_fn!(method_name: smart_min, display_name: min);
define_server_key_bench_fn!(method_name: smart_eq, display_name: equal);
define_server_key_bench_fn!(method_name: smart_ne, display_name: not_equal);
define_server_key_bench_fn!(method_name: smart_lt, display_name: less_than);
define_server_key_bench_fn!(method_name: smart_le, display_name: less_or_equal);
define_server_key_bench_fn!(method_name: smart_gt, display_name: greater_than);
define_server_key_bench_fn!(method_name: smart_ge, display_name: greater_or_equal);

define_server_key_bench_fn!(method_name: smart_max_parallelized, display_name: max);
define_server_key_bench_fn!(method_name: smart_min_parallelized, display_name: min);
define_server_key_bench_fn!(method_name: smart_eq_parallelized, display_name: equal);
define_server_key_bench_fn!(method_name: smart_ne_parallelized, display_name: not_equal);
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

#[cfg(feature = "gpu")]
mod cuda {
    use super::*;
    use crate::utilities::{write_to_json, EnvConfig, OperatorType};
    use criterion::{criterion_group, Criterion};
    use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::server_key::CudaServerKey;
    use tfhe::integer::keycache::KEY_CACHE;
    use tfhe::integer::IntegerKeyKind;
    use tfhe::keycache::NamedParam;

    fn bench_cuda_server_key_unary_function_clean_inputs<F>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        unary_op: F,
    ) where
        F: Fn(&CudaServerKey, &mut CudaUnsignedRadixCiphertext, &CudaStream),
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

                let encrypt_gpu = || {
                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                    let ct_0 = cks.encrypt_radix(clear_0, num_block);

                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_0, &stream)
                };

                b.iter_batched(
                    encrypt_gpu,
                    |mut ct_0| {
                        unary_op(&gpu_sks, &mut ct_0, &stream);
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

    /// Base function to bench a server key function that is a binary operation, input ciphertext
    /// will contain only zero carries
    fn bench_cuda_server_key_binary_function_clean_inputs<F>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        binary_op: F,
    ) where
        F: Fn(
            &CudaServerKey,
            &mut CudaUnsignedRadixCiphertext,
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
                    let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                    let ct_0 = cks.encrypt_radix(clear_0, num_block);

                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_1 = tfhe::integer::U256::from((clearlow, clearhigh));
                    let ct_1 = cks.encrypt_radix(clear_1, num_block);

                    let d_ctxt_1 =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_0, &stream);
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

    fn bench_cuda_server_key_binary_scalar_function_clean_inputs<F, G>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        binary_op: F,
        rng_func: G,
    ) where
        F: Fn(&CudaServerKey, &mut CudaUnsignedRadixCiphertext, ScalarType, &CudaStream),
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
                    let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                    let ct_0 = cks.encrypt_radix(clear_0, num_block);

                    let d_ctxt_1 =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_0, &stream);

                    let clear_1 = rng_func(&mut rng, bit_size) & max_value_for_bit_size;

                    (d_ctxt_1, clear_1)
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

    fn cuda_default_if_then_else(c: &mut Criterion) {
        let mut bench_group = c.benchmark_group("integer::cuda::if_then_else");
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
                    let ct_cond =
                        cks.encrypt_radix(tfhe::integer::U256::from(clear_cond), num_block);

                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                    let ct_then = cks.encrypt_radix(clear_0, num_block);

                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();
                    let clear_1 = tfhe::integer::U256::from((clearlow, clearhigh));
                    let ct_else = cks.encrypt_radix(clear_1, num_block);

                    let d_ct_cond =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_cond, &stream);
                    let d_ct_then =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_then, &stream);
                    let d_ct_else =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_else, &stream);

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

    macro_rules! define_cuda_server_key_bench_clean_input_unary_fn (
        (method_name: $server_key_method:ident, display_name:$name:ident) => {
            ::paste::paste!{
                fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                    bench_cuda_server_key_unary_function_clean_inputs(
                        c,
                        concat!("integer::cuda::", stringify!($server_key_method)),
                        stringify!($name),
                        |server_key, lhs, stream| {
                            server_key.$server_key_method(lhs, stream);
                        }
                    )
                }
            }
        }
      );

    macro_rules! define_cuda_server_key_bench_clean_input_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        ::paste::paste!{
            fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                bench_cuda_server_key_binary_function_clean_inputs(
                    c,
                    concat!("integer::cuda::", stringify!($server_key_method)),
                    stringify!($name),
                    |server_key, lhs, rhs, stream| {
                        server_key.$server_key_method(lhs, rhs, stream);
                    }
                )
            }
        }
    }
  );

    macro_rules! define_cuda_server_key_bench_clean_input_scalar_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident, rng_func:$($rng_fn:tt)*) => {
        ::paste::paste!{
            fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                bench_cuda_server_key_binary_scalar_function_clean_inputs(
                    c,
                    concat!("integer::cuda::", stringify!($server_key_method)),
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

    //===========================================
    // Unchecked
    //===========================================
    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: unchecked_neg,
        display_name: negation
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_bitand,
        display_name: bitand
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_bitor,
        display_name: bitor
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_bitxor,
        display_name: bitxor
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_mul,
        display_name: mul
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_add,
        display_name: add
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_sub,
        display_name: sub
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_eq,
        display_name: equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_ne,
        display_name: not_equal
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_bitand,
        display_name: bitand,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_bitor,
        display_name: bitand,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_bitxor,
        display_name: bitand,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_add,
        display_name: add,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_sub,
        display_name: sub,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_left_shift,
        display_name: left_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_right_shift,
        display_name: right_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_left_rotate,
        display_name: left_rotate,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_right_rotate,
        display_name: right_rotate,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_eq,
        display_name: equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_ne,
        display_name: not_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_gt,
        display_name: greater_than,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_ge,
        display_name: greater_or_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_lt,
        display_name: less_than,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_le,
        display_name: less_or_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_max,
        display_name: max,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_min,
        display_name: min,
        rng_func: default_scalar
    );

    //===========================================
    // Default
    //===========================================

    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: neg,
        display_name: negation
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: add,
        display_name: add
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: sub,
        display_name: sub
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: mul,
        display_name: mul
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: ne,
        display_name: not_equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: eq,
        display_name: equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: bitand,
        display_name: bitand
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: bitor,
        display_name: bitor
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: bitxor,
        display_name: bitxor
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: gt,
        display_name: greater_than
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: ge,
        display_name: greater_or_equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: lt,
        display_name: less_than
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: le,
        display_name: less_or_equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: max,
        display_name: max
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: min,
        display_name: min
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_sub,
        display_name: sub,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_add,
        display_name: add,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_left_shift,
        display_name: left_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_right_shift,
        display_name: right_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_bitand,
        display_name: bitand,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_bitor,
        display_name: bitor,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_bitxor,
        display_name: bitxor,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_eq,
        display_name: equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_ne,
        display_name: not_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_gt,
        display_name: greater_than,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_ge,
        display_name: greater_or_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_lt,
        display_name: less_than,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_le,
        display_name: less_or_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_max,
        display_name: max,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_min,
        display_name: min,
        rng_func: default_scalar
    );

    criterion_group!(
        unchecked_cuda_ops,
        cuda_unchecked_neg,
        cuda_unchecked_bitand,
        cuda_unchecked_bitor,
        cuda_unchecked_bitxor,
        cuda_unchecked_mul,
        cuda_unchecked_sub,
        cuda_unchecked_add,
        cuda_unchecked_eq,
        cuda_unchecked_ne,
    );

    criterion_group!(
        unchecked_scalar_cuda_ops,
        cuda_unchecked_scalar_bitand,
        cuda_unchecked_scalar_bitor,
        cuda_unchecked_scalar_bitxor,
        cuda_unchecked_scalar_add,
        cuda_unchecked_scalar_sub,
        cuda_unchecked_scalar_left_shift,
        cuda_unchecked_scalar_right_shift,
        cuda_unchecked_scalar_left_rotate,
        cuda_unchecked_scalar_right_rotate,
        cuda_unchecked_scalar_ge,
        cuda_unchecked_scalar_gt,
        cuda_unchecked_scalar_le,
        cuda_unchecked_scalar_lt,
        cuda_unchecked_scalar_max,
        cuda_unchecked_scalar_min,
    );

    criterion_group!(
        default_cuda_ops,
        cuda_neg,
        cuda_sub,
        cuda_add,
        cuda_mul,
        cuda_eq,
        cuda_ne,
        cuda_ge,
        cuda_gt,
        cuda_le,
        cuda_lt,
        cuda_max,
        cuda_min,
        cuda_bitand,
        cuda_bitor,
        cuda_bitxor,
        cuda_default_if_then_else,
    );

    criterion_group!(
        default_scalar_cuda_ops,
        cuda_scalar_sub,
        cuda_scalar_add,
        cuda_scalar_left_shift,
        cuda_scalar_right_shift,
        cuda_scalar_bitand,
        cuda_scalar_bitor,
        cuda_scalar_bitxor,
        cuda_scalar_ge,
        cuda_scalar_gt,
        cuda_scalar_le,
        cuda_scalar_lt,
        cuda_scalar_max,
        cuda_scalar_min,
    );

    fn cuda_bench_server_key_cast_function<F>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        cast_op: F,
    ) where
        F: Fn(&CudaServerKey, CudaUnsignedRadixCiphertext, usize),
    {
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));
        let mut rng = rand::thread_rng();

        let env_config = EnvConfig::new();
        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        for (param, num_blocks, bit_size) in ParamsAndNumBlocksIter::default() {
            let all_num_blocks = env_config
                .bit_sizes()
                .iter()
                .copied()
                .map(|bit| bit.div_ceil(param.message_modulus().0.ilog2() as usize))
                .collect::<Vec<_>>();
            let param_name = param.name();

            for target_num_blocks in all_num_blocks.iter().copied() {
                let target_bit_size =
                    target_num_blocks * param.message_modulus().0.ilog2() as usize;
                let bench_id =
                    format!("{bench_name}::{param_name}::{bit_size}_to_{target_bit_size}");
                bench_group.bench_function(&bench_id, |b| {
                    let (cks, _sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                    let gpu_sks = CudaServerKey::new(&cks, &stream);

                    let encrypt_one_value = || -> CudaUnsignedRadixCiphertext {
                        let ct = cks.encrypt_radix(gen_random_u256(&mut rng), num_blocks);
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &stream)
                    };

                    b.iter_batched(
                        encrypt_one_value,
                        |ct| {
                            cast_op(&gpu_sks, ct, target_num_blocks);
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

    macro_rules! define_cuda_server_key_bench_cast_fn (
        (method_name: $server_key_method:ident, display_name:$name:ident) => {
            ::paste::paste!{
                fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                    bench_server_key_cast_function(
                        c,
                        concat!("integer::cuda::", stringify!($server_key_method)),
                        stringify!($name),
                        |server_key, lhs, rhs| {
                            server_key.$server_key_method(lhs, rhs);
                        })
                }
            }
        }
    );

    define_cuda_server_key_bench_cast_fn!(
        method_name: cast_to_unsigned,
        display_name: cast_to_unsigned
    );

    criterion_group!(cuda_cast_ops, cuda_cast_to_unsigned);
}

#[cfg(feature = "gpu")]
use cuda::{
    cuda_cast_ops, default_cuda_ops, default_scalar_cuda_ops, unchecked_cuda_ops,
    unchecked_scalar_cuda_ops,
};

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
    smart_ne,
    smart_lt,
    smart_le,
    smart_gt,
    smart_ge,
);

criterion_group!(
    smart_parallelized_ops,
    smart_neg_parallelized,
    smart_abs_parallelized,
    smart_add_parallelized,
    smart_sub_parallelized,
    smart_mul_parallelized,
    // smart_div_parallelized,
    // smart_rem_parallelized,
    smart_div_rem_parallelized, // For ciphertext div == rem == div_rem
    smart_bitand_parallelized,
    smart_bitor_parallelized,
    smart_bitxor_parallelized,
    smart_rotate_right_parallelized,
    smart_rotate_left_parallelized,
    smart_right_shift_parallelized,
    smart_left_shift_parallelized,
);

criterion_group!(
    smart_parallelized_ops_comp,
    smart_max_parallelized,
    smart_min_parallelized,
    smart_eq_parallelized,
    smart_ne_parallelized,
    smart_lt_parallelized,
    smart_le_parallelized,
    smart_gt_parallelized,
    smart_ge_parallelized,
);

criterion_group!(
    default_parallelized_ops,
    neg_parallelized,
    abs_parallelized,
    add_parallelized,
    unsigned_overflowing_add_parallelized,
    sub_parallelized,
    unsigned_overflowing_sub_parallelized,
    mul_parallelized,
    unsigned_overflowing_mul_parallelized,
    // div_parallelized,
    // rem_parallelized,
    div_rem_parallelized,
    bitand_parallelized,
    bitnot_parallelized,
    bitor_parallelized,
    bitxor_parallelized,
    left_shift_parallelized,
    right_shift_parallelized,
    rotate_left_parallelized,
    rotate_right_parallelized,
    ciphertexts_sum_parallelized,
    leading_zeros,
    leading_ones,
    trailing_zeros,
    trailing_ones,
    ilog2,
    checked_ilog2,
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
    smart_scalar_div_parallelized,
    smart_scalar_rem_parallelized, // For scalar rem == div_rem
    // smart_scalar_div_rem_parallelized,
    smart_scalar_bitand_parallelized,
    smart_scalar_bitor_parallelized,
    smart_scalar_bitxor_parallelized,
    smart_scalar_rotate_right_parallelized,
    smart_scalar_rotate_left_parallelized,
);

criterion_group!(
    smart_scalar_parallelized_ops_comp,
    smart_scalar_max_parallelized,
    smart_scalar_min_parallelized,
    smart_scalar_eq_parallelized,
    smart_scalar_ne_parallelized,
    smart_scalar_lt_parallelized,
    smart_scalar_le_parallelized,
    smart_scalar_gt_parallelized,
    smart_scalar_ge_parallelized,
);

criterion_group!(
    default_scalar_parallelized_ops,
    scalar_add_parallelized,
    unsigned_overflowing_scalar_add_parallelized,
    scalar_sub_parallelized,
    unsigned_overflowing_scalar_sub_parallelized,
    scalar_mul_parallelized,
    scalar_div_parallelized,
    scalar_rem_parallelized,
    // scalar_div_rem_parallelized,
    scalar_left_shift_parallelized,
    scalar_right_shift_parallelized,
    scalar_rotate_left_parallelized,
    scalar_rotate_right_parallelized,
    scalar_bitand_parallelized,
    scalar_bitor_parallelized,
    scalar_bitxor_parallelized,
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
    unchecked_parallelized_ops,
    unchecked_abs_parallelized,
    unchecked_add_parallelized,
    unchecked_mul_parallelized,
    // unchecked_div_parallelized,
    // unchecked_rem_parallelized,
    unchecked_div_rem_parallelized,
    unchecked_bitand_parallelized,
    unchecked_bitor_parallelized,
    unchecked_bitxor_parallelized,
    unchecked_rotate_right_parallelized,
    unchecked_rotate_left_parallelized,
    unchecked_right_shift_parallelized,
    unchecked_left_shift_parallelized,
);

criterion_group!(
    unchecked_parallelized_ops_comp,
    unchecked_eq_parallelized,
    unchecked_ne_parallelized,
    unchecked_gt_parallelized,
    unchecked_ge_parallelized,
    unchecked_lt_parallelized,
    unchecked_max_parallelized,
    unchecked_min_parallelized,
);

criterion_group!(
    unchecked_ops_comp,
    unchecked_max,
    unchecked_min,
    unchecked_eq,
    unchecked_ne,
    unchecked_lt,
    unchecked_le,
    unchecked_gt,
    unchecked_ge,
);

criterion_group!(
    unchecked_scalar_ops,
    unchecked_scalar_add,
    unchecked_scalar_sub,
    unchecked_scalar_mul_parallelized,
    unchecked_scalar_div_parallelized,
    unchecked_scalar_rem_parallelized,
    // unchecked_scalar_div_rem_parallelized,
    unchecked_scalar_bitand_parallelized,
    unchecked_scalar_bitor_parallelized,
    unchecked_scalar_bitxor_parallelized,
    unchecked_scalar_rotate_right_parallelized,
    unchecked_scalar_rotate_left_parallelized,
    unchecked_scalar_right_shift_parallelized,
    unchecked_scalar_left_shift_parallelized,
);

criterion_group!(
    unchecked_scalar_ops_comp,
    unchecked_scalar_max_parallelized,
    unchecked_scalar_min_parallelized,
    unchecked_scalar_eq_parallelized,
    unchecked_scalar_ne_parallelized,
    unchecked_scalar_lt_parallelized,
    unchecked_scalar_le_parallelized,
    unchecked_scalar_gt_parallelized,
    unchecked_scalar_ge_parallelized,
);

//================================================================================
//     Miscellaneous Benches
//================================================================================

fn bench_server_key_cast_function<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    cast_op: F,
) where
    F: Fn(&ServerKey, RadixCiphertext, usize),
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

                let encrypt_one_value = || cks.encrypt_radix(gen_random_u256(&mut rng), num_blocks);

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
        bench_server_key_cast_function(
              c,
              concat!("integer::", stringify!($server_key_method)),
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

define_server_key_bench_unary_fn!(method_name: full_propagate, display_name: carry_propagation);
define_server_key_bench_unary_fn!(
    method_name: full_propagate_parallelized,
    display_name: carry_propagation
);

criterion_group!(misc, full_propagate, full_propagate_parallelized);

#[cfg(feature = "gpu")]
fn go_through_gpu_bench_groups(val: &str) {
    match val.to_lowercase().as_str() {
        "default" => {
            default_cuda_ops();
            default_scalar_cuda_ops();
            cuda_cast_ops()
        }
        "unchecked" => {
            unchecked_cuda_ops();
            unchecked_scalar_cuda_ops()
        }
        _ => panic!("unknown benchmark operations flavor"),
    };
}

fn go_through_cpu_bench_groups(val: &str) {
    match val.to_lowercase().as_str() {
        "default" => {
            default_parallelized_ops();
            default_parallelized_ops_comp();
            default_scalar_parallelized_ops();
            default_scalar_parallelized_ops_comp();
            cast_ops()
        }
        "smart" => {
            smart_ops();
            smart_ops_comp();
            smart_scalar_ops();
            smart_parallelized_ops();
            smart_parallelized_ops_comp();
            smart_scalar_parallelized_ops();
            smart_scalar_parallelized_ops_comp()
        }
        "unchecked" => {
            unchecked_ops();
            unchecked_parallelized_ops();
            unchecked_ops_comp();
            unchecked_scalar_ops();
            unchecked_scalar_ops_comp()
        }
        "misc" => misc(),
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
