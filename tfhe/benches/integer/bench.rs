#![allow(dead_code)]

#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{throughput_num_threads, BenchmarkType, BENCH_TYPE};
use criterion::{criterion_group, Criterion, Throughput};
use itertools::iproduct;
use rand::prelude::*;
use rayon::prelude::*;
use std::env;
use std::vec::IntoIter;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::{RadixCiphertextBig, ServerKey};
use tfhe::shortint::keycache::NamedParam;

use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
#[allow(unused_imports)]
use tfhe::shortint::parameters::{
    PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_2_CARRY_2, PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_4_CARRY_4,
};

/// An iterator that yields a succession of combinations
/// of parameters and a num_block to achieve a certain bit_size ciphertext
/// in radix decomposition
struct ParamsAndNumBlocksIter {
    params_and_bit_sizes: itertools::Product<IntoIter<tfhe::shortint::Parameters>, IntoIter<usize>>,
}

impl Default for ParamsAndNumBlocksIter {
    fn default() -> Self {
        let is_multi_bit = match env::var("__TFHE_RS_BENCH_TYPE") {
            Ok(val) => val.to_lowercase() == "multi_bit",
            Err(_) => false,
        };

        // if is_multi_bit {
        //     let params = vec![PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS.into()];
        //     let bit_sizes = vec![8, 16, 32, 40, 64];
        //     let params_and_bit_sizes = iproduct!(params, bit_sizes);
        //     Self {
        //         params_and_bit_sizes,
        //     }
        // } else {
        // FIXME One set of parameter is tested since we want to benchmark only quickest
        // operations.
        let params = vec![
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64.into(),
            // PARAM_MESSAGE_3_CARRY_3_KS_PBS.into(),
            // PARAM_MESSAGE_4_CARRY_4_KS_PBS.into(),
        ];
        let bit_sizes = vec![64];
        let params_and_bit_sizes = iproduct!(params, bit_sizes);
        Self {
            params_and_bit_sizes,
        }
        // }
    }
}
impl Iterator for ParamsAndNumBlocksIter {
    type Item = (tfhe::shortint::Parameters, usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let (param, bit_size) = self.params_and_bit_sizes.next()?;
        let num_block =
            (bit_size as f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

        Some((param, num_block, bit_size))
    }
}

/// Base function to bench a server key function that is a binary operation
fn bench_server_key_binary_function<F>(c: &mut Criterion, bench_name: &str, binary_op: F)
where
    F: Fn(&ServerKey, &mut RadixCiphertextBig, &mut RadixCiphertextBig) + Sync,
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id;

        match BENCH_TYPE.get().unwrap() {
            BenchmarkType::Latency => {
                bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
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
                        let mut carry_mod = param.carry_modulus.0;
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
            }
            BenchmarkType::Throughput => {
                bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                bench_group
                    .sample_size(10)
                    .measurement_time(std::time::Duration::from_secs(30));
                let elements = throughput_num_threads(num_block);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let (cks, sks) = KEY_CACHE.get_from_params(param);

                    let mut cts_0 = (0..elements)
                        .map(|_| {
                            let clearlow = rng.gen::<u128>();
                            let clearhigh = rng.gen::<u128>();
                            let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                            let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

                            // Raise the degree, so as to ensure worst case path in operations
                            let mut carry_mod = param.carry_modulus.0;
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
                        })
                        .collect::<Vec<_>>();
                    let mut cts_1 = (0..elements)
                        .map(|_| {
                            let clearlow = rng.gen::<u128>();
                            let clearhigh = rng.gen::<u128>();
                            let clear_1 = tfhe::integer::U256::from((clearlow, clearhigh));
                            let mut ct_1 = cks.encrypt_radix(clear_1, num_block);

                            // Raise the degree, so as to ensure worst case path in operations
                            let mut carry_mod = param.carry_modulus.0;
                            while carry_mod > 0 {
                                // Raise the degree, so as to ensure worst case path in operations
                                let clearlow = rng.gen::<u128>();
                                let clearhigh = rng.gen::<u128>();
                                let clear_2 = tfhe::integer::U256::from((clearlow, clearhigh));
                                let ct_2 = cks.encrypt_radix(clear_2, num_block);
                                sks.unchecked_add_assign(&mut ct_1, &ct_2);

                                carry_mod -= 1;
                            }

                            ct_1
                        })
                        .collect::<Vec<_>>();

                    b.iter(|| {
                        cts_0
                            .par_iter_mut()
                            .zip(cts_1.par_iter_mut())
                            .for_each(|(ct_0, ct_1)| {
                                binary_op(&sks, ct_0, ct_1);
                            })
                    })
                });
            }
        }
    }

    bench_group.finish()
}

/// Base function to bench a server key function that is a unary operation
fn bench_server_key_unary_function<F>(c: &mut Criterion, group_name: &str, unary_fn: F)
where
    F: Fn(&ServerKey, &mut RadixCiphertextBig),
{
    let mut bench_group = c.benchmark_group(group_name);

    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id = format!("{param_name}/{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            let encrypt_one_value = || {
                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();

                let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));

                let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

                // Raise the degree, so as to ensure worst case path in operations
                let mut carry_mod = param.carry_modulus.0;
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
    }

    bench_group.finish()
}

fn bench_server_key_binary_scalar_function<F>(c: &mut Criterion, bench_name: &str, binary_op: F)
where
    F: Fn(&ServerKey, &mut RadixCiphertextBig, u64),
{
    let mut bench_group = c.benchmark_group(bench_name);
    let mut rng = rand::thread_rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id = format!("{param_name}/{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            let encrypt_one_value = || {
                let clearlow = rng.gen::<u128>();
                let clearhigh = rng.gen::<u128>();

                let clear_0 = tfhe::integer::U256::from((clearlow, clearhigh));
                let ct_0 = cks.encrypt_radix(clear_0, num_block);

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
    }

    bench_group.finish()
}

macro_rules! define_server_key_bench_unary_fn (
    ($server_key_method:ident) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_unary_function(
                c,
                concat!("ServerKey::", stringify!($server_key_method)),
                |server_key, lhs| {
                  server_key.$server_key_method(lhs);
            })
        }
    }
  );

macro_rules! define_server_key_bench_fn (
  ($server_key_method:ident) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_function(
              c,
              concat!("ServerKey::", stringify!($server_key_method)),
              |server_key, lhs, rhs| {
                server_key.$server_key_method(lhs, rhs);
          })
      }
  }
);

macro_rules! define_server_key_bench_scalar_fn (
  ($server_key_method:ident) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_scalar_function(
              c,
              concat!("ServerKey::", stringify!($server_key_method)),
              |server_key, lhs, rhs| {
                server_key.$server_key_method(lhs, rhs);
          })
      }
  }
);

define_server_key_bench_fn!(smart_add);
define_server_key_bench_fn!(smart_sub);
define_server_key_bench_fn!(smart_mul);
define_server_key_bench_fn!(smart_bitand);
define_server_key_bench_fn!(smart_bitor);
define_server_key_bench_fn!(smart_bitxor);

define_server_key_bench_fn!(smart_add_parallelized);
define_server_key_bench_fn!(smart_sub_parallelized);
define_server_key_bench_fn!(smart_mul_parallelized);
define_server_key_bench_fn!(smart_bitand_parallelized);
define_server_key_bench_fn!(smart_bitxor_parallelized);
define_server_key_bench_fn!(smart_bitor_parallelized);

define_server_key_bench_fn!(unchecked_add);
define_server_key_bench_fn!(unchecked_sub);
define_server_key_bench_fn!(unchecked_mul);
define_server_key_bench_fn!(unchecked_bitand);
define_server_key_bench_fn!(unchecked_bitor);
define_server_key_bench_fn!(unchecked_bitxor);

define_server_key_bench_fn!(unchecked_mul_parallelized);
define_server_key_bench_fn!(unchecked_bitand_parallelized);
define_server_key_bench_fn!(unchecked_bitor_parallelized);
define_server_key_bench_fn!(unchecked_bitxor_parallelized);

define_server_key_bench_scalar_fn!(smart_scalar_add);
define_server_key_bench_scalar_fn!(smart_scalar_sub);
define_server_key_bench_scalar_fn!(smart_scalar_mul);

define_server_key_bench_scalar_fn!(smart_scalar_add_parallelized);
define_server_key_bench_scalar_fn!(smart_scalar_sub_parallelized);
define_server_key_bench_scalar_fn!(smart_scalar_mul_parallelized);

define_server_key_bench_scalar_fn!(unchecked_scalar_add);
define_server_key_bench_scalar_fn!(unchecked_scalar_sub);
define_server_key_bench_scalar_fn!(unchecked_small_scalar_mul);

define_server_key_bench_unary_fn!(smart_neg);
define_server_key_bench_unary_fn!(full_propagate);
define_server_key_bench_unary_fn!(full_propagate_parallelized);

define_server_key_bench_fn!(unchecked_max);
define_server_key_bench_fn!(unchecked_min);
define_server_key_bench_fn!(unchecked_eq);
define_server_key_bench_fn!(unchecked_lt);
define_server_key_bench_fn!(unchecked_le);
define_server_key_bench_fn!(unchecked_gt);
define_server_key_bench_fn!(unchecked_ge);

define_server_key_bench_fn!(unchecked_max_parallelized);
define_server_key_bench_fn!(unchecked_min_parallelized);
define_server_key_bench_fn!(unchecked_eq_parallelized);
define_server_key_bench_fn!(unchecked_lt_parallelized);
define_server_key_bench_fn!(unchecked_le_parallelized);
define_server_key_bench_fn!(unchecked_gt_parallelized);
define_server_key_bench_fn!(unchecked_ge_parallelized);

define_server_key_bench_fn!(smart_max);
define_server_key_bench_fn!(smart_min);
define_server_key_bench_fn!(smart_eq);
define_server_key_bench_fn!(smart_lt);
define_server_key_bench_fn!(smart_le);
define_server_key_bench_fn!(smart_gt);
define_server_key_bench_fn!(smart_ge);

define_server_key_bench_fn!(smart_max_parallelized);
define_server_key_bench_fn!(smart_min_parallelized);
define_server_key_bench_fn!(smart_eq_parallelized);
define_server_key_bench_fn!(smart_lt_parallelized);
define_server_key_bench_fn!(smart_le_parallelized);
define_server_key_bench_fn!(smart_gt_parallelized);
define_server_key_bench_fn!(smart_ge_parallelized);

criterion_group!(
    smart_arithmetic_operation,
    smart_neg,
    smart_add,
    smart_mul,
    smart_bitand,
    smart_bitor,
    smart_bitxor,
    smart_max,
    smart_min,
    smart_eq,
    smart_lt,
    smart_le,
    smart_gt,
    smart_ge,
);

criterion_group!(
    smart_arithmetic_parallelized_operation,
    smart_add_parallelized,
    // smart_sub_parallelized,
    smart_mul_parallelized,
    // smart_bitand_parallelized,
    // smart_bitor_parallelized,
    // smart_bitxor_parallelized,
    // smart_max_parallelized,
    // smart_min_parallelized,
    // smart_eq_parallelized,
    // smart_lt_parallelized,
    // smart_le_parallelized,
    smart_gt_parallelized,
    // smart_ge_parallelized,
);

criterion_group!(
    smart_scalar_arithmetic_operation,
    smart_scalar_add,
    smart_scalar_sub,
    smart_scalar_mul,
);

criterion_group!(
    smart_scalar_arithmetic_parallel_operation,
    smart_scalar_add_parallelized,
    smart_scalar_sub_parallelized,
    smart_scalar_mul_parallelized,
);

criterion_group!(
    unchecked_arithmetic_operation,
    unchecked_add,
    unchecked_sub,
    unchecked_mul,
    unchecked_bitand,
    unchecked_bitor,
    unchecked_bitxor,
    unchecked_max,
    unchecked_min,
    unchecked_eq,
    unchecked_lt,
    unchecked_le,
    unchecked_gt,
    unchecked_ge,
);

criterion_group!(
    unchecked_scalar_arithmetic_operation,
    unchecked_scalar_add,
    unchecked_scalar_sub,
    unchecked_small_scalar_mul,
    unchecked_max_parallelized,
    unchecked_min_parallelized,
    unchecked_eq_parallelized,
    unchecked_lt_parallelized,
    unchecked_le_parallelized,
    unchecked_gt_parallelized,
    unchecked_ge_parallelized,
    unchecked_bitand_parallelized,
    unchecked_bitor_parallelized,
    unchecked_bitxor_parallelized,
);

criterion_group!(misc, full_propagate, full_propagate_parallelized);

fn main() {
    BENCH_TYPE.get_or_init(|| BenchmarkType::from_env().unwrap());

    smart_arithmetic_parallelized_operation();

    Criterion::default().configure_from_args().final_summary();
}
