#![allow(dead_code)]

mod aes;
mod aes256;
mod kreyvium;
mod oprf;
mod trivium;
mod vector_find;

mod rerand;

use benchmark::params::ParamsAndNumBlocksIter;
use benchmark::utilities::{
    get_bench_type, throughput_num_threads, write_to_json, BenchmarkType, EnvConfig, OperatorType,
};
use criterion::{criterion_group, Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use std::cell::LazyCell;
use std::cmp::max;
use std::env;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::prelude::*;
use tfhe::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey, U256};
use tfhe::keycache::NamedParam;
use tfhe::{get_pbs_count, reset_pbs_count};

/// The type used to hold scalar values
/// It must be as big as the largest bit size tested
type ScalarType = U256;

fn gen_random_u256(rng: &mut ThreadRng) -> U256 {
    let clearlow = rng.gen::<u128>();
    let clearhigh = rng.gen::<u128>();

    tfhe::integer::U256::from((clearlow, clearhigh))
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
    let mut rng = rand::rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let keys = LazyCell::new(move || KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix));

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = (&keys.0, &keys.1);

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
                    binary_op(sks, &mut ct_0, &mut ct_1);
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
    F: Fn(&ServerKey, &RadixCiphertext, &RadixCiphertext) + Sync,
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let bench_data = LazyCell::new(|| {
                    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                    let clear_0 = gen_random_u256(&mut rng);
                    let clear_1 = gen_random_u256(&mut rng);

                    let ct_0 = cks.encrypt_radix(clear_0, num_block);
                    let ct_1 = cks.encrypt_radix(clear_1, num_block);
                    (sks, ct_0, ct_1)
                });

                bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
                bench_group.bench_function(&bench_id, |b| {
                    let (sks, ct_0, ct_1) = (&bench_data.0, &bench_data.1, &bench_data.2);
                    b.iter(|| {
                        binary_op(sks, ct_0, ct_1);
                    })
                });
            }
            BenchmarkType::Throughput => {
                let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                // Execute the operation once to know its cost.
                let clear_0 = gen_random_u256(&mut rng);
                let ct_0 = cks.encrypt_radix(clear_0, num_block);
                let clear_1 = gen_random_u256(&mut rng);
                let ct_1 = cks.encrypt_radix(clear_1, num_block);

                reset_pbs_count();
                binary_op(&sks, &ct_0, &ct_1);
                let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                bench_group
                    .sample_size(10)
                    .measurement_time(std::time::Duration::from_secs(30));
                let elements = throughput_num_threads(num_block, pbs_count);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let cts_0 = (0..elements)
                            .map(|_| cks.encrypt_radix(gen_random_u256(&mut rng), num_block))
                            .collect::<Vec<_>>();
                        let cts_1 = (0..elements)
                            .map(|_| cks.encrypt_radix(gen_random_u256(&mut rng), num_block))
                            .collect::<Vec<_>>();

                        (cts_0, cts_1)
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(cts_0, cts_1)| {
                            cts_0
                                .par_iter()
                                .zip(cts_1.par_iter())
                                .for_each(|(ct_0, ct_1)| {
                                    binary_op(&sks, ct_0, ct_1);
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

    let mut rng = rand::rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let keys = LazyCell::new(move || KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix));

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = (&keys.0, &keys.1);

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
                    unary_fn(sks, &mut ct_0);
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
    F: Fn(&ServerKey, &RadixCiphertext) + Sync,
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    let mut rng = rand::rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let bench_data = LazyCell::new(|| {
                    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                    let clear_0 = gen_random_u256(&mut rng);

                    let ct_0 = cks.encrypt_radix(clear_0, num_block);
                    (sks, ct_0)
                });

                bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
                bench_group.bench_function(&bench_id, |b| {
                    let (sks, ct_0) = (&bench_data.0, &bench_data.1);

                    b.iter(|| {
                        unary_fn(sks, ct_0);
                    })
                });
            }
            BenchmarkType::Throughput => {
                let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                // Execute the operation once to know its cost.
                let clear_0 = gen_random_u256(&mut rng);
                let ct_0 = cks.encrypt_radix(clear_0, num_block);

                reset_pbs_count();
                unary_fn(&sks, &ct_0);
                let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                bench_group
                    .sample_size(10)
                    .measurement_time(std::time::Duration::from_secs(30));
                let elements = throughput_num_threads(num_block, pbs_count);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        (0..elements)
                            .map(|_| cks.encrypt_radix(gen_random_u256(&mut rng), num_block))
                            .collect::<Vec<_>>()
                    };
                    b.iter_batched(
                        setup_encrypted_values,
                        |cts| {
                            cts.par_iter().for_each(|ct_0| {
                                unary_fn(&sks, ct_0);
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
    let mut rng = rand::rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let max_value_for_bit_size = ScalarType::MAX >> (ScalarType::BITS as usize - bit_size);

        let keys = LazyCell::new(move || KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix));

        let bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            let (cks, sks) = (&keys.0, &keys.1);

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
                    binary_op(sks, &mut ct_0, clear_1);
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
    F: Fn(&ServerKey, &RadixCiphertext, ScalarType) + Sync,
    G: Fn(&mut ThreadRng, usize) -> ScalarType,
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        if bit_size > ScalarType::BITS as usize {
            break;
        }
        let param_name = param.name();

        let max_value_for_bit_size = ScalarType::MAX >> (ScalarType::BITS as usize - bit_size);

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let bench_data =
                    LazyCell::new(|| KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix));

                bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits_scalar_{bit_size}");
                bench_group.bench_function(&bench_id, |b| {
                    let (cks, sks) = (&bench_data.0, &bench_data.1);

                    b.iter_batched(
                        || {
                            let clear_0 = gen_random_u256(&mut rng);
                            let clear_1 = rng_func(&mut rng, bit_size) & max_value_for_bit_size;

                            let ct_0 = cks.encrypt_radix(clear_0, num_block);
                            (ct_0, clear_1)
                        },
                        |(ct_0, clear_1)| {
                            binary_op(sks, &ct_0, clear_1);
                        },
                        criterion::BatchSize::SmallInput,
                    )
                });
            }
            BenchmarkType::Throughput => {
                let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                // Execute the operation once to know its cost.
                let clear_0 = gen_random_u256(&mut rng);
                let mut ct_0 = cks.encrypt_radix(clear_0, num_block);
                let clear_1 = rng_func(&mut rng, bit_size) & max_value_for_bit_size;

                reset_pbs_count();
                binary_op(&sks, &mut ct_0, clear_1);
                let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                bench_group
                    .sample_size(10)
                    .measurement_time(std::time::Duration::from_secs(30));
                let elements = throughput_num_threads(num_block, pbs_count);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let cts_0 = (0..elements)
                            .map(|_| cks.encrypt_radix(gen_random_u256(&mut rng), num_block))
                            .collect::<Vec<_>>();
                        let clears_1 = (0..elements)
                            .map(|_| rng_func(&mut rng, bit_size) & max_value_for_bit_size)
                            .collect::<Vec<_>>();

                        (cts_0, clears_1)
                    };
                    b.iter_batched(
                        setup_encrypted_values,
                        |(mut cts_0, clears_1)| {
                            cts_0.par_iter_mut().zip(clears_1.par_iter()).for_each(
                                |(ct_0, clear_1)| {
                                    binary_op(&sks, ct_0, *clear_1);
                                },
                            )
                        },
                        criterion::BatchSize::SmallInput,
                    )
                });
            }
        }

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
    let mut rng = rand::rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let bench_data = LazyCell::new(|| {
                    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                    let clear_0 = gen_random_u256(&mut rng);
                    let clear_1 = gen_random_u256(&mut rng);
                    let clear_cond = rng.gen_bool(0.5);

                    let true_ct = cks.encrypt_radix(clear_0, num_block);
                    let false_ct = cks.encrypt_radix(clear_1, num_block);
                    let condition = cks.encrypt_bool(clear_cond);

                    (sks, condition, true_ct, false_ct)
                });

                bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
                bench_group.bench_function(&bench_id, |b| {
                    let (sks, condition, true_ct, false_ct) =
                        (&bench_data.0, &bench_data.1, &bench_data.2, &bench_data.3);

                    b.iter(|| sks.if_then_else_parallelized(condition, true_ct, false_ct))
                });
            }
            BenchmarkType::Throughput => {
                let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                // Execute the operation once to know its cost.
                let clear_0 = gen_random_u256(&mut rng);
                let true_ct = cks.encrypt_radix(clear_0, num_block);

                let clear_1 = gen_random_u256(&mut rng);
                let false_ct = cks.encrypt_radix(clear_1, num_block);

                let condition = cks.encrypt_bool(rng.gen_bool(0.5));

                reset_pbs_count();
                sks.if_then_else_parallelized(&condition, &true_ct, &false_ct);
                let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                bench_group
                    .sample_size(10)
                    .measurement_time(std::time::Duration::from_secs(30));
                let elements = throughput_num_threads(num_block, pbs_count);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let cts_cond = (0..elements)
                            .map(|_| cks.encrypt_bool(rng.gen_bool(0.5)))
                            .collect::<Vec<_>>();

                        let cts_then = (0..elements)
                            .map(|_| cks.encrypt_radix(gen_random_u256(&mut rng), num_block))
                            .collect::<Vec<_>>();
                        let cts_else = (0..elements)
                            .map(|_| cks.encrypt_radix(gen_random_u256(&mut rng), num_block))
                            .collect::<Vec<_>>();

                        (cts_cond, cts_then, cts_else)
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(cts_cond, cts_then, cts_else)| {
                            cts_cond
                                .par_iter()
                                .zip(cts_then.par_iter())
                                .zip(cts_else.par_iter())
                                .for_each(|((condition, true_ct), false_ct)| {
                                    sks.if_then_else_parallelized(condition, true_ct, false_ct);
                                })
                        },
                        criterion::BatchSize::SmallInput,
                    );
                });
            }
        }

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

fn flip_parallelized(c: &mut Criterion) {
    let bench_name = "integer::flip_parallelized";
    let display_name = "flip";

    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let bench_data = LazyCell::new(|| {
                    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                    let clear_0 = gen_random_u256(&mut rng);
                    let clear_1 = gen_random_u256(&mut rng);
                    let clear_cond = rng.gen_bool(0.5);

                    let true_ct = cks.encrypt_radix(clear_0, num_block);
                    let false_ct = cks.encrypt_radix(clear_1, num_block);
                    let condition = cks.encrypt_bool(clear_cond);

                    (sks, condition, true_ct, false_ct)
                });

                bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
                bench_group.bench_function(&bench_id, |b| {
                    let (sks, condition, true_ct, false_ct) =
                        (&bench_data.0, &bench_data.1, &bench_data.2, &bench_data.3);

                    b.iter(|| sks.flip_parallelized(condition, true_ct, false_ct))
                });
            }
            BenchmarkType::Throughput => {
                let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                // Execute the operation once to know its cost.
                let clear_0 = gen_random_u256(&mut rng);
                let true_ct = cks.encrypt_radix(clear_0, num_block);

                let clear_1 = gen_random_u256(&mut rng);
                let false_ct = cks.encrypt_radix(clear_1, num_block);

                let condition = cks.encrypt_bool(rng.gen_bool(0.5));

                reset_pbs_count();
                sks.flip_parallelized(&condition, &true_ct, &false_ct);
                let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                bench_group
                    .sample_size(10)
                    .measurement_time(std::time::Duration::from_secs(30));
                let elements = throughput_num_threads(num_block, pbs_count);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let cts_cond = (0..elements)
                            .map(|_| cks.encrypt_bool(rng.gen_bool(0.5)))
                            .collect::<Vec<_>>();

                        let cts_then = (0..elements)
                            .map(|_| cks.encrypt_radix(gen_random_u256(&mut rng), num_block))
                            .collect::<Vec<_>>();
                        let cts_else = (0..elements)
                            .map(|_| cks.encrypt_radix(gen_random_u256(&mut rng), num_block))
                            .collect::<Vec<_>>();

                        (cts_cond, cts_then, cts_else)
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(cts_cond, cts_then, cts_else)| {
                            cts_cond
                                .par_iter()
                                .zip(cts_then.par_iter())
                                .zip(cts_else.par_iter())
                                .for_each(|((condition, true_ct), false_ct)| {
                                    sks.flip_parallelized(condition, true_ct, false_ct);
                                })
                        },
                        criterion::BatchSize::SmallInput,
                    );
                });
            }
        }

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
    let mut rng = rand::rng();

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();
        let max_for_bit_size = ScalarType::MAX >> (ScalarType::BITS as usize - bit_size);

        for len in [5, 10, 20] {
            let bench_id;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let bench_data = LazyCell::new(|| {
                        let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                        let clears = (0..len)
                            .map(|_| gen_random_u256(&mut rng) & max_for_bit_size)
                            .collect::<Vec<_>>();

                        // encryption of integers
                        let ctxts = clears
                            .iter()
                            .copied()
                            .map(|clear| cks.encrypt_radix(clear, num_block))
                            .collect::<Vec<_>>();

                        (sks, ctxts)
                    });

                    bench_id = format!("{bench_name}_{len}_ctxts::{param_name}::{bit_size}_bits");
                    bench_group.bench_function(&bench_id, |b| {
                        let (sks, ctxts) = (&bench_data.0, &bench_data.1);

                        b.iter(|| sks.sum_ciphertexts_parallelized(ctxts))
                    });
                }
                BenchmarkType::Throughput => {
                    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                    // Execute the operation once to know its cost.
                    let nb_ctxt = bit_size.div_ceil(param.message_modulus().0.ilog2() as usize);
                    let cks = RadixClientKey::from((cks, nb_ctxt));

                    let clears = (0..len)
                        .map(|_| gen_random_u256(&mut rng) & max_for_bit_size)
                        .collect::<Vec<_>>();
                    let ctxts = clears
                        .iter()
                        .copied()
                        .map(|clear| cks.encrypt(clear))
                        .collect::<Vec<_>>();

                    reset_pbs_count();
                    sks.sum_ciphertexts_parallelized(&ctxts);
                    let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                    bench_id = format!(
                        "{bench_name}_{len}_ctxts::throughput::{param_name}::{bit_size}_bits"
                    );
                    bench_group
                        .sample_size(10)
                        .measurement_time(std::time::Duration::from_secs(30));
                    let elements = throughput_num_threads(num_block, pbs_count);
                    bench_group.throughput(Throughput::Elements(elements));
                    bench_group.bench_function(&bench_id, |b| {
                        let setup_encrypted_values = || {
                            (0..elements)
                                .map(|_| {
                                    let clears = (0..len)
                                        .map(|_| gen_random_u256(&mut rng) & max_for_bit_size)
                                        .collect::<Vec<_>>();

                                    let ctxts = clears
                                        .iter()
                                        .copied()
                                        .map(|clear| cks.encrypt(clear))
                                        .collect::<Vec<_>>();

                                    ctxts
                                })
                                .collect::<Vec<_>>()
                        };

                        b.iter_batched(
                            setup_encrypted_values,
                            |cts| {
                                cts.par_iter().for_each(|ctxts| {
                                    sks.sum_ciphertexts_parallelized(ctxts);
                                })
                            },
                            criterion::BatchSize::SmallInput,
                        );
                    });
                }
            }

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
                }
            )
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
define_server_key_bench_unary_default_fn!(method_name: bitnot, display_name: bitnot);

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
define_server_key_bench_unary_default_fn!(method_name: leading_zeros_parallelized, display_name: leading_zeros);
define_server_key_bench_unary_default_fn!(method_name: leading_ones_parallelized, display_name: leading_ones);
define_server_key_bench_unary_default_fn!(method_name: trailing_zeros_parallelized, display_name: trailing_zeros);
define_server_key_bench_unary_default_fn!(method_name: trailing_ones_parallelized, display_name: trailing_ones);
define_server_key_bench_unary_default_fn!(method_name: ilog2_parallelized, display_name: ilog2);
define_server_key_bench_unary_default_fn!(method_name: count_ones_parallelized, display_name: count_ones);
define_server_key_bench_unary_default_fn!(method_name: count_zeros_parallelized, display_name: count_zeros);
define_server_key_bench_unary_default_fn!(method_name: checked_ilog2_parallelized, display_name: checked_ilog2);

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
    use benchmark::utilities::cuda_integer_utils::{cuda_local_keys, cuda_local_streams};
    use criterion::criterion_group;
    use std::cmp::max;
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::server_key::CudaServerKey;
    use tfhe::integer::{RadixCiphertext, ServerKey};

    fn bench_cuda_server_key_unary_function_clean_inputs<F, G>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        unary_op: F,
        unary_op_cpu: G,
    ) where
        F: Fn(&CudaServerKey, &mut CudaUnsignedRadixCiphertext, &CudaStreams) + Sync,
        G: Fn(&ServerKey, &mut RadixCiphertext) + Sync,
    {
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));
        let mut rng = rand::rng();

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            let param_name = param.name();

            let bench_id;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let streams = CudaStreams::new_multi_gpu();
                    bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");

                    bench_group.bench_function(&bench_id, |b| {
                        let (cks, _cpu_sks) =
                            KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                        let gpu_sks = CudaServerKey::new(&cks, &streams);

                        let encrypt_one_value = || {
                            let ct_0 = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_0, &streams)
                        };

                        b.iter_batched(
                            encrypt_one_value,
                            |mut ct_0| {
                                unary_op(&gpu_sks, &mut ct_0, &streams);
                            },
                            criterion::BatchSize::SmallInput,
                        )
                    });
                }
                BenchmarkType::Throughput => {
                    let (cks, cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                    let gpu_count = get_number_of_gpus() as usize;
                    let gpu_sks_vec = cuda_local_keys(&cks);

                    let clear_0 = gen_random_u256(&mut rng);
                    let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

                    reset_pbs_count();
                    // Use CPU operation as pbs_count do not count PBS on GPU backend.
                    unary_op_cpu(&cpu_sks, &mut ct_0);
                    let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                    bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                    bench_group
                        .sample_size(10)
                        .measurement_time(std::time::Duration::from_secs(30));
                    let elements = throughput_num_threads(num_block, pbs_count);
                    bench_group.throughput(Throughput::Elements(elements));
                    bench_group.bench_function(&bench_id, |b| {
                        let setup_encrypted_values = || {
                            let local_streams = cuda_local_streams(num_block, elements as usize);
                            let cts = (0..elements)
                                .map(|i| {
                                    let ct_0 =
                                        cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                        &ct_0,
                                        &local_streams[i as usize],
                                    )
                                })
                                .collect::<Vec<_>>();

                            (cts, local_streams)
                        };

                        b.iter_batched(
                            setup_encrypted_values,
                            |(mut cts, local_streams)| {
                                cts.par_iter_mut()
                                    .zip(local_streams.par_iter())
                                    .enumerate()
                                    .for_each(|(i, (ct_0, local_stream))| {
                                        unary_op(&gpu_sks_vec[i % gpu_count], ct_0, local_stream);
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
    fn bench_cuda_server_key_binary_function_clean_inputs<F, G>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        binary_op: F,
        binary_op_cpu: G,
    ) where
        F: Fn(
                &CudaServerKey,
                &mut CudaUnsignedRadixCiphertext,
                &mut CudaUnsignedRadixCiphertext,
                &CudaStreams,
            ) + Sync,
        G: Fn(&ServerKey, &mut RadixCiphertext, &mut RadixCiphertext) + Sync,
    {
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));
        let mut rng = rand::rng();

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            let param_name = param.name();

            let bench_id;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let streams = CudaStreams::new_multi_gpu();
                    bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");

                    bench_group.bench_function(&bench_id, |b| {
                        let (cks, _cpu_sks) =
                            KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                        let gpu_sks = CudaServerKey::new(&cks, &streams);

                        let encrypt_two_values = || {
                            let ct_0 = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                            let ct_1 = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                            let d_ctxt_1 =
                                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_0, &streams);
                            let d_ctxt_2 =
                                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_1, &streams);

                            (d_ctxt_1, d_ctxt_2)
                        };

                        b.iter_batched(
                            encrypt_two_values,
                            |(mut ct_0, mut ct_1)| {
                                binary_op(&gpu_sks, &mut ct_0, &mut ct_1, &streams);
                            },
                            criterion::BatchSize::SmallInput,
                        )
                    });
                }
                BenchmarkType::Throughput => {
                    let (cks, cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                    let gpu_sks_vec = cuda_local_keys(&cks);
                    let gpu_count = get_number_of_gpus() as usize;

                    // Execute the operation once to know its cost.
                    let clear_0 = gen_random_u256(&mut rng);
                    let mut ct_0 = cks.encrypt_radix(clear_0, num_block);
                    let clear_1 = gen_random_u256(&mut rng);
                    let mut ct_1 = cks.encrypt_radix(clear_1, num_block);

                    reset_pbs_count();
                    // Use CPU operation as pbs_count do not count PBS on GPU backend.
                    binary_op_cpu(&cpu_sks, &mut ct_0, &mut ct_1);
                    let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                    bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                    bench_group
                        .sample_size(10)
                        .measurement_time(std::time::Duration::from_secs(30));
                    let elements = throughput_num_threads(num_block, pbs_count);
                    bench_group.throughput(Throughput::Elements(elements));
                    bench_group.bench_function(&bench_id, |b| {
                        let setup_encrypted_values = || {
                            let local_streams = cuda_local_streams(num_block, elements as usize);
                            let cts_0 = (0..elements)
                                .map(|i| {
                                    let ct_0 =
                                        cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                        &ct_0,
                                        &local_streams[i as usize],
                                    )
                                })
                                .collect::<Vec<_>>();
                            let cts_1 = (0..elements)
                                .map(|i| {
                                    let ct_1 =
                                        cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                        &ct_1,
                                        &local_streams[i as usize],
                                    )
                                })
                                .collect::<Vec<_>>();

                            (cts_0, cts_1, local_streams)
                        };

                        b.iter_batched(
                            setup_encrypted_values,
                            |(mut cts_0, mut cts_1, local_streams)| {
                                cts_0
                                    .par_iter_mut()
                                    .zip(cts_1.par_iter_mut())
                                    .zip(local_streams.par_iter())
                                    .enumerate()
                                    .for_each(|(i, ((ct_0, ct_1), local_stream))| {
                                        binary_op(
                                            &gpu_sks_vec[i % gpu_count],
                                            ct_0,
                                            ct_1,
                                            local_stream,
                                        );
                                    })
                            },
                            criterion::BatchSize::SmallInput,
                        );
                    });
                }
            }

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

    fn bench_cuda_server_key_binary_scalar_function_clean_inputs<F, G, H>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        binary_op: F,
        binary_op_cpu: G,
        rng_func: H,
    ) where
        F: Fn(&CudaServerKey, &mut CudaUnsignedRadixCiphertext, ScalarType, &CudaStreams) + Sync,
        G: Fn(&ServerKey, &mut RadixCiphertext, ScalarType) + Sync,
        H: Fn(&mut ThreadRng, usize) -> ScalarType,
    {
        let mut bench_group = c.benchmark_group(bench_name);
        let mut rng = rand::rng();

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            if bit_size > ScalarType::BITS as usize {
                break;
            }

            let param_name = param.name();

            let max_value_for_bit_size = ScalarType::MAX >> (ScalarType::BITS as usize - bit_size);

            let bench_id;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let streams = CudaStreams::new_multi_gpu();

                    bench_group
                        .sample_size(15)
                        .measurement_time(std::time::Duration::from_secs(30));
                    bench_id =
                        format!("{bench_name}::{param_name}::{bit_size}_bits_scalar_{bit_size}"); // FIXME it makes no sense to duplicate `bit_size`
                    bench_group.bench_function(&bench_id, |b| {
                        let (cks, _cpu_sks) =
                            KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                        let gpu_sks = CudaServerKey::new(&cks, &streams);

                        let encrypt_one_value = || {
                            let ct_0 = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                            let d_ctxt_1 =
                                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_0, &streams);

                            let clear_1 = rng_func(&mut rng, bit_size) & max_value_for_bit_size;

                            (d_ctxt_1, clear_1)
                        };

                        b.iter_batched(
                            encrypt_one_value,
                            |(mut ct_0, clear_1)| {
                                binary_op(&gpu_sks, &mut ct_0, clear_1, &streams);
                            },
                            criterion::BatchSize::SmallInput,
                        )
                    });
                }
                BenchmarkType::Throughput => {
                    let (cks, cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                    let gpu_count = get_number_of_gpus() as usize;
                    let gpu_sks_vec = cuda_local_keys(&cks);

                    // Execute the operation once to know its cost.
                    let clear_0 = gen_random_u256(&mut rng);
                    let mut ct_0 = cks.encrypt_radix(clear_0, num_block);
                    let clear_1 = rng_func(&mut rng, bit_size) & max_value_for_bit_size;

                    reset_pbs_count();
                    // Use CPU operation as pbs_count do not count PBS on GPU backend.
                    binary_op_cpu(&cpu_sks, &mut ct_0, clear_1);
                    let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                    bench_group
                        .sample_size(10)
                        .measurement_time(std::time::Duration::from_secs(30));
                    bench_id = format!(
                        "{bench_name}::throughput::{param_name}::{bit_size}_bits_scalar_{bit_size}"
                    );
                    let elements = throughput_num_threads(num_block, pbs_count);
                    bench_group.throughput(Throughput::Elements(elements));
                    bench_group.bench_function(&bench_id, |b| {
                        let setup_encrypted_values = || {
                            let local_streams = cuda_local_streams(num_block, elements as usize);
                            let cts_0 = (0..elements)
                                .map(|i| {
                                    let ct_0 =
                                        cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                        &ct_0,
                                        &local_streams[i as usize],
                                    )
                                })
                                .collect::<Vec<_>>();
                            let clears_1 = (0..elements)
                                .map(|_| rng_func(&mut rng, bit_size) & max_value_for_bit_size)
                                .collect::<Vec<_>>();

                            (cts_0, clears_1, local_streams)
                        };

                        b.iter_batched(
                            setup_encrypted_values,
                            |(mut cts_0, clears_1, local_streams)| {
                                cts_0
                                    .par_iter_mut()
                                    .zip(clears_1.par_iter())
                                    .zip(local_streams.par_iter())
                                    .enumerate()
                                    .for_each(|(i, ((ct_0, clear_1), local_stream))| {
                                        binary_op(
                                            &gpu_sks_vec[i % gpu_count],
                                            ct_0,
                                            *clear_1,
                                            local_stream,
                                        );
                                    })
                            },
                            criterion::BatchSize::SmallInput,
                        );
                    });
                }
            }

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
        let bench_name = "integer::cuda::unsigned::if_then_else";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));
        let mut rng = rand::rng();

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            if bit_size > ScalarType::BITS as usize {
                break;
            }

            let param_name = param.name();

            let bench_id;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let stream = CudaStreams::new_multi_gpu();

                    bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");

                    bench_group.bench_function(&bench_id, |b| {
                        let (cks, _cpu_sks) =
                            KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                        let gpu_sks = CudaServerKey::new(&cks, &stream);

                        let encrypt_tree_values = || {
                            let clear_cond = rng.gen::<bool>();
                            let ct_then = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                            let ct_else = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                            let ct_cond = cks.encrypt_bool(clear_cond);

                            let d_ct_cond = CudaBooleanBlock::from_boolean_block(&ct_cond, &stream);
                            let d_ct_then = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                &ct_then, &stream,
                            );
                            let d_ct_else = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                &ct_else, &stream,
                            );

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
                }
                BenchmarkType::Throughput => {
                    let (cks, cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                    let gpu_count = get_number_of_gpus() as usize;
                    let gpu_sks_vec = cuda_local_keys(&cks);

                    // Execute the operation once to know its cost.
                    let clear_0 = gen_random_u256(&mut rng);
                    let ct_then = cks.encrypt_radix(clear_0, num_block);
                    let clear_1 = gen_random_u256(&mut rng);
                    let ct_else = cks.encrypt_radix(clear_1, num_block);
                    let ct_cond = cks.encrypt_bool(rng.gen_bool(0.5));

                    reset_pbs_count();
                    // Use CPU operation as pbs_count do not count PBS on GPU backend.
                    cpu_sks.if_then_else_parallelized(&ct_cond, &ct_then, &ct_else);
                    let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                    bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                    bench_group
                        .sample_size(10)
                        .measurement_time(std::time::Duration::from_secs(30));
                    let elements = throughput_num_threads(num_block, pbs_count);
                    bench_group.throughput(Throughput::Elements(elements));
                    bench_group.bench_function(&bench_id, |b| {
                        let setup_encrypted_values = || {
                            let local_streams = cuda_local_streams(num_block, elements as usize);
                            let cts_cond = (0..elements)
                                .map(|i| {
                                    let ct_cond = cks.encrypt_bool(rng.gen::<bool>());
                                    CudaBooleanBlock::from_boolean_block(
                                        &ct_cond,
                                        &local_streams[i as usize],
                                    )
                                })
                                .collect::<Vec<_>>();
                            let cts_then = (0..elements)
                                .map(|i| {
                                    let ct_then =
                                        cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                        &ct_then,
                                        &local_streams[i as usize],
                                    )
                                })
                                .collect::<Vec<_>>();
                            let cts_else = (0..elements)
                                .map(|i| {
                                    let ct_else =
                                        cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                        &ct_else,
                                        &local_streams[i as usize],
                                    )
                                })
                                .collect::<Vec<_>>();

                            (cts_cond, cts_then, cts_else, local_streams)
                        };
                        b.iter_batched(
                            setup_encrypted_values,
                            |(cts_cond, cts_then, cts_else, local_streams)| {
                                cts_cond
                                    .par_iter()
                                    .zip(cts_then.par_iter())
                                    .zip(cts_else.par_iter())
                                    .zip(local_streams.par_iter())
                                    .enumerate()
                                    .for_each(
                                        |(i, (((ct_cond, ct_then), ct_else), local_stream))| {
                                            let _ = gpu_sks_vec[i % gpu_count].if_then_else(
                                                ct_cond,
                                                ct_then,
                                                ct_else,
                                                local_stream,
                                            );
                                        },
                                    )
                            },
                            criterion::BatchSize::SmallInput,
                        );
                    });
                }
            }

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
        (method_name: $server_key_method:ident, method_name_cpu: $server_key_method_cpu:ident, display_name: $name:ident) => {
            ::paste::paste!{
                fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                    bench_cuda_server_key_unary_function_clean_inputs(
                        c,
                        concat!("integer::cuda::unsigned::", stringify!($server_key_method)),
                        stringify!($name),
                        |server_key, lhs, stream| {
                            server_key.$server_key_method(lhs, stream);
                        },
                        |server_key_cpu, lhs| {
                            server_key_cpu.$server_key_method_cpu(lhs);
                        }
                    )
                }
            }
        });

    macro_rules! define_cuda_server_key_bench_clean_input_fn (
        (method_name: $server_key_method:ident, method_name_cpu: $server_key_method_cpu:ident, display_name:$name:ident) => {
            ::paste::paste!{
                fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                    bench_cuda_server_key_binary_function_clean_inputs(
                        c,
                        concat!("integer::cuda::unsigned::", stringify!($server_key_method)),
                        stringify!($name),
                        |server_key, lhs, rhs, stream| {
                            server_key.$server_key_method(lhs, rhs, stream);
                        },
                        |server_key_cpu, lhs, rhs| {
                            server_key_cpu.$server_key_method_cpu(lhs, rhs);
                        }
                    )
                }
            }
        }
    );

    macro_rules! define_cuda_server_key_bench_clean_input_scalar_fn (
        (method_name: $server_key_method:ident,  method_name_cpu: $server_key_method_cpu:ident, display_name:$name:ident, rng_func:$($rng_fn:tt)*) => {
            ::paste::paste!{
                fn [<cuda_ $server_key_method>](c: &mut Criterion) {
                    bench_cuda_server_key_binary_scalar_function_clean_inputs(
                        c,
                        concat!("integer::cuda::unsigned::", stringify!($server_key_method)),
                        stringify!($name),
                        |server_key, lhs, rhs, stream| {
                            server_key.$server_key_method(lhs, rhs, stream);
                        },
                        |server_key_cpu, lhs, rhs| {
                            server_key_cpu.$server_key_method_cpu(lhs, rhs);
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
        method_name_cpu: unchecked_neg,
        display_name: negation
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_bitand,
        method_name_cpu: unchecked_bitand,
        display_name: bitand
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_bitor,
        method_name_cpu: unchecked_bitor,
        display_name: bitor
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_bitxor,
        method_name_cpu: unchecked_bitxor,
        display_name: bitxor
    );

    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: unchecked_bitnot,
        method_name_cpu: bitnot,
        display_name: bitnot
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_mul,
        method_name_cpu: unchecked_mul_parallelized,
        display_name: mul
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_div_rem,
        method_name_cpu: unchecked_div_rem_parallelized,
        display_name: div_mod
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_add,
        method_name_cpu: unchecked_add_parallelized,
        display_name: add
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_sub,
        method_name_cpu: unchecked_sub,
        display_name: sub
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_unsigned_overflowing_sub,
        method_name_cpu: unchecked_unsigned_overflowing_sub_parallelized,
        display_name: overflowing_sub
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_unsigned_overflowing_add,
        method_name_cpu: unsigned_overflowing_add_parallelized,
        display_name: overflowing_add
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_eq,
        method_name_cpu: unchecked_eq,
        display_name: equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_ne,
        method_name_cpu: unchecked_ne,
        display_name: not_equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_left_shift,
        method_name_cpu: unchecked_left_shift_parallelized,
        display_name: left_shift
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_right_shift,
        method_name_cpu: unchecked_right_shift_parallelized,
        display_name: right_shift
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_rotate_left,
        method_name_cpu: unchecked_rotate_left_parallelized,
        display_name: rotate_left
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unchecked_rotate_right,
        method_name_cpu: unchecked_rotate_right_parallelized,
        display_name: rotate_right
    );

    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: unchecked_ilog2,
        method_name_cpu: unchecked_ilog2_parallelized,
        display_name: ilog2
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_bitand,
        method_name_cpu: unchecked_scalar_bitand_parallelized,
        display_name: bitand,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_bitor,
        method_name_cpu: unchecked_scalar_bitor_parallelized,
        display_name: bitand,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_bitxor,
        method_name_cpu: unchecked_scalar_bitxor_parallelized,
        display_name: bitand,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_add,
        method_name_cpu: unchecked_scalar_add,
        display_name: add,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_mul,
        method_name_cpu: unchecked_scalar_mul_parallelized,
        display_name: mul,
        rng_func: mul_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_sub,
        method_name_cpu: unchecked_scalar_sub,
        display_name: sub,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_left_shift,
        method_name_cpu: unchecked_scalar_left_shift_parallelized,
        display_name: left_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_right_shift,
        method_name_cpu: unchecked_scalar_right_shift_parallelized,
        display_name: right_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_rotate_left,
        method_name_cpu: unchecked_scalar_rotate_left_parallelized,
        display_name: rotate_left,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_rotate_right,
        method_name_cpu: unchecked_scalar_rotate_right_parallelized,
        display_name: rotate_right,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_eq,
        method_name_cpu: unchecked_scalar_eq_parallelized,
        display_name: equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_ne,
        method_name_cpu: unchecked_scalar_ne_parallelized,
        display_name: not_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_gt,
        method_name_cpu: unchecked_scalar_gt_parallelized,
        display_name: greater_than,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_ge,
        method_name_cpu: unchecked_scalar_ge_parallelized,
        display_name: greater_or_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_lt,
        method_name_cpu: unchecked_scalar_lt_parallelized,
        display_name: less_than,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_le,
        method_name_cpu: unchecked_scalar_le_parallelized,
        display_name: less_or_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_max,
        method_name_cpu: unchecked_scalar_max_parallelized,
        display_name: max,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_min,
        method_name_cpu: unchecked_scalar_min_parallelized,
        display_name: min,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_div_rem,
        method_name_cpu: unchecked_scalar_div_rem_parallelized,
        display_name: div_mod,
        rng_func: div_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_div,
        method_name_cpu: unchecked_scalar_div_parallelized,
        display_name: div,
        rng_func: div_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_scalar_rem,
        method_name_cpu: unchecked_scalar_rem_parallelized,
        display_name: modulo,
        rng_func: div_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unchecked_unsigned_overflowing_scalar_add,
        method_name_cpu: unsigned_overflowing_scalar_add_parallelized,
        display_name: overflowing_add,
        rng_func: default_scalar
    );

    //===========================================
    // Default
    //===========================================

    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: neg,
        method_name_cpu: neg_parallelized,
        display_name: negation
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: add,
        method_name_cpu: add_parallelized,
        display_name: add
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: sub,
        method_name_cpu: sub_parallelized,
        display_name: sub
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unsigned_overflowing_sub,
        method_name_cpu: unsigned_overflowing_sub_parallelized,
        display_name: overflowing_sub
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: unsigned_overflowing_add,
        method_name_cpu: unsigned_overflowing_add_parallelized,
        display_name: overflowing_add
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: mul,
        method_name_cpu: mul_parallelized,
        display_name: mul
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: div_rem,
        method_name_cpu: div_rem_parallelized,
        display_name: div_mod
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: div,
        method_name_cpu: div_parallelized,
        display_name: div
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: rem,
        method_name_cpu: rem_parallelized,
        display_name: modulo
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: ne,
        method_name_cpu: ne_parallelized,
        display_name: not_equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: eq,
        method_name_cpu: eq_parallelized,
        display_name: equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: bitand,
        method_name_cpu: bitand_parallelized,
        display_name: bitand
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: bitor,
        method_name_cpu: bitor_parallelized,
        display_name: bitor
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: bitxor,
        method_name_cpu: bitxor_parallelized,
        display_name: bitxor
    );

    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: bitnot,
        method_name_cpu: bitnot,
        display_name: bitnot
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: gt,
        method_name_cpu: gt_parallelized,
        display_name: greater_than
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: ge,
        method_name_cpu: ge_parallelized,
        display_name: greater_or_equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: lt,
        method_name_cpu: lt_parallelized,
        display_name: less_than
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: le,
        method_name_cpu: le_parallelized,
        display_name: less_or_equal
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: max,
        method_name_cpu: max_parallelized,
        display_name: max
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: min,
        method_name_cpu: min_parallelized,
        display_name: min
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: left_shift,
        method_name_cpu: left_shift_parallelized,
        display_name: left_shift
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: right_shift,
        method_name_cpu: right_shift_parallelized,
        display_name: right_shift
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: rotate_left,
        method_name_cpu: rotate_left_parallelized,
        display_name: rotate_left
    );

    define_cuda_server_key_bench_clean_input_fn!(
        method_name: rotate_right,
        method_name_cpu: rotate_right_parallelized,
        display_name: rotate_right
    );

    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: leading_zeros,
        method_name_cpu: leading_zeros_parallelized,
        display_name: leading_zeros
    );

    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: leading_ones,
        method_name_cpu: leading_ones_parallelized,
        display_name: leading_ones
    );

    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: trailing_zeros,
        method_name_cpu: trailing_zeros_parallelized,
        display_name: trailing_zeros
    );

    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: trailing_ones,
        method_name_cpu: trailing_ones_parallelized,
        display_name: trailing_ones
    );

    define_cuda_server_key_bench_clean_input_unary_fn!(
        method_name: ilog2,
        method_name_cpu: ilog2_parallelized,
        display_name: ilog2
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_sub,
        method_name_cpu: scalar_sub_parallelized,
        display_name: sub,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_add,
        method_name_cpu: scalar_add_parallelized,
        display_name: add,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_mul,
        method_name_cpu: scalar_mul_parallelized,
        display_name: mul,
        rng_func: mul_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_left_shift,
        method_name_cpu: scalar_left_shift_parallelized,
        display_name: left_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_right_shift,
        method_name_cpu: scalar_right_shift_parallelized,
        display_name: right_shift,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_rotate_left,
        method_name_cpu: scalar_rotate_left_parallelized,
        display_name: rotate_left,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_rotate_right,
        method_name_cpu: scalar_rotate_right_parallelized,
        display_name: rotate_right,
        rng_func: shift_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_bitand,
        method_name_cpu: scalar_bitand_parallelized,
        display_name: bitand,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_bitor,
        method_name_cpu: scalar_bitor_parallelized,
        display_name: bitor,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_bitxor,
        method_name_cpu: scalar_bitxor_parallelized,
        display_name: bitxor,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_eq,
        method_name_cpu: scalar_eq_parallelized,
        display_name: equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_ne,
        method_name_cpu: scalar_ne_parallelized,
        display_name: not_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_gt,
        method_name_cpu: scalar_gt_parallelized,
        display_name: greater_than,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_ge,
        method_name_cpu: scalar_ge_parallelized,
        display_name: greater_or_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_lt,
        method_name_cpu: scalar_lt_parallelized,
        display_name: less_than,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_le,
        method_name_cpu: scalar_le_parallelized,
        display_name: less_or_equal,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_max,
        method_name_cpu: scalar_max_parallelized,
        display_name: max,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_min,
        method_name_cpu: scalar_min_parallelized,
        display_name: min,
        rng_func: default_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_div_rem,
        method_name_cpu: scalar_div_rem_parallelized,
        display_name: div_mod,
        rng_func: div_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_div,
        method_name_cpu: scalar_div_parallelized,
        display_name: div,
        rng_func: div_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: scalar_rem,
        method_name_cpu: scalar_rem_parallelized,
        display_name: modulo,
        rng_func: div_scalar
    );

    define_cuda_server_key_bench_clean_input_scalar_fn!(
        method_name: unsigned_overflowing_scalar_add,
        method_name_cpu: unsigned_overflowing_scalar_add_parallelized,
        display_name: overflowing_add,
        rng_func: default_scalar
    );

    criterion_group!(
        unchecked_cuda_ops,
        cuda_unchecked_neg,
        cuda_unchecked_bitand,
        cuda_unchecked_bitor,
        cuda_unchecked_bitxor,
        cuda_unchecked_bitnot,
        cuda_unchecked_mul,
        cuda_unchecked_div_rem,
        //cuda_unchecked_div,
        //cuda_unchecked_rem,
        cuda_unchecked_sub,
        cuda_unchecked_unsigned_overflowing_sub,
        cuda_unchecked_unsigned_overflowing_add,
        cuda_unchecked_add,
        cuda_unchecked_eq,
        cuda_unchecked_ne,
        cuda_unchecked_left_shift,
        cuda_unchecked_right_shift,
        cuda_unchecked_rotate_left,
        cuda_unchecked_rotate_right,
        cuda_unchecked_ilog2,
    );

    criterion_group!(
        unchecked_scalar_cuda_ops,
        cuda_unchecked_scalar_bitand,
        cuda_unchecked_scalar_bitor,
        cuda_unchecked_scalar_bitxor,
        cuda_unchecked_scalar_add,
        cuda_unchecked_scalar_mul,
        cuda_unchecked_scalar_sub,
        cuda_unchecked_scalar_left_shift,
        cuda_unchecked_scalar_right_shift,
        cuda_unchecked_scalar_rotate_left,
        cuda_unchecked_scalar_rotate_right,
        cuda_unchecked_scalar_eq,
        cuda_unchecked_scalar_ne,
        cuda_unchecked_scalar_ge,
        cuda_unchecked_scalar_gt,
        cuda_unchecked_scalar_le,
        cuda_unchecked_scalar_lt,
        cuda_unchecked_scalar_max,
        cuda_unchecked_scalar_min,
        //cuda_unchecked_scalar_div_rem,
        cuda_unchecked_scalar_div,
        cuda_unchecked_scalar_rem,
        cuda_unchecked_unsigned_overflowing_scalar_add,
    );

    criterion_group!(
        default_cuda_ops,
        cuda_neg,
        cuda_sub,
        cuda_unsigned_overflowing_sub,
        cuda_unsigned_overflowing_add,
        cuda_add,
        cuda_mul,
        cuda_div_rem,
        //cuda_div,
        //cuda_rem,
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
        cuda_bitnot,
        cuda_default_if_then_else,
        cuda_left_shift,
        cuda_right_shift,
        cuda_rotate_left,
        cuda_rotate_right,
        cuda_leading_zeros,
        cuda_leading_ones,
        cuda_trailing_zeros,
        cuda_trailing_ones,
        cuda_ilog2,
        oprf::cuda::cuda_unsigned_oprf,
        vector_find::cuda::cuda_match_value,
    );

    criterion_group!(
        default_cuda_dedup_ops,
        cuda_add,
        cuda_neg,
        cuda_mul,
        cuda_div_rem,
        cuda_bitand,
        cuda_bitnot,
        cuda_left_shift,
        cuda_rotate_left,
        cuda_eq,
        cuda_gt,
        cuda_max,
        cuda_default_if_then_else,
        cuda_ilog2,
        cuda_leading_zeros,
        cuda_scalar_add,
        cuda_scalar_eq,
        cuda_scalar_gt,
        cuda_scalar_max,
        cuda_scalar_bitand,
        cuda_scalar_rotate_left,
        cuda_scalar_left_shift,
        cuda_scalar_mul,
        cuda_scalar_div,
        cuda_scalar_rem,
        oprf::cuda::cuda_unsigned_oprf,
        vector_find::cuda::cuda_match_value,
    );

    criterion_group!(
        default_scalar_cuda_ops,
        cuda_scalar_sub,
        cuda_scalar_add,
        cuda_scalar_mul,
        cuda_scalar_left_shift,
        cuda_scalar_right_shift,
        cuda_scalar_rotate_left,
        cuda_scalar_rotate_right,
        cuda_scalar_bitand,
        cuda_scalar_bitor,
        cuda_scalar_bitxor,
        cuda_scalar_eq,
        cuda_scalar_ne,
        cuda_scalar_ge,
        cuda_scalar_gt,
        cuda_scalar_le,
        cuda_scalar_lt,
        cuda_scalar_max,
        cuda_scalar_min,
        //cuda_scalar_div_rem,
        cuda_scalar_div,
        cuda_scalar_rem,
        cuda_unsigned_overflowing_scalar_add,
    );

    fn cuda_bench_server_key_cast_function<F>(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        cast_op: F,
    ) where
        F: Fn(&CudaServerKey, CudaUnsignedRadixCiphertext, usize, &CudaStreams),
    {
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));
        let mut rng = rand::rng();

        let env_config = EnvConfig::new();
        let stream = CudaStreams::new_multi_gpu();

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
                            cast_op(&gpu_sks, ct, target_num_blocks, &stream);
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
                    cuda_bench_server_key_cast_function(
                        c,
                        concat!("integer::cuda::unsigned::", stringify!($server_key_method)),
                        stringify!($name),
                        |server_key, lhs, rhs, stream| {
                            server_key.$server_key_method(lhs, rhs, stream);
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
    cuda_cast_ops, default_cuda_dedup_ops, default_cuda_ops, default_scalar_cuda_ops,
    unchecked_cuda_ops, unchecked_scalar_cuda_ops,
};

#[cfg(feature = "hpu")]
mod hpu {
    use super::*;
    use criterion::{black_box, criterion_group};
    use tfhe::integer::hpu::ciphertext::HpuRadixCiphertext;
    use tfhe::prelude::CastFrom;
    use tfhe::tfhe_hpu_backend::prelude::*;

    /// Base function to bench an hpu operations.
    /// Inputs/Output types and length are inferred based on associated iop prototype
    fn bench_hpu_iop_clean_inputs(
        c: &mut Criterion,
        bench_name: &str,
        display_name: &str,
        iop: &hpu_asm::AsmIOpcode,
    ) {
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));
        let mut rng = rand::rng();

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            if bit_size > ScalarType::BITS as usize {
                break;
            }
            let param_name = param.name();

            let max_value_for_bit_size = ScalarType::MAX >> (ScalarType::BITS as usize - bit_size);

            let bench_id;

            let proto = if let Some(format) = iop.format() {
                format.proto.clone()
            } else {
                panic!("HPU only IOp with defined prototype could be benched");
            };

            match get_bench_type() {
                BenchmarkType::Latency => {
                    bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
                    bench_group.bench_function(&bench_id, |b| {
                        let (cks, _sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                        let hpu_device_mutex = KEY_CACHE.get_hpu_device(param);
                        let hpu_device = hpu_device_mutex.lock().unwrap();

                        let gen_inputs = || {
                            let srcs = proto
                                .src
                                .iter()
                                .map(|mode| {
                                    let (bw, block) = match mode {
                                        hpu_asm::iop::VarMode::Native => (bit_size, num_block),
                                        hpu_asm::iop::VarMode::Half => {
                                            (bit_size / 2, num_block / 2)
                                        }
                                        hpu_asm::iop::VarMode::Bool => (1, 1),
                                    };

                                    let clear = rng
                                        .gen_range(0..u128::cast_from(max_value_for_bit_size))
                                        & if bw < u128::BITS as usize {
                                            (1_u128 << bw) - 1
                                        } else {
                                            !0_u128
                                        };
                                    let fhe = cks.encrypt_radix(clear, block);
                                    HpuRadixCiphertext::from_radix_ciphertext(&fhe, &hpu_device)
                                })
                                .collect::<Vec<_>>();

                            let imms = (0..proto.imm)
                                .map(|_| rng.gen_range(0..u128::cast_from(max_value_for_bit_size)))
                                .collect::<Vec<_>>();
                            (srcs, imms)
                        };

                        b.iter_batched(
                            gen_inputs,
                            |(srcs, imms)| {
                                let res =
                                    HpuRadixCiphertext::exec(&proto, iop.opcode(), &srcs, &imms);
                                res.into_iter().for_each(|ct| {
                                    ct.wait();
                                    black_box(ct);
                                });
                            },
                            criterion::BatchSize::SmallInput,
                        )
                    });
                }
                BenchmarkType::Throughput => {
                    bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                    bench_group
                        .sample_size(10)
                        .measurement_time(std::time::Duration::from_secs(120));
                    // Enforce that 64Iop are sent, except for div & modulus which
                    // are triggering a criterion assertion
                    let elements = if bench_name.contains("div") || bench_name.contains("mod") {
                        10
                    } else {
                        64
                    };
                    bench_group.throughput(Throughput::Elements(elements));
                    bench_group.bench_function(&bench_id, |b| {
                        let (cks, _sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                        let hpu_device_mutex = KEY_CACHE.get_hpu_device(param);
                        let hpu_device = hpu_device_mutex.lock().unwrap();

                        let inputs = (0..elements)
                            .map(|_| {
                                let srcs = proto
                                    .src
                                    .iter()
                                    .map(|mode| {
                                        let (bw, block) = match mode {
                                            hpu_asm::iop::VarMode::Native => (bit_size, num_block),
                                            hpu_asm::iop::VarMode::Half => {
                                                (bit_size / 2, num_block / 2)
                                            }
                                            hpu_asm::iop::VarMode::Bool => (1, 1),
                                        };

                                        let clear = rng
                                            .gen_range(0..u128::cast_from(max_value_for_bit_size))
                                            & if bw < u128::BITS as usize {
                                                (1_u128 << bw) - 1
                                            } else {
                                                !0_u128
                                            };
                                        let fhe = cks.encrypt_radix(clear, block);
                                        HpuRadixCiphertext::from_radix_ciphertext(&fhe, &hpu_device)
                                    })
                                    .collect::<Vec<_>>();

                                let imms = (0..proto.imm)
                                    .map(|_| {
                                        rng.gen_range(0..u128::cast_from(max_value_for_bit_size))
                                    })
                                    .collect::<Vec<_>>();
                                (srcs, imms)
                            })
                            .collect::<Vec<_>>();

                        b.iter(|| {
                            let last_res = inputs
                                .iter()
                                .map(|input| {
                                    HpuRadixCiphertext::exec(
                                        &proto,
                                        iop.opcode(),
                                        &input.0,
                                        &input.1,
                                    )
                                })
                                .last()
                                .unwrap();
                            last_res.into_iter().for_each(|ct| {
                                ct.wait();
                                black_box(ct);
                            });
                        })
                    });
                }
            }

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

    macro_rules! define_hpu_bench_default_fn (
    (iop_name: $iop:ident, display_name:$name:ident) => {
        ::paste::paste!{
        fn [< default_hpu_ $iop:lower >](c: &mut Criterion) {
            bench_hpu_iop_clean_inputs(
                c,
                concat!("integer::hpu::", stringify!($iop)),
                stringify!($name),
                &hpu_asm::iop::[< IOP_ $iop:upper >],
            )
        }
        }
    }
    );

    macro_rules! define_hpu_bench_default_fn_scalar (
    (iop_name: $iop:ident, display_name:$name:ident) => {
        ::paste::paste!{
        fn [< default_hpu_ $iop:lower >](c: &mut Criterion) {
            bench_hpu_iop_clean_inputs(
                c,
                concat!("integer::hpu::scalar_", stringify!($iop)),
                stringify!($name),
                &hpu_asm::iop::[< IOP_ $iop:upper >],
            )
        }
        }
    }
    );

    // Alu ------------------------------------------------------------------------
    define_hpu_bench_default_fn!(
        iop_name: add,
        display_name: add
    );
    define_hpu_bench_default_fn!(
        iop_name: sub,
        display_name: sub
    );
    define_hpu_bench_default_fn!(
        iop_name: mul,
        display_name: mul
    );
    define_hpu_bench_default_fn!(
        iop_name: div,
        display_name: div_mod
    );
    define_hpu_bench_default_fn!(
        iop_name: mod,
        display_name: modulo
    );
    criterion_group!(
        default_hpu_ops,
        default_hpu_add,
        default_hpu_sub,
        default_hpu_mul,
        default_hpu_div,
        default_hpu_mod
    );

    // Alu Scalar -----------------------------------------------------------------
    define_hpu_bench_default_fn_scalar!(
        iop_name: adds,
        display_name: add
    );
    define_hpu_bench_default_fn_scalar!(
        iop_name: subs,
        display_name: sub
    );
    //define_hpu_bench_default_fn!(
    //    iop_name: ssub,
    //    display_name: scalar_sub
    //);
    define_hpu_bench_default_fn_scalar!(
        iop_name: muls,
        display_name: mul
    );
    define_hpu_bench_default_fn_scalar!(
        iop_name: divs,
        display_name: div
    );
    criterion_group!(
        default_hpu_ops_scalar,
        default_hpu_adds,
        default_hpu_subs,
        //default_hpu_ssub,
        default_hpu_muls,
        default_hpu_divs,
        default_hpu_divs
    );

    // Shift/Rot -----------------------------------------------------------
    define_hpu_bench_default_fn!(
        iop_name: shift_r,
        display_name: right_shift
    );
    define_hpu_bench_default_fn!(
        iop_name: shift_l,
        display_name: left_shift
    );
    define_hpu_bench_default_fn!(
        iop_name: rot_r,
        display_name: rotate_right
    );
    define_hpu_bench_default_fn!(
        iop_name: rot_l,
        display_name: rotate_left
    );
    criterion_group!(
        default_hpu_shiftrot,
        default_hpu_shift_r,
        default_hpu_shift_l,
        default_hpu_rot_r,
        default_hpu_rot_l
    );

    // Scalar Shift/Rot -----------------------------------------------------------
    define_hpu_bench_default_fn_scalar!(
        iop_name: shifts_r,
        display_name: right_shift
    );
    define_hpu_bench_default_fn_scalar!(
        iop_name: shifts_l,
        display_name: left_shift
    );
    define_hpu_bench_default_fn_scalar!(
        iop_name: rots_r,
        display_name: rotate_right
    );
    define_hpu_bench_default_fn_scalar!(
        iop_name: rots_l,
        display_name: rotate_left
    );
    criterion_group!(
        default_hpu_shiftrot_scalar,
        default_hpu_shifts_r,
        default_hpu_shifts_l,
        default_hpu_rots_r,
        default_hpu_rots_l
    );
    // Bitwise --------------------------------------------------------------------
    define_hpu_bench_default_fn!(
        iop_name: bw_and,
        display_name: bitand
    );
    define_hpu_bench_default_fn!(
        iop_name: bw_or,
        display_name: bitor
    );
    define_hpu_bench_default_fn!(
        iop_name: bw_xor,
        display_name: bitxor
    );
    criterion_group!(
        default_hpu_bitwise,
        default_hpu_bw_and,
        default_hpu_bw_or,
        default_hpu_bw_xor,
    );
    // Comparison ----------------------------------------------------------------
    define_hpu_bench_default_fn!(
        iop_name: cmp_eq,
        display_name: equal
    );
    define_hpu_bench_default_fn!(
        iop_name: cmp_neq,
        display_name: not_equal
    );
    define_hpu_bench_default_fn!(
        iop_name: cmp_gt,
        display_name: greater_than
    );
    define_hpu_bench_default_fn!(
        iop_name: cmp_gte,
        display_name: greater_or_equal
    );
    define_hpu_bench_default_fn!(
        iop_name: cmp_lt,
        display_name: less_than
    );
    define_hpu_bench_default_fn!(
        iop_name: cmp_lte,
        display_name: less_or_equal
    );
    criterion_group!(
        default_hpu_cmp,
        default_hpu_cmp_eq,
        default_hpu_cmp_neq,
        default_hpu_cmp_gt,
        default_hpu_cmp_gte,
        default_hpu_cmp_lt,
        default_hpu_cmp_lte,
    );
    // Ternary --------------------------------------------------------------------
    define_hpu_bench_default_fn!(
        iop_name: if_then_else,
        display_name: if_then_else
    );
    define_hpu_bench_default_fn!(
        iop_name: if_then_zero,
        display_name: if_then_zero
    );
    criterion_group!(
        default_hpu_select,
        default_hpu_if_then_else,
        default_hpu_if_then_zero,
    );
    // Bitcnt ---------------------------------------------------------------------
    define_hpu_bench_default_fn!(
        iop_name: trail0,
        display_name: trailing_zeros
    );
    define_hpu_bench_default_fn!(
        iop_name: trail1,
        display_name: trailing_ones
    );
    define_hpu_bench_default_fn!(
        iop_name: lead0,
        display_name: leading_zeros
    );
    define_hpu_bench_default_fn!(
        iop_name: lead1,
        display_name: leading_ones
    );
    define_hpu_bench_default_fn!(
        iop_name: count0,
        display_name: count_zeros
    );
    define_hpu_bench_default_fn!(
        iop_name: count1,
        display_name: count_ones
    );
    define_hpu_bench_default_fn!(
        iop_name: ilog2,
        display_name: ilog2
    );
    criterion_group!(
        default_hpu_bitcnt,
        default_hpu_trail0,
        default_hpu_trail1,
        default_hpu_lead0,
        default_hpu_lead1,
        default_hpu_count0,
        default_hpu_count1,
        default_hpu_ilog2,
    );
}

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
    bitnot,
    bitor_parallelized,
    bitxor_parallelized,
    left_shift_parallelized,
    right_shift_parallelized,
    rotate_left_parallelized,
    rotate_right_parallelized,
    ciphertexts_sum_parallelized,
    leading_zeros_parallelized,
    leading_ones_parallelized,
    trailing_zeros_parallelized,
    trailing_ones_parallelized,
    ilog2_parallelized,
    checked_ilog2_parallelized,
    count_zeros_parallelized,
    count_ones_parallelized,
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
    flip_parallelized,
);

criterion_group!(
    default_dedup_ops,
    add_parallelized,
    mul_parallelized,
    div_rem_parallelized,
    bitand_parallelized,
    bitnot,
    left_shift_parallelized,
    rotate_left_parallelized,
    max_parallelized,
    eq_parallelized,
    gt_parallelized,
    if_then_else_parallelized,
    flip_parallelized,
    neg_parallelized,
    leading_zeros_parallelized,
    ilog2_parallelized,
    scalar_add_parallelized,
    scalar_mul_parallelized,
    scalar_div_parallelized,
    scalar_rem_parallelized,
    scalar_bitand_parallelized,
    scalar_left_shift_parallelized,
    scalar_rotate_left_parallelized,
    scalar_max_parallelized,
    scalar_eq_parallelized,
    scalar_gt_parallelized,
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
    let mut rng = rand::rng();

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

criterion_group!(oprf, oprf::unsigned_oprf);

criterion_group!(vector_find, vector_find::match_value);

#[cfg(feature = "gpu")]
fn go_through_gpu_bench_groups(val: &str) {
    match val.to_lowercase().as_str() {
        "default" => {
            default_cuda_ops();
            default_scalar_cuda_ops();
            cuda_cast_ops();
        }
        "fast_default" => {
            default_cuda_dedup_ops();
        }
        "unchecked" => {
            unchecked_cuda_ops();
            unchecked_scalar_cuda_ops()
        }
        _ => panic!("unknown benchmark operations flavor"),
    };
}

#[cfg(feature = "hpu")]
fn go_through_hpu_bench_groups(val: &str) {
    match val.to_lowercase().as_str() {
        "default" => {
            hpu::default_hpu_ops();
            hpu::default_hpu_ops_scalar();
            hpu::default_hpu_bitwise();
            hpu::default_hpu_cmp();
            hpu::default_hpu_select();
            hpu::default_hpu_shiftrot();
            hpu::default_hpu_shiftrot_scalar();
            hpu::default_hpu_bitcnt();
        }
        "fast_default" => {
            hpu::default_hpu_ops();
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
            cast_ops();
            oprf();
            vector_find();
        }
        "fast_default" => {
            default_dedup_ops();
            vector_find();
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
            #[cfg(feature = "hpu")]
            go_through_hpu_bench_groups(&val);
            #[cfg(not(any(feature = "gpu", feature = "hpu")))]
            go_through_cpu_bench_groups(&val);
        }
        Err(_) => {
            default_parallelized_ops();
            default_parallelized_ops_comp();
            default_scalar_parallelized_ops();
            default_scalar_parallelized_ops_comp();
            cast_ops();
            oprf();
            vector_find();
        }
    };

    Criterion::default().configure_from_args().final_summary();
}
