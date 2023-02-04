#![allow(dead_code)]

use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use tfhe::integer::client_key::radix_decomposition;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::parameters::*;
use tfhe::integer::wopbs::WopbsKey;
use tfhe::integer::{gen_keys, RadixCiphertext, ServerKey};
use tfhe::shortint::keycache::{NamedParam, KEY_CACHE_WOPBS};
use tfhe::shortint::parameters::parameters_wopbs_message_carry::get_parameters_from_message_and_carry_wopbs;
use tfhe::shortint::parameters::{get_parameters_from_message_and_carry, DEFAULT_PARAMETERS};

criterion_group!(
    to_be_reworked,
    smart_block_mul,
    radmodint_unchecked_mul,
    radmodint_unchecked_mul_many_sizes,
    crt,
    // radmodint_wopbs,
    // radmodint_wopbs_32_bits,
    // radmodint_wopbs_16bits_param_2_2_8_blocks,
    // radmodint_wopbs_16bits_param_4_4_4_blocks,
    concrete_integer_unchecked_mul_crt_16_bits,
    concrete_integer_unchecked_add_crt_16_bits,
    concrete_integer_unchecked_clean_carry_crt_16_bits,
    concrete_integer_unchecked_mul_crt_32_bits,
    concrete_integer_unchecked_add_crt_32_bits,
    concrete_integer_unchecked_clean_carry_crt_32_bits,
);

#[allow(unused_imports)]
use tfhe::shortint::parameters::{
    PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_2_CARRY_2, PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_4_CARRY_4,
};

macro_rules! named_param {
    ($param:ident) => {
        (stringify!($param), $param)
    };
}

struct Parameters {
    block_parameters: tfhe::shortint::Parameters,
    num_block: usize,
}

const BLOCK_4_MESSAGE_2_CARRY_2: Parameters = Parameters {
    block_parameters: PARAM_MESSAGE_2_CARRY_2,
    num_block: 4,
};

const BLOCK_4_MESSAGE_3_CARRY_3: Parameters = Parameters {
    block_parameters: PARAM_MESSAGE_3_CARRY_3,
    num_block: 4,
};

const SERVER_KEY_BENCH_PARAMS: [(&str, Parameters); 2] = [
    named_param!(BLOCK_4_MESSAGE_2_CARRY_2),
    named_param!(BLOCK_4_MESSAGE_3_CARRY_3),
];

fn smart_neg(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("smart_neg");

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = KEY_CACHE.get_from_params(param.block_parameters);

        let mut rng = rand::thread_rng();

        let modulus = (param.block_parameters.message_modulus.0 * param.num_block) as u64;

        let clear_0 = rng.gen::<u64>() % modulus;

        let mut ct = cks.encrypt_radix(clear_0, param.num_block);

        let bench_id = param_name;
        bench_group.bench_function(bench_id, |b| {
            b.iter(|| {
                sks.smart_neg(&mut ct);
            })
        });
    }

    bench_group.finish()
}

fn full_propagate(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("full_propagate");

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = KEY_CACHE.get_from_params(param.block_parameters);
        let mut rng = rand::thread_rng();

        let modulus = (param.block_parameters.message_modulus.0 * param.num_block) as u64;

        let clear_0 = rng.gen::<u64>() % modulus;

        let mut ct = cks.encrypt_radix(clear_0, param.num_block);

        let bench_id = param_name;
        bench_group.bench_function(bench_id, |b| {
            b.iter(|| {
                sks.full_propagate(&mut ct);
            })
        });
    }

    bench_group.finish()
}

fn bench_server_key_binary_function<F>(c: &mut Criterion, bench_name: &str, binary_op: F)
where
    F: Fn(&ServerKey, &mut RadixCiphertext, &mut RadixCiphertext),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = KEY_CACHE.get_from_params(param.block_parameters);

        let mut rng = rand::thread_rng();

        let modulus = (param.block_parameters.message_modulus.0 * param.num_block) as u64;

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ct_0 = cks.encrypt_radix(clear_0, param.num_block);
        let mut ct_1 = cks.encrypt_radix(clear_1, param.num_block);

        let bench_id = format!("{bench_name}::{param_name}");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                binary_op(&sks, &mut ct_0, &mut ct_1);
            })
        });
    }

    bench_group.finish()
}

fn bench_smart_add_radix(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("smart_add_radix");

    let mut rng = rand::thread_rng();

    let bit_sizes = [8, 16, 32, 40, 64, 128, 256];
    let params = [
        PARAM_MESSAGE_1_CARRY_1,
        PARAM_MESSAGE_2_CARRY_2,
        PARAM_MESSAGE_3_CARRY_3,
        PARAM_MESSAGE_4_CARRY_4,
    ];

    for param in params {
        let param_name = param.name();

        let (cks, sks) = KEY_CACHE.get_from_params(param);

        for bit_size in bit_sizes {
            let num_block =
                (bit_size as f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

            let bench_id = format!("{param_name} * {num_block}={bit_size} bits");
            bench_group.bench_function(&bench_id, |b| {
                let encrypt_two_values = || {
                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();

                    let clear_0 = tfhe::integer::client_key::U256::from((clearlow, clearhigh));

                    let clearlow = rng.gen::<u128>();
                    let clearhigh = rng.gen::<u128>();

                    let clear_1 = tfhe::integer::client_key::U256::from((clearlow, clearhigh));

                    let ct_0 = cks.encrypt_radix(clear_0, num_block);
                    let ct_1 = cks.encrypt_radix(clear_1, num_block);

                    (ct_0, ct_1)
                };

                b.iter_batched(
                    encrypt_two_values,
                    |(mut ct_0, mut ct_1)| {
                        sks.smart_add(&mut ct_0, &mut ct_1);
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }
    }

    bench_group.finish()
}

fn bench_server_key_binary_scalar_function<F>(c: &mut Criterion, bench_name: &str, binary_op: F)
where
    F: Fn(&ServerKey, &mut RadixCiphertext, u64),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = KEY_CACHE.get_from_params(param.block_parameters);

        let mut rng = rand::thread_rng();

        let modulus = (param.block_parameters.message_modulus.0 * param.num_block) as u64;

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ct_0 = cks.encrypt_radix(clear_0, param.num_block);

        let bench_id = format!("{bench_name}::{param_name}");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                binary_op(&sks, &mut ct_0, clear_1);
            })
        });
    }

    bench_group.finish()
}

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
define_server_key_bench_fn!(smart_add_parallelized);
define_server_key_bench_fn!(smart_sub);
define_server_key_bench_fn!(smart_sub_parallelized);
define_server_key_bench_fn!(smart_mul);
define_server_key_bench_fn!(smart_mul_parallelized);
define_server_key_bench_fn!(smart_bitand);
define_server_key_bench_fn!(smart_bitand_parallelized);
define_server_key_bench_fn!(smart_bitor);
define_server_key_bench_fn!(smart_bitor_parallelized);
define_server_key_bench_fn!(smart_bitxor);
define_server_key_bench_fn!(smart_bitxor_parallelized);

define_server_key_bench_fn!(unchecked_add);
define_server_key_bench_fn!(unchecked_sub);
define_server_key_bench_fn!(unchecked_mul);
define_server_key_bench_fn!(unchecked_mul_parallelized);
define_server_key_bench_fn!(unchecked_bitand);
define_server_key_bench_fn!(unchecked_bitor);
define_server_key_bench_fn!(unchecked_bitxor);

define_server_key_bench_scalar_fn!(smart_scalar_add);
define_server_key_bench_scalar_fn!(smart_scalar_add_parallelized);
define_server_key_bench_scalar_fn!(smart_scalar_sub);
define_server_key_bench_scalar_fn!(smart_scalar_sub_parallelized);
define_server_key_bench_scalar_fn!(smart_scalar_mul);
define_server_key_bench_scalar_fn!(smart_scalar_mul_parallelized);

define_server_key_bench_scalar_fn!(unchecked_scalar_add);
define_server_key_bench_scalar_fn!(unchecked_scalar_sub);
define_server_key_bench_scalar_fn!(unchecked_small_scalar_mul);

criterion_group!(
    smart_arithmetic_operation,
    smart_neg,
    smart_add,
    smart_add_parallelized,
    smart_sub,
    smart_sub_parallelized,
    smart_mul,
    smart_mul_parallelized,
    smart_bitand,
    smart_bitand_parallelized,
    smart_bitor,
    smart_bitor_parallelized,
    smart_bitxor,
    smart_bitxor_parallelized,
    bench_smart_add_radix,
);

criterion_group!(
    smart_scalar_arithmetic_operation,
    smart_scalar_add,
    smart_scalar_add_parallelized,
    smart_scalar_sub,
    smart_scalar_sub_parallelized,
    smart_scalar_mul,
    smart_scalar_mul_parallelized,
);

criterion_group!(
    unchecked_arithmetic_operation,
    unchecked_add,
    unchecked_sub,
    unchecked_mul,
    unchecked_mul_parallelized,
    unchecked_bitand,
    unchecked_bitor,
    unchecked_bitxor,
);

criterion_group!(
    unchecked_scalar_arithmetic_operation,
    unchecked_scalar_add,
    unchecked_scalar_sub,
    unchecked_small_scalar_mul,
);

criterion_group!(misc, full_propagate,);

criterion_main!(
    smart_arithmetic_operation,
    smart_scalar_arithmetic_operation,
    unchecked_arithmetic_operation,
    unchecked_scalar_arithmetic_operation,
    misc,
    to_be_reworked,
);

fn smart_block_mul(c: &mut Criterion) {
    let size = 4;

    // generate the server-client key set
    let (cks, sks) = gen_keys(&DEFAULT_PARAMETERS);

    //RNG
    let mut rng = rand::thread_rng();

    let block_modulus = DEFAULT_PARAMETERS.message_modulus.0 as u64;

    // message_modulus^vec_length
    let modulus = DEFAULT_PARAMETERS.message_modulus.0.pow(size as u32) as u64;

    let clear_0 = rng.gen::<u64>() % modulus;

    let clear_1 = rng.gen::<u64>() % block_modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_radix(clear_0, size);

    // encryption of an integer
    let ct_one = cks.encrypt_one_block(clear_1);

    //scalar mul
    c.bench_function("Smart_Block_Mul", |b| {
        b.iter(|| {
            sks.smart_block_mul(&mut ct_zero, &ct_one, 0);
        })
    });
}

fn crt(c: &mut Criterion) {
    // generate the server-client key set
    let (cks, sks) = gen_keys(&DEFAULT_PARAMETERS);

    //RNG
    let mut rng = rand::thread_rng();

    let basis = vec![2, 3, 5];
    let modulus = 30; // 30 = 2*3*5

    // Define the cleartexts
    let clear1 = rng.gen::<u64>() % modulus;
    let clear2 = rng.gen::<u64>() % modulus;

    // Encrypt the integers
    let mut ctxt_1 = cks.encrypt_crt(clear1, basis.clone());
    let mut ctxt_2 = cks.encrypt_crt(clear2, basis);

    //scalar mul
    c.bench_function("CRT: Smart_Mul", |b| {
        b.iter(|| {
            sks.smart_crt_mul_assign(&mut ctxt_1, &mut ctxt_2);
        })
    });
    c.bench_function("CRT: Smart_Add", |b| {
        b.iter(|| {
            sks.smart_crt_add_assign(&mut ctxt_1, &mut ctxt_2);
        })
    });
}

fn radmodint_unchecked_mul(c: &mut Criterion) {
    let size = 2;

    let param = DEFAULT_PARAMETERS;
    let (cks, sks) = KEY_CACHE.get_from_params(param);

    println!("Chosen Parameter Set: {param:?}");

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = DEFAULT_PARAMETERS.message_modulus.0.pow(size as u32) as u64;

    // Define the cleartexts
    let clear1 = rng.gen::<u64>() % modulus;
    let clear2 = rng.gen::<u64>() % modulus;

    // Encrypt the integers
    let mut ctxt_1 = cks.encrypt_radix(clear1, size);
    let ctxt_2 = cks.encrypt_radix(clear2, size);

    //scalar mul
    c.bench_function("Unchecked Mul + Full Propagate", |b| {
        b.iter(|| {
            sks.unchecked_mul(&ctxt_1, &ctxt_2);
            sks.full_propagate(&mut ctxt_1);
        })
    });
}

fn radmodint_unchecked_mul_many_sizes(c: &mut Criterion) {
    //Change the number of sample
    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);

    //At most 4bits
    let max_message_space = 4;

    let message_spaces = [16];
    for msg_space in message_spaces {
        let dec = radix_decomposition(msg_space, 2, max_message_space);
        println!("radix decomposition = {dec:?}");
        for rad_decomp in dec.iter() {
            //The carry space is at least equal to the msg_space
            let carry_space = rad_decomp.msg_space;

            let param =
                get_parameters_from_message_and_carry(1 << rad_decomp.msg_space, 1 << carry_space);
            let (cks, sks) = KEY_CACHE.get_from_params(param);

            println!("Chosen Parameter Set: {param:?}");

            //RNG
            let mut rng = rand::thread_rng();

            // Define the cleartexts
            let clear1 = rng.gen::<u64>() % msg_space as u64;
            let clear2 = rng.gen::<u64>() % msg_space as u64;

            // Encrypt the integers

            let mut ctxt_1 = cks.encrypt_radix(clear1, rad_decomp.block_number);
            let ctxt_2 = cks.encrypt_radix(clear2, rad_decomp.block_number);

            println!(
                "(Input Size {}; Carry_Space {}, Message_Space {}, Block Number {}):  \
                    Unchecked Mul\
                     + \
                    Full \
                Propagate ",
                msg_space, carry_space, rad_decomp.msg_space, rad_decomp.block_number,
            );
            let id = format!(
                "(Integer-Mul-Propagate-Message_{}_Carry_{}_Input_{}_Block_{}):",
                rad_decomp.msg_space, carry_space, msg_space, rad_decomp.block_number,
            );

            group.bench_function(&id, |b| {
                b.iter(|| {
                    sks.unchecked_mul(&ctxt_1, &ctxt_2);
                    sks.full_propagate(&mut ctxt_1);
                })
            });
        }
    }
}
//
fn radmodint_wopbs(c: &mut Criterion) {
    //Change the number of sample
    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);

    //At most 4bits
    let max_message_space = 4;

    let message_spaces = [16];
    for msg_space in message_spaces {
        let dec = radix_decomposition(msg_space, 2, max_message_space);
        println!("radix decomposition = {dec:?}");
        //for rad_decomp in dec.iter() {
        let rad_decomp = dec[0];
        //The carry space is at least equal to the msg_space
        let carry_space = rad_decomp.msg_space;

        let param = get_parameters_from_message_and_carry_wopbs(
            1 << rad_decomp.msg_space,
            1 << carry_space,
        );
        //let (mut cks, mut sks) = KEY_CACHE.get_from_params(param);
        let keys = KEY_CACHE_WOPBS.get_from_param((param, param));
        let (cks, _, wopbs_shortint) = (keys.client_key(), keys.server_key(), keys.wopbs_key());

        println!("Chosen Parameter Set: {param:?}");

        let cks = tfhe::integer::client_key::ClientKey::from(cks.clone());

        let wopbs = WopbsKey::new_from_shortint(wopbs_shortint);
        let mut rng = rand::thread_rng();

        let delta = 63 - f64::log2((param.message_modulus.0 * param.carry_modulus.0) as f64) as u64;
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % msg_space as u64;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt_radix(clear1, rad_decomp.block_number);

        let nb_bit_to_extract = f64::log2((param.message_modulus.0 * param.carry_modulus.0) as f64)
            as usize
            * rad_decomp.block_number;

        let mut lut_size = param.polynomial_size.0;
        if (1 << nb_bit_to_extract) > wopbs_shortint.param.polynomial_size.0 {
            lut_size = 1 << nb_bit_to_extract;
        }

        let mut lut_1: Vec<u64> = vec![];
        let mut lut_2: Vec<u64> = vec![];
        for _ in 0..lut_size {
            lut_1.push(
                (rng.gen::<u64>() % (param.message_modulus.0 * param.carry_modulus.0) as u64)
                    << delta,
            );
            lut_2.push(
                (rng.gen::<u64>() % (param.message_modulus.0 * param.carry_modulus.0) as u64)
                    << delta,
            );
        }
        let big_lut = vec![lut_1, lut_2];

        println!(
            "(Input Size {}; Carry_Space {}, Message_Space {}, Block Number {}):  \
                    WoPBS",
            msg_space, carry_space, rad_decomp.msg_space, rad_decomp.block_number,
        );
        let id = format!(
            "(Integer-WoPBS-Message_{}_Carry_{}_Input_{}_Block_{}):",
            rad_decomp.msg_space, carry_space, msg_space, rad_decomp.block_number,
        );

        group.bench_function(&id, |b| b.iter(|| wopbs.wopbs(&ctxt_1, &big_lut)));
    }
    //}
}

fn radmodint_wopbs_16bits_param_2_2_8_blocks(c: &mut Criterion) {
    //Change the number of sample
    let param = PARAM_MESSAGE_2_CARRY_2_16_BITS;
    let nb_block = 8;
    let input = 16;

    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);

    println!("Chosen Parameter Set: {PARAM_MESSAGE_2_CARRY_2_16_BITS:?}");

    let (cks, sks) = gen_keys(&param);
    let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &param);

    let mut rng = rand::thread_rng();
    let delta = 63 - f64::log2((param.message_modulus.0 * param.carry_modulus.0) as f64) as u64;
    // Define the cleartexts
    let clear1 = rng.gen::<u64>() % param.message_modulus.0 as u64;

    // Encrypt the integers
    let ctxt_1 = cks.encrypt_radix(clear1, nb_block);

    let nb_bit_to_extract =
        f64::log2((param.message_modulus.0 * param.carry_modulus.0) as f64) as usize * nb_block;

    let mut lut_size = param.polynomial_size.0;
    if (1 << nb_bit_to_extract) > param.polynomial_size.0 {
        lut_size = 1 << nb_block;
    }

    let mut lut_1: Vec<u64> = vec![];
    let mut lut_2: Vec<u64> = vec![];
    for _ in 0..lut_size {
        lut_1.push(
            (rng.gen::<u64>() % (param.message_modulus.0 * param.carry_modulus.0) as u64) << delta,
        );
        lut_2.push(
            (rng.gen::<u64>() % (param.message_modulus.0 * param.carry_modulus.0) as u64) << delta,
        );
    }
    let big_lut = vec![lut_1, lut_2];

    let id = format!(
        "(Integer-WoPBS-Message_{}_Carry_{}_Input_{}_Block_{}):",
        param.message_modulus.0, param.message_modulus.0, input, nb_block
    );

    group.bench_function(&id, |b| b.iter(|| wopbs_key.wopbs(&ctxt_1, &big_lut)));
}

fn radmodint_wopbs_16bits_param_4_4_4_blocks(c: &mut Criterion) {
    //Change the number of sample
    let param = PARAM_MESSAGE_4_CARRY_4_16_BITS;
    let nb_block = 4;
    let input = 16;

    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);

    println!("Chosen Parameter Set: {param:?}");

    let (cks, sks) = gen_keys(&param);
    let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &param);

    let mut rng = rand::thread_rng();
    let delta = 63 - f64::log2((param.message_modulus.0 * param.carry_modulus.0) as f64) as u64;
    // Define the cleartexts
    let clear1 = rng.gen::<u64>() % param.message_modulus.0 as u64;

    // Encrypt the integers
    let ctxt_1 = cks.encrypt_radix(clear1, nb_block);

    let nb_bit_to_extract =
        f64::log2((param.message_modulus.0 * param.carry_modulus.0) as f64) as usize * nb_block;

    let mut lut_size = param.polynomial_size.0;
    if (1 << nb_bit_to_extract) > param.polynomial_size.0 {
        lut_size = 1 << nb_block;
    }

    let mut lut_1: Vec<u64> = vec![];
    let mut lut_2: Vec<u64> = vec![];
    for _ in 0..lut_size {
        lut_1.push(
            (rng.gen::<u64>() % (param.message_modulus.0 * param.carry_modulus.0) as u64) << delta,
        );
        lut_2.push(
            (rng.gen::<u64>() % (param.message_modulus.0 * param.carry_modulus.0) as u64) << delta,
        );
    }
    let big_lut = vec![lut_1, lut_2];

    let id = format!(
        "(Integer-WoPBS-Message_{}_Carry_{}_Input_{}_Block_{}):",
        param.message_modulus.0, param.message_modulus.0, input, nb_block
    );

    group.bench_function(&id, |b| b.iter(|| wopbs_key.wopbs(&ctxt_1, &big_lut)));
}

fn radmodint_wopbs_32_bits(c: &mut Criterion) {
    //Change the number of sample
    let vec_param = &[
        PARAM_MESSAGE_1_CARRY_1_32_BITS,
        PARAM_MESSAGE_2_CARRY_2_32_BITS,
        PARAM_MESSAGE_4_CARRY_4_32_BITS,
    ];
    let vec_nb_block = &[32, 16, 8];
    let input = 16;

    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);

    for (param, nb_block) in vec_param.iter().zip(vec_nb_block.iter()) {
        println!("Chosen Parameter Set: {param:?}");

        let (cks, sks) = gen_keys(param);
        let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, param);

        let mut rng = rand::thread_rng();
        let delta = 63 - f64::log2((param.message_modulus.0 * param.carry_modulus.0) as f64) as u64;
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % param.message_modulus.0 as u64;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt_radix(clear1, *nb_block);

        let nb_bit_to_extract =
            f64::log2((param.message_modulus.0 * param.carry_modulus.0) as f64) as usize * nb_block;

        let mut lut_size = param.polynomial_size.0;
        if (1 << nb_bit_to_extract) > param.polynomial_size.0 {
            lut_size = 1 << nb_block;
        }

        let mut lut_1: Vec<u64> = vec![];
        let mut lut_2: Vec<u64> = vec![];
        for _ in 0..lut_size {
            lut_1.push(
                (rng.gen::<u64>() % (param.message_modulus.0 * param.carry_modulus.0) as u64)
                    << delta,
            );
            lut_2.push(
                (rng.gen::<u64>() % (param.message_modulus.0 * param.carry_modulus.0) as u64)
                    << delta,
            );
        }
        let big_lut = vec![lut_1, lut_2];

        let id = format!(
            "(Integer-WoPBS-Message_{}_Carry_{}_Input_{}_Block_{}):",
            param.message_modulus.0, param.message_modulus.0, input, nb_block
        );

        group.bench_function(&id, |b| b.iter(|| wopbs_key.wopbs(&ctxt_1, &big_lut)));
    }
}

fn concrete_integer_unchecked_mul_crt_16_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);
    let param = tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4;

    let (cks, sks) = KEY_CACHE.get_from_params(param);

    println!("Chosen Parameter Set: {param:?}");

    let basis = vec![8, 9, 11, 13, 7];
    let mut modulus = 1;
    for b in basis.iter() {
        modulus *= b;
    }

    //
    // let block_modulus = DEFAULT_PARAMETERS.message_modulus.0 as u64;
    //
    // // message_modulus^vec_length
    // let modulus = DEFAULT_PARAMETERS.message_modulus.0.pow(size as u32) as u64;

    let clear_0 = 29 % modulus;
    let clear_1 = 23 % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());
    let ct_one = cks.encrypt_crt(clear_1, basis);

    let id = "(bench_concrete_integer_unchecked_mul_crt_16_bits):";
    // add the two ciphertexts
    group.bench_function(id, |b| {
        b.iter(|| {
            sks.unchecked_crt_mul_assign(&mut ct_zero, &ct_one);
        })
    });
}

fn concrete_integer_unchecked_add_crt_16_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);
    let param = tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4;

    let (cks, sks) = KEY_CACHE.get_from_params(param);

    println!("Chosen Parameter Set: {param:?}");

    let basis = vec![8, 9, 11, 13, 7];
    let mut modulus = 1;
    for b in basis.iter() {
        modulus *= b;
    }

    //RN
    //
    // let block_modulus = DEFAULT_PARAMETERS.message_modulus.0 as u64;
    //
    // // message_modulus^vec_length
    // let modulus = DEFAULT_PARAMETERS.message_modulus.0.pow(size as u32) as u64;

    let clear_0 = 29 % modulus;
    let clear_1 = 23 % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());
    let ct_one = cks.encrypt_crt(clear_1, basis);

    let id = "(bench_concrete_integer_unchecked_add_crt_16_bits):";
    // add the two ciphertexts
    group.bench_function(id, |b| {
        b.iter(|| {
            sks.unchecked_crt_add_assign(&mut ct_zero, &ct_one);
        })
    });
}

fn concrete_integer_unchecked_clean_carry_crt_16_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);
    let param = tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4;

    // generate the server-client key set
    //let (mut cks, mut sks) =
    //gen_keys(&tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4,
    //size);

    let (cks, sks) = KEY_CACHE.get_from_params(param);

    println!("Chosen Parameter Set: {param:?}");

    let basis = vec![8, 9, 11, 13, 7];
    let mut modulus = 1;
    for b in basis.iter() {
        modulus *= b;
    }

    //RN
    //
    // let block_modulus = DEFAULT_PARAMETERS.message_modulus.0 as u64;
    //
    // // message_modulus^vec_length
    // let modulus = DEFAULT_PARAMETERS.message_modulus.0.pow(size as u32) as u64;

    let clear_0 = 29 % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());

    let id = "(bench_concrete_integer_clean_carry_16_bits):";
    // add the two ciphertexts
    group.bench_function(id, |b| {
        b.iter(|| {
            sks.pbs_crt_compliant_function_assign(&mut ct_zero, |x| x % basis[0]);
        })
    });
}

fn concrete_integer_unchecked_mul_crt_32_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);
    let param = tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4;

    // generate the server-client key set
    //let (mut cks, mut sks) =
    //gen_keys(&tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4,
    //size);

    let (cks, sks) = KEY_CACHE.get_from_params(param);

    println!("Chosen Parameter Set: {param:?}");

    let basis = vec![43, 47, 37, 49, 29, 41];
    let mut modulus = 1;
    for b in basis.iter() {
        modulus *= b;
    }

    //
    // let block_modulus = DEFAULT_PARAMETERS.message_modulus.0 as u64;
    //
    // // message_modulus^vec_length
    // let modulus = DEFAULT_PARAMETERS.message_modulus.0.pow(size as u32) as u64;

    let clear_0 = 29 % modulus;
    let clear_1 = 23 % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());
    let ct_one = cks.encrypt_crt(clear_1, basis);

    let id = "(bench_concrete_integer_unchecked_mul_crt_32_bits):";
    // add the two ciphertexts
    group.bench_function(id, |b| {
        b.iter(|| {
            sks.unchecked_crt_mul_assign(&mut ct_zero, &ct_one);
        })
    });
}

fn concrete_integer_unchecked_add_crt_32_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);
    let param = tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4;

    // generate the server-client key set
    //let (mut cks, mut sks) =
    //gen_keys(&tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4,
    //size);

    let (cks, sks) = KEY_CACHE.get_from_params(param);

    println!("Chosen Parameter Set: {param:?}");

    let basis = vec![43, 47, 37, 49, 29, 41];
    let mut modulus = 1;
    for b in basis.iter() {
        modulus *= b;
    }

    //RN
    //
    // let block_modulus = DEFAULT_PARAMETERS.message_modulus.0 as u64;
    //
    // // message_modulus^vec_length
    // let modulus = DEFAULT_PARAMETERS.message_modulus.0.pow(size as u32) as u64;

    let clear_0 = 29 % modulus;
    let clear_1 = 23 % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());
    let ct_one = cks.encrypt_crt(clear_1, basis);

    let id = "(bench_concrete_integer_unchecked_add_crt_32_bits):";
    // add the two ciphertexts
    group.bench_function(id, |b| {
        b.iter(|| {
            sks.unchecked_crt_add_assign(&mut ct_zero, &ct_one);
        })
    });
}

fn concrete_integer_unchecked_clean_carry_crt_32_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("smaller-sample-count");
    group.sample_size(10);
    let param = tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4;

    // generate the server-client key set
    //let (mut cks, mut sks) =
    //gen_keys(&tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_4,
    //size);

    let (cks, sks) = KEY_CACHE.get_from_params(param);

    println!("Chosen Parameter Set: {param:?}");

    let basis = vec![43, 47, 37, 49, 29, 41];
    let mut modulus = 1;
    for b in basis.iter() {
        modulus *= b;
    }

    //RN
    //
    // let block_modulus = DEFAULT_PARAMETERS.message_modulus.0 as u64;
    //
    // // message_modulus^vec_length
    // let modulus = DEFAULT_PARAMETERS.message_modulus.0.pow(size as u32) as u64;

    let clear_0 = 29 % modulus;

    // encryption of an integer
    let mut ct_zero = cks.encrypt_crt(clear_0, basis.clone());

    let id = "(bench_concrete_integer_clean_carry_32_bits):";
    // add the two ciphertexts
    group.bench_function(id, |b| {
        b.iter(|| {
            sks.pbs_crt_compliant_function_assign(&mut ct_zero, |x| x % basis[0]);
        })
    });
}
