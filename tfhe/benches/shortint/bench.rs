use tfhe::shortint::parameters::*;
use tfhe::shortint::{Ciphertext, Parameters, ServerKey};
use criterion::{criterion_group, criterion_main, Criterion};

use tfhe::shortint::keycache::KEY_CACHE;
use rand::Rng;

use tfhe::shortint::keycache::KEY_CACHE_WOPBS;
use tfhe::shortint::parameters::parameters_wopbs::WOPBS_PARAM_MESSAGE_4_NORM2_6;

macro_rules! named_param {
    ($param:ident) => {
        (stringify!($param), $param)
    };
}

const SERVER_KEY_BENCH_PARAMS: [(&str, Parameters); 4] = [
    named_param!(PARAM_MESSAGE_1_CARRY_1),
    named_param!(PARAM_MESSAGE_2_CARRY_2),
    named_param!(PARAM_MESSAGE_3_CARRY_3),
    named_param!(PARAM_MESSAGE_4_CARRY_4),
];

fn bench_server_key_binary_function<F>(c: &mut Criterion, bench_name: &str, binary_op: F)
where
    F: Fn(&ServerKey, &mut Ciphertext, &mut Ciphertext),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let keys = KEY_CACHE.get_from_param(param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = 1_u64 << cks.parameters.message_modulus.0;

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ct_0 = cks.encrypt(clear_0);
        let mut ct_1 = cks.encrypt(clear_1);

        let bench_id = format!("{}::{}", bench_name, param_name);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                binary_op(sks, &mut ct_0, &mut ct_1);
            })
        });
    }

    bench_group.finish()
}

fn bench_server_key_binary_scalar_function<F>(c: &mut Criterion, bench_name: &str, binary_op: F)
where
    F: Fn(&ServerKey, &mut Ciphertext, u8),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let keys = KEY_CACHE.get_from_param(param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = 1_u64 << cks.parameters.message_modulus.0;

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ct_0 = cks.encrypt(clear_0);

        let bench_id = format!("{}::{}", bench_name, param_name);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                binary_op(sks, &mut ct_0, clear_1 as u8);
            })
        });
    }

    bench_group.finish()
}

fn carry_extract(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("carry_extract");

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let keys = KEY_CACHE.get_from_param(param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = 1_u64 << cks.parameters.message_modulus.0;

        let clear_0 = rng.gen::<u64>() % modulus;

        let ct_0 = cks.encrypt(clear_0);

        let bench_id = format!("ServerKey::carry_extract::{}", param_name);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                sks.carry_extract(&ct_0);
            })
        });
    }

    bench_group.finish()
}

fn programmable_bootstrapping(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("programmable_bootstrap");

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let keys = KEY_CACHE.get_from_param(param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus.0 as u64;

        let acc = sks.generate_accumulator(|x| x);

        let clear_0 = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear_0);

        let id = format!("ServerKey::programmable_bootstrap::{}", param_name);

        bench_group.bench_function(&id, |b| {
            b.iter(|| {
                sks.keyswitch_programmable_bootstrap(&ctxt, &acc);
            })
        });
    }

    bench_group.finish();
}

fn bench_wopbs_param_message_8_norm2_5(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("programmable_bootstrap");

    let param = WOPBS_PARAM_MESSAGE_4_NORM2_6;

    let keys = KEY_CACHE_WOPBS.get_from_param((param, param));
    let (cks, _, wopbs_key) = (keys.client_key(), keys.server_key(), keys.wopbs_key());

    let mut rng = rand::thread_rng();

    let clear = rng.gen::<usize>() % param.message_modulus.0;
    let mut ct = cks.encrypt_without_padding(clear as u64);
    let vec_lut = wopbs_key.generate_lut_native_crt(&ct, |x| x);

    let id = format!("Shortint WOPBS: {:?}", param);

    bench_group.bench_function(&id, |b| {
        b.iter(|| {
            wopbs_key.programmable_bootstrapping_native_crt(&mut ct, &vec_lut);
        })
    });

    bench_group.finish();
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

macro_rules! define_server_key_scalar_bench_fn (
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

define_server_key_bench_fn!(unchecked_add);
define_server_key_bench_fn!(unchecked_sub);
define_server_key_bench_fn!(unchecked_mul_lsb);
define_server_key_bench_fn!(unchecked_mul_msb);
define_server_key_bench_fn!(smart_bitand);
define_server_key_bench_fn!(smart_bitor);
define_server_key_bench_fn!(smart_bitxor);
define_server_key_bench_fn!(smart_add);
define_server_key_bench_fn!(smart_sub);
define_server_key_bench_fn!(smart_mul_lsb);

define_server_key_scalar_bench_fn!(unchecked_scalar_add);
define_server_key_scalar_bench_fn!(unchecked_scalar_mul);

criterion_group!(
    arithmetic_operation,
    unchecked_add,
    unchecked_sub,
    unchecked_mul_lsb,
    unchecked_mul_msb,
    smart_bitand,
    smart_bitor,
    smart_bitxor,
    smart_add,
    smart_sub,
    smart_mul_lsb,
    carry_extract,
    // programmable_bootstrapping,
    // multivalue_programmable_bootstrapping
    //bench_two_block_pbs
    //wopbs_v0_norm2_2,
    bench_wopbs_param_message_8_norm2_5,
    programmable_bootstrapping
);

criterion_group!(
    arithmetic_scalar_operation,
    unchecked_scalar_add,
    unchecked_scalar_mul,
);

criterion_main!(arithmetic_operation,); // arithmetic_scalar_operation,);
