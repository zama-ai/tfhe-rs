use criterion::{criterion_group, criterion_main, Criterion};
use tfhe::shortint::keycache::NamedParam;
use tfhe::shortint::parameters::*;
use tfhe::shortint::{CiphertextBig, Parameters, ServerKey};

use rand::Rng;
use tfhe::shortint::keycache::KEY_CACHE;

use tfhe::shortint::keycache::KEY_CACHE_WOPBS;
use tfhe::shortint::parameters::parameters_wopbs::WOPBS_PARAM_MESSAGE_4_NORM2_6;

const SERVER_KEY_BENCH_PARAMS: [Parameters; 4] = [
    PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_2_CARRY_2,
    PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_4_CARRY_4,
];

const SERVER_KEY_BENCH_PARAMS_EXTENDED: [Parameters; 15] = [
    PARAM_MESSAGE_1_CARRY_0,
    PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_2_CARRY_0,
    PARAM_MESSAGE_2_CARRY_1,
    PARAM_MESSAGE_2_CARRY_2,
    PARAM_MESSAGE_3_CARRY_0,
    PARAM_MESSAGE_3_CARRY_2,
    PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_4_CARRY_0,
    PARAM_MESSAGE_4_CARRY_3,
    PARAM_MESSAGE_4_CARRY_4,
    PARAM_MESSAGE_5_CARRY_0,
    PARAM_MESSAGE_6_CARRY_0,
    PARAM_MESSAGE_7_CARRY_0,
    PARAM_MESSAGE_8_CARRY_0,
];

fn bench_server_key_unary_function<F>(
    c: &mut Criterion,
    bench_name: &str,
    unary_op: F,
    params: &[Parameters],
) where
    F: Fn(&ServerKey, &mut CiphertextBig),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for param in params.iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus.0 as u64;

        let clear_text = rng.gen::<u64>() % modulus;

        let mut ct = cks.encrypt(clear_text);

        let bench_id = format!("{bench_name}::{}", param.name());
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                unary_op(sks, &mut ct);
            })
        });
    }

    bench_group.finish()
}

fn bench_server_key_binary_function<F>(
    c: &mut Criterion,
    bench_name: &str,
    binary_op: F,
    params: &[Parameters],
) where
    F: Fn(&ServerKey, &mut CiphertextBig, &mut CiphertextBig),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for param in params.iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus.0 as u64;

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ct_0 = cks.encrypt(clear_0);
        let mut ct_1 = cks.encrypt(clear_1);

        let bench_id = format!("{bench_name}::{}", param.name());
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                binary_op(sks, &mut ct_0, &mut ct_1);
            })
        });
    }

    bench_group.finish()
}

fn bench_server_key_binary_scalar_function<F>(
    c: &mut Criterion,
    bench_name: &str,
    binary_op: F,
    params: &[Parameters],
) where
    F: Fn(&ServerKey, &mut CiphertextBig, u8),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for param in params {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus.0 as u64;

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ct_0 = cks.encrypt(clear_0);

        let bench_id = format!("{bench_name}::{}", param.name());
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                binary_op(sks, &mut ct_0, clear_1 as u8);
            })
        });
    }

    bench_group.finish()
}

fn bench_server_key_binary_scalar_division_function<F>(
    c: &mut Criterion,
    bench_name: &str,
    binary_op: F,
    params: &[Parameters],
) where
    F: Fn(&ServerKey, &mut CiphertextBig, u8),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for param in params {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus.0 as u64;
        assert_ne!(modulus, 1);

        let clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        while clear_1 == 0 {
            clear_1 = rng.gen::<u64>() % modulus;
        }

        let mut ct_0 = cks.encrypt(clear_0);

        let bench_id = format!("{bench_name}::{}", param.name());
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

    for param in SERVER_KEY_BENCH_PARAMS {
        let keys = KEY_CACHE.get_from_param(param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus.0 as u64;

        let clear_0 = rng.gen::<u64>() % modulus;

        let ct_0 = cks.encrypt(clear_0);

        let bench_id = format!("ServerKey::carry_extract::{}", param.name());
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let _ = sks.carry_extract(&ct_0);
            })
        });
    }

    bench_group.finish()
}

fn programmable_bootstrapping(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("programmable_bootstrap");

    for param in SERVER_KEY_BENCH_PARAMS {
        let keys = KEY_CACHE.get_from_param(param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus.0 as u64;

        let acc = sks.generate_accumulator(|x| x);

        let clear_0 = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear_0);

        let id = format!("ServerKey::programmable_bootstrap::{}", param.name());

        bench_group.bench_function(&id, |b| {
            b.iter(|| {
                let _ = sks.apply_lookup_table(&ctxt, &acc);
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

    let id = format!("Shortint WOPBS: {param:?}");

    bench_group.bench_function(&id, |b| {
        b.iter(|| {
            let _ = wopbs_key.programmable_bootstrapping_native_crt(&mut ct, &vec_lut);
        })
    });

    bench_group.finish();
}

macro_rules! define_server_key_unary_bench_fn (
  ($server_key_method:ident, $params:expr) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_unary_function(
              c,
              concat!("ServerKey::", stringify!($server_key_method)),
              |server_key, lhs| {
                let _ = server_key.$server_key_method(lhs);},
              $params)
      }
  }
);

macro_rules! define_server_key_bench_fn (
  ($server_key_method:ident, $params:expr) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_function(
              c,
              concat!("ServerKey::", stringify!($server_key_method)),
              |server_key, lhs, rhs| {
                let _ = server_key.$server_key_method(lhs, rhs);},
              $params)
      }
  }
);

macro_rules! define_server_key_scalar_bench_fn (
  ($server_key_method:ident, $params:expr) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_scalar_function(
              c,
              concat!("ServerKey::", stringify!($server_key_method)),
              |server_key, lhs, rhs| {
                let _ = server_key.$server_key_method(lhs, rhs);},
              $params)
      }
  }
);

macro_rules! define_server_key_scalar_div_bench_fn (
  ($server_key_method:ident, $params:expr) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_scalar_division_function(
              c,
              concat!("ServerKey::", stringify!($server_key_method)),
              |server_key, lhs, rhs| {
                let _ = server_key.$server_key_method(lhs, rhs);},
              $params)
      }
  }
);

define_server_key_unary_bench_fn!(unchecked_neg, &SERVER_KEY_BENCH_PARAMS);

define_server_key_bench_fn!(unchecked_add, &SERVER_KEY_BENCH_PARAMS_EXTENDED);
define_server_key_bench_fn!(unchecked_sub, &SERVER_KEY_BENCH_PARAMS_EXTENDED);
define_server_key_bench_fn!(unchecked_mul_lsb, &SERVER_KEY_BENCH_PARAMS_EXTENDED);
define_server_key_bench_fn!(unchecked_mul_msb, &SERVER_KEY_BENCH_PARAMS);
define_server_key_bench_fn!(unchecked_div, &SERVER_KEY_BENCH_PARAMS_EXTENDED);
define_server_key_bench_fn!(smart_bitand, &SERVER_KEY_BENCH_PARAMS);
define_server_key_bench_fn!(smart_bitor, &SERVER_KEY_BENCH_PARAMS);
define_server_key_bench_fn!(smart_bitxor, &SERVER_KEY_BENCH_PARAMS);
define_server_key_bench_fn!(smart_add, &SERVER_KEY_BENCH_PARAMS);
define_server_key_bench_fn!(smart_sub, &SERVER_KEY_BENCH_PARAMS);
define_server_key_bench_fn!(smart_mul_lsb, &SERVER_KEY_BENCH_PARAMS);
define_server_key_bench_fn!(unchecked_greater, &SERVER_KEY_BENCH_PARAMS);
define_server_key_bench_fn!(unchecked_less, &SERVER_KEY_BENCH_PARAMS);
define_server_key_bench_fn!(unchecked_equal, &SERVER_KEY_BENCH_PARAMS);

define_server_key_scalar_bench_fn!(unchecked_scalar_add, &SERVER_KEY_BENCH_PARAMS_EXTENDED);
define_server_key_scalar_bench_fn!(unchecked_scalar_sub, &SERVER_KEY_BENCH_PARAMS_EXTENDED);
define_server_key_scalar_bench_fn!(unchecked_scalar_mul, &SERVER_KEY_BENCH_PARAMS_EXTENDED);
define_server_key_scalar_bench_fn!(unchecked_scalar_left_shift, &SERVER_KEY_BENCH_PARAMS);
define_server_key_scalar_bench_fn!(unchecked_scalar_right_shift, &SERVER_KEY_BENCH_PARAMS);

define_server_key_scalar_div_bench_fn!(unchecked_scalar_div, &SERVER_KEY_BENCH_PARAMS_EXTENDED);
define_server_key_scalar_div_bench_fn!(unchecked_scalar_mod, &SERVER_KEY_BENCH_PARAMS);

criterion_group!(
    arithmetic_operation,
    unchecked_neg,
    unchecked_add,
    unchecked_sub,
    unchecked_mul_lsb,
    unchecked_mul_msb,
    unchecked_div,
    smart_bitand,
    smart_bitor,
    smart_bitxor,
    smart_add,
    smart_sub,
    smart_mul_lsb,
    unchecked_greater,
    unchecked_less,
    unchecked_equal,
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
    unchecked_scalar_sub,
    unchecked_scalar_div,
    unchecked_scalar_mod,
    unchecked_scalar_left_shift,
    unchecked_scalar_right_shift,
);

criterion_main!(arithmetic_operation, arithmetic_scalar_operation);
