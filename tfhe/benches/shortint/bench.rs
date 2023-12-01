#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, OperatorType};
use std::env;

use criterion::{criterion_group, Criterion};
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::*;
use tfhe::shortint::{
    Ciphertext, ClassicPBSParameters, CompressedServerKey, ServerKey, ShortintParameterSet,
};

use rand::Rng;
use tfhe::shortint::keycache::{KEY_CACHE, KEY_CACHE_WOPBS};

use tfhe::shortint::parameters::parameters_wopbs::WOPBS_PARAM_MESSAGE_4_NORM2_6_KS_PBS;

const SERVER_KEY_BENCH_PARAMS: [ClassicPBSParameters; 4] = [
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
];

const SERVER_KEY_BENCH_PARAMS_EXTENDED: [ClassicPBSParameters; 15] = [
    PARAM_MESSAGE_1_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_0_KS_PBS,
    PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_0_KS_PBS,
    PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_0_KS_PBS,
    PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MESSAGE_5_CARRY_0_KS_PBS,
    PARAM_MESSAGE_6_CARRY_0_KS_PBS,
    PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    PARAM_MESSAGE_8_CARRY_0_KS_PBS,
];

const SERVER_KEY_MULTI_BIT_BENCH_PARAMS: [MultiBitPBSParameters; 2] = [
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
];

const SERVER_KEY_MULTI_BIT_BENCH_PARAMS_EXTENDED: [MultiBitPBSParameters; 6] = [
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
];

enum BenchParamsSet {
    Standard,
    Extended,
}

fn benchmark_parameters(params_set: BenchParamsSet) -> Vec<PBSParameters> {
    let is_multi_bit = match env::var("__TFHE_RS_BENCH_TYPE") {
        Ok(val) => val.to_lowercase() == "multi_bit",
        Err(_) => false,
    };

    if is_multi_bit {
        let params = match params_set {
            BenchParamsSet::Standard => SERVER_KEY_MULTI_BIT_BENCH_PARAMS.to_vec(),
            BenchParamsSet::Extended => SERVER_KEY_MULTI_BIT_BENCH_PARAMS_EXTENDED.to_vec(),
        };
        params.iter().map(|p| (*p).into()).collect()
    } else {
        let params = match params_set {
            BenchParamsSet::Standard => SERVER_KEY_BENCH_PARAMS.to_vec(),
            BenchParamsSet::Extended => SERVER_KEY_BENCH_PARAMS_EXTENDED.to_vec(),
        };
        params.iter().map(|p| (*p).into()).collect()
    }
}

fn bench_server_key_unary_function<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    unary_op: F,
    params_set: BenchParamsSet,
) where
    F: Fn(&ServerKey, &mut Ciphertext),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for param in benchmark_parameters(params_set).iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus().0 as u64;

        let clear_text = rng.gen::<u64>() % modulus;

        let mut ct = cks.encrypt(clear_text);

        let bench_id = format!("{bench_name}::{}", param.name());
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                unary_op(sks, &mut ct);
            })
        });

        write_to_json::<u64, _>(
            &bench_id,
            *param,
            param.name(),
            display_name,
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish()
}

fn bench_server_key_binary_function<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
    params_set: BenchParamsSet,
) where
    F: Fn(&ServerKey, &mut Ciphertext, &mut Ciphertext),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for param in benchmark_parameters(params_set).iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus().0 as u64;

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

        write_to_json::<u64, _>(
            &bench_id,
            *param,
            param.name(),
            display_name,
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish()
}

fn bench_server_key_binary_scalar_function<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
    params_set: BenchParamsSet,
) where
    F: Fn(&ServerKey, &mut Ciphertext, u8),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for param in benchmark_parameters(params_set).iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus().0 as u64;

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ct_0 = cks.encrypt(clear_0);

        let bench_id = format!("{bench_name}::{}", param.name());
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                binary_op(sks, &mut ct_0, clear_1 as u8);
            })
        });

        write_to_json::<u64, _>(
            &bench_id,
            *param,
            param.name(),
            display_name,
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish()
}

fn bench_server_key_binary_scalar_division_function<F>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
    params_set: BenchParamsSet,
) where
    F: Fn(&ServerKey, &mut Ciphertext, u8),
{
    let mut bench_group = c.benchmark_group(bench_name);

    for param in benchmark_parameters(params_set).iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus().0 as u64;
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

        write_to_json::<u64, _>(
            &bench_id,
            *param,
            param.name(),
            display_name,
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish()
}

fn carry_extract_bench(c: &mut Criterion, params_set: BenchParamsSet) {
    let mut bench_group = c.benchmark_group("carry_extract");

    for param in benchmark_parameters(params_set).iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus().0 as u64;

        let clear_0 = rng.gen::<u64>() % modulus;

        let ct_0 = cks.encrypt(clear_0);

        let bench_id = format!("shortint::carry_extract::{}", param.name());
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let _ = sks.carry_extract(&ct_0);
            })
        });

        write_to_json::<u64, _>(
            &bench_id,
            *param,
            param.name(),
            "carry_extract",
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish()
}

fn programmable_bootstrapping_bench(c: &mut Criterion, params_set: BenchParamsSet) {
    let mut bench_group = c.benchmark_group("programmable_bootstrap");

    for param in benchmark_parameters(params_set).iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus().0 as u64;

        let acc = sks.generate_lookup_table(|x| x);

        let clear_0 = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear_0);

        let bench_id = format!("shortint::programmable_bootstrap::{}", param.name());

        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let _ = sks.apply_lookup_table(&ctxt, &acc);
            })
        });

        write_to_json::<u64, _>(
            &bench_id,
            *param,
            param.name(),
            "pbs",
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish();
}

fn server_key_from_compressed_key(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("uncompress_key");
    bench_group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(60));

    let mut params = SERVER_KEY_BENCH_PARAMS_EXTENDED
        .iter()
        .map(|p| (*p).into())
        .collect::<Vec<PBSParameters>>();
    let multi_bit_params = SERVER_KEY_MULTI_BIT_BENCH_PARAMS_EXTENDED
        .iter()
        .map(|p| (*p).into())
        .collect::<Vec<PBSParameters>>();
    params.extend(&multi_bit_params);

    for param in params.iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let sks_compressed = CompressedServerKey::new(keys.client_key());

        let bench_id = format!("shortint::uncompress_key::{}", param.name());

        bench_group.bench_function(&bench_id, |b| {
            let clone_compressed_key = || sks_compressed.clone();

            b.iter_batched(
                clone_compressed_key,
                |sks_cloned| {
                    let _ = ServerKey::from(sks_cloned);
                },
                criterion::BatchSize::PerIteration,
            )
        });

        write_to_json::<u64, _>(
            &bench_id,
            *param,
            param.name(),
            "uncompress_key",
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish();
}

// TODO: remove?
fn _bench_wopbs_param_message_8_norm2_5(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("programmable_bootstrap");

    let param = WOPBS_PARAM_MESSAGE_4_NORM2_6_KS_PBS;
    let param_set: ShortintParameterSet = param.into();
    let pbs_params = param_set.pbs_parameters().unwrap();

    let keys = KEY_CACHE_WOPBS.get_from_param((pbs_params, param));
    let (cks, _, wopbs_key) = (keys.client_key(), keys.server_key(), keys.wopbs_key());

    let mut rng = rand::thread_rng();

    let clear = rng.gen::<usize>() % param.message_modulus.0;
    let ct = cks.encrypt_without_padding(clear as u64);
    let vec_lut = wopbs_key.generate_lut_native_crt(&ct, |x| x);

    let id = format!("Shortint WOPBS: {param:?}");

    bench_group.bench_function(&id, |b| {
        b.iter(|| {
            let _ = wopbs_key.programmable_bootstrapping_native_crt(&ct, &vec_lut);
        })
    });

    bench_group.finish();
}

macro_rules! define_server_key_unary_bench_fn (
  (method_name:$server_key_method:ident, display_name:$name:ident, $params_set:expr) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_unary_function(
              c,
              concat!("shortint::", stringify!($server_key_method)),
              stringify!($name),
              |server_key, lhs| {
                let _ = server_key.$server_key_method(lhs);},
              $params_set)
      }
  }
);

macro_rules! define_server_key_bench_fn (
  (method_name:$server_key_method:ident, display_name:$name:ident, $params_set:expr) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_function(
              c,
              concat!("shortint::", stringify!($server_key_method)),
              stringify!($name),
              |server_key, lhs, rhs| {
                let _ = server_key.$server_key_method(lhs, rhs);},
              $params_set)
      }
  }
);

macro_rules! define_server_key_scalar_bench_fn (
  (method_name:$server_key_method:ident, display_name:$name:ident, $params_set:expr) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_scalar_function(
              c,
              concat!("shortint::", stringify!($server_key_method)),
              stringify!($name),
              |server_key, lhs, rhs| {
                let _ = server_key.$server_key_method(lhs, rhs);},
              $params_set)
      }
  }
);

macro_rules! define_server_key_scalar_div_bench_fn (
  (method_name:$server_key_method:ident, display_name:$name:ident, $params_set:expr) => {
      fn $server_key_method(c: &mut Criterion) {
          bench_server_key_binary_scalar_division_function(
              c,
              concat!("shortint::", stringify!($server_key_method)),
              stringify!($name),
              |server_key, lhs, rhs| {
                let _ = server_key.$server_key_method(lhs, rhs);},
              $params_set)
      }
  }
);

macro_rules! define_custom_bench_fn (
  (function_name:$function:ident, $params_set:expr) => {
      fn $function(c: &mut Criterion) {
          ::paste::paste! {
              [<$function _bench>](
                  c,
                  $params_set)
          }
      }
  }
);

define_server_key_unary_bench_fn!(
    method_name: unchecked_neg,
    display_name: negation,
    BenchParamsSet::Standard
);

define_server_key_bench_fn!(
    method_name: unchecked_add,
    display_name: add,
    BenchParamsSet::Extended
);
define_server_key_bench_fn!(
    method_name: unchecked_sub,
    display_name: sub,
    BenchParamsSet::Extended
);
define_server_key_bench_fn!(
    method_name: unchecked_mul_lsb,
    display_name: mul,
    BenchParamsSet::Extended
);
define_server_key_bench_fn!(
    method_name: unchecked_mul_msb,
    display_name: mul,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: unchecked_div,
    display_name: div,
    BenchParamsSet::Extended
);
define_server_key_bench_fn!(
    method_name: smart_bitand,
    display_name: bitand,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: smart_bitor,
    display_name: bitor,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: smart_bitxor,
    display_name: bitxor,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: smart_add,
    display_name: add,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: smart_sub,
    display_name: sub,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: smart_mul_lsb,
    display_name: mul,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: bitand,
    display_name: bitand,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: bitor,
    display_name: bitor,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: bitxor,
    display_name: bitxor,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: add,
    display_name: add,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: sub,
    display_name: sub,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: mul,
    display_name: mul,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: div,
    display_name: div,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: greater,
    display_name: greater,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: greater_or_equal,
    display_name: greater_or_equal,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: less,
    display_name: less,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: less_or_equal,
    display_name: less_or_equal,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: equal,
    display_name: equal,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: not_equal,
    display_name: not_equal,
    BenchParamsSet::Standard
);
define_server_key_unary_bench_fn!(
    method_name: neg,
    display_name: negation,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: unchecked_greater,
    display_name: greater_than,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: unchecked_less,
    display_name: less_than,
    BenchParamsSet::Standard
);
define_server_key_bench_fn!(
    method_name: unchecked_equal,
    display_name: equal,
    BenchParamsSet::Standard
);

define_server_key_scalar_bench_fn!(
    method_name: unchecked_scalar_add,
    display_name: add,
    BenchParamsSet::Extended
);
define_server_key_scalar_bench_fn!(
    method_name: unchecked_scalar_sub,
    display_name: sub,
    BenchParamsSet::Extended
);
define_server_key_scalar_bench_fn!(
    method_name: unchecked_scalar_mul,
    display_name: mul,
    BenchParamsSet::Extended
);
define_server_key_scalar_bench_fn!(
    method_name: unchecked_scalar_left_shift,
    display_name: left_shift,
    BenchParamsSet::Standard
);
define_server_key_scalar_bench_fn!(
    method_name: unchecked_scalar_right_shift,
    display_name: right_shift,
    BenchParamsSet::Standard
);

define_server_key_scalar_div_bench_fn!(
    method_name: unchecked_scalar_div,
    display_name: div,
    BenchParamsSet::Extended
);
define_server_key_scalar_div_bench_fn!(
    method_name: unchecked_scalar_mod,
    display_name: modulo,
    BenchParamsSet::Standard
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_add,
    display_name: add,
    BenchParamsSet::Standard
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_sub,
    display_name: sub,
    BenchParamsSet::Standard
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_mul,
    display_name: mul,
    BenchParamsSet::Standard
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_left_shift,
    display_name: left_shift,
    BenchParamsSet::Standard
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_right_shift,
    display_name: right_shift,
    BenchParamsSet::Standard
);

define_server_key_scalar_div_bench_fn!(
    method_name: scalar_div,
    display_name: div,
    BenchParamsSet::Standard
);
define_server_key_scalar_div_bench_fn!(
    method_name: scalar_mod,
    display_name: modulo,
    BenchParamsSet::Standard
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_greater,
    display_name: greater,
    BenchParamsSet::Standard
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_greater_or_equal,
    display_name: greater_or_equal,
    BenchParamsSet::Standard
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_less,
    display_name: less,
    BenchParamsSet::Standard
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_less_or_equal,
    display_name: less_or_equal,
    BenchParamsSet::Standard
);
define_server_key_scalar_div_bench_fn!(
    method_name: scalar_equal,
    display_name: equal,
    BenchParamsSet::Standard
);
define_server_key_scalar_div_bench_fn!(
    method_name: scalar_not_equal,
    display_name: not_equal,
    BenchParamsSet::Standard
);

define_custom_bench_fn!(function_name: carry_extract, BenchParamsSet::Standard);

define_custom_bench_fn!(
    function_name: programmable_bootstrapping,
    BenchParamsSet::Standard
);

criterion_group!(
    smart_ops,
    smart_bitand,
    smart_bitor,
    smart_bitxor,
    smart_add,
    smart_sub,
    smart_mul_lsb,
);

criterion_group!(
    unchecked_ops,
    unchecked_neg,
    unchecked_add,
    unchecked_sub,
    unchecked_mul_lsb,
    unchecked_mul_msb,
    unchecked_div,
    unchecked_greater,
    unchecked_less,
    unchecked_equal,
    carry_extract,
    programmable_bootstrapping
);

criterion_group!(
    unchecked_scalar_ops,
    unchecked_scalar_add,
    unchecked_scalar_mul,
    unchecked_scalar_sub,
    unchecked_scalar_div,
    unchecked_scalar_mod,
    unchecked_scalar_left_shift,
    unchecked_scalar_right_shift,
);

criterion_group!(
    default_ops,
    neg,
    bitand,
    bitor,
    bitxor,
    add,
    sub,
    div,
    mul,
    greater,
    greater_or_equal,
    less,
    less_or_equal,
    equal,
    not_equal
);

criterion_group!(
    default_scalar_ops,
    scalar_add,
    scalar_sub,
    scalar_div,
    scalar_mul,
    scalar_mod,
    scalar_left_shift,
    scalar_right_shift,
    scalar_greater,
    scalar_greater_or_equal,
    scalar_less,
    scalar_less_or_equal,
    scalar_equal,
    scalar_not_equal
);

criterion_group!(misc, server_key_from_compressed_key);

mod casting;
criterion_group!(
    casting,
    casting::pack_cast_64,
    casting::pack_cast,
    casting::cast
);

fn main() {
    fn default_bench() {
        casting();
        default_ops();
        default_scalar_ops();
        misc();
    }

    match env::var("__TFHE_RS_BENCH_OP_FLAVOR") {
        Ok(val) => {
            match val.to_lowercase().as_str() {
                "default" => default_bench(),
                "smart" => smart_ops(),
                "unchecked" => {
                    unchecked_ops();
                    unchecked_scalar_ops();
                }
                _ => panic!("unknown benchmark operations flavor"),
            };
        }
        Err(_) => default_bench(),
    };

    Criterion::default().configure_from_args().final_summary();
}
