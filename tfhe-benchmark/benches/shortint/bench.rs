use benchmark::params::{
    raw_benchmark_parameters, SHORTINT_BENCH_PARAMS_GAUSSIAN, SHORTINT_BENCH_PARAMS_TUNIFORM,
    SHORTINT_MULTI_BIT_BENCH_PARAMS,
};
use benchmark::utilities::{bench_backend_from_cfg, write_to_json, OperatorType};
use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, ShortintBench};
use criterion::{criterion_group, Criterion};
use rand::Rng;
use std::env;
use tfhe::keycache::NamedParam;
use tfhe::shortint::keycache::KEY_CACHE;
use tfhe::shortint::parameters::*;
use tfhe::shortint::{Ciphertext, CompressedServerKey, ServerKey};

fn bench_server_key_unary_function<F>(
    c: &mut Criterion,
    shortint_bench: ShortintBench,
    display_name: &str,
    unary_op: F,
) where
    F: Fn(&ServerKey, &mut Ciphertext),
{
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());

    for param in raw_benchmark_parameters().iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters().message_modulus().0;

        let clear_text = rng.gen::<u64>() % modulus;

        let mut ct = cks.encrypt(clear_text);

        let param_name = param.name();
        let benchmark_spec = BenchmarkSpec::<str>::new_shortint(
            shortint_bench,
            &param_name,
            BenchmarkMetric::Latency,
            bench_backend_from_cfg(),
        );
        let bench_id = benchmark_spec.to_string();
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                unary_op(sks, &mut ct);
            })
        });

        write_to_json::<u64, _, _>(
            &benchmark_spec,
            *param,
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
    shortint_bench: ShortintBench,
    display_name: &str,
    binary_op: F,
) where
    F: Fn(&ServerKey, &mut Ciphertext, &mut Ciphertext),
{
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());

    for param in raw_benchmark_parameters().iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters().message_modulus().0;

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ct_0 = cks.encrypt(clear_0);
        let mut ct_1 = cks.encrypt(clear_1);

        let param_name = param.name();
        let benchmark_spec = BenchmarkSpec::<str>::new_shortint(
            shortint_bench,
            &param_name,
            BenchmarkMetric::Latency,
            bench_backend_from_cfg(),
        );
        let bench_id = benchmark_spec.to_string();
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                binary_op(sks, &mut ct_0, &mut ct_1);
            })
        });

        write_to_json::<u64, _, _>(
            &benchmark_spec,
            *param,
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
    shortint_bench: ShortintBench,
    display_name: &str,
    binary_op: F,
) where
    F: Fn(&ServerKey, &mut Ciphertext, u8),
{
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());

    for param in raw_benchmark_parameters().iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters().message_modulus().0;

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ct_0 = cks.encrypt(clear_0);

        let param_name = param.name();
        let benchmark_spec = BenchmarkSpec::<str>::new_shortint(
            shortint_bench,
            &param_name,
            BenchmarkMetric::Latency,
            bench_backend_from_cfg(),
        );
        let bench_id = benchmark_spec.to_string();
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                binary_op(sks, &mut ct_0, clear_1 as u8);
            })
        });

        write_to_json::<u64, _, _>(
            &benchmark_spec,
            *param,
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
    shortint_bench: ShortintBench,
    display_name: &str,
    binary_op: F,
) where
    F: Fn(&ServerKey, &mut Ciphertext, u8),
{
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());

    for param in raw_benchmark_parameters().iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters().message_modulus().0;
        assert_ne!(modulus, 1);

        let clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        while clear_1 == 0 {
            clear_1 = rng.gen::<u64>() % modulus;
        }

        let mut ct_0 = cks.encrypt(clear_0);

        let param_name = param.name();
        let benchmark_spec = BenchmarkSpec::<str>::new_shortint(
            shortint_bench,
            &param_name,
            BenchmarkMetric::Latency,
            bench_backend_from_cfg(),
        );
        let bench_id = benchmark_spec.to_string();
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                binary_op(sks, &mut ct_0, clear_1 as u8);
            })
        });

        write_to_json::<u64, _, _>(
            &benchmark_spec,
            *param,
            display_name,
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish()
}

fn carry_extract_bench(c: &mut Criterion) {
    let shortint_bench = ShortintBench::CarryExtract;
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());

    for param in raw_benchmark_parameters().iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters().message_modulus().0;

        let clear_0 = rng.gen::<u64>() % modulus;

        let ct_0 = cks.encrypt(clear_0);

        let param_name = param.name();
        let benchmark_spec = BenchmarkSpec::<str>::new_shortint(
            shortint_bench,
            &param_name,
            BenchmarkMetric::Latency,
            bench_backend_from_cfg(),
        );
        let bench_id = benchmark_spec.to_string();
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let _ = sks.carry_extract(&ct_0);
            })
        });

        write_to_json::<u64, _, _>(
            &benchmark_spec,
            *param,
            "carry_extract",
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish()
}

fn programmable_bootstrapping_bench(c: &mut Criterion) {
    let shortint_bench = ShortintBench::ProgrammableBootstrap;
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());

    for param in raw_benchmark_parameters().iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let (cks, sks) = (keys.client_key(), keys.server_key());

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters().message_modulus().0;

        let acc = sks.generate_lookup_table(|x| x);

        let clear_0 = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear_0);

        let param_name = param.name();
        let benchmark_spec = BenchmarkSpec::<str>::new_shortint(
            shortint_bench,
            &param_name,
            BenchmarkMetric::Latency,
            bench_backend_from_cfg(),
        );
        let bench_id = benchmark_spec.to_string();

        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let _ = sks.apply_lookup_table(&ctxt, &acc);
            })
        });

        write_to_json::<u64, _, _>(
            &benchmark_spec,
            *param,
            "pbs",
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish();
}

fn server_key_from_compressed_key(c: &mut Criterion) {
    let shortint_bench = ShortintBench::UncompressKey;
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());
    bench_group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(60));

    let mut params = SHORTINT_BENCH_PARAMS_TUNIFORM
        .iter()
        .chain(SHORTINT_BENCH_PARAMS_GAUSSIAN.iter())
        .map(|p| (*p).into())
        .collect::<Vec<PBSParameters>>();
    let multi_bit_params = SHORTINT_MULTI_BIT_BENCH_PARAMS
        .iter()
        .map(|p| (*p).into())
        .collect::<Vec<PBSParameters>>();
    params.extend(&multi_bit_params);

    for param in params.iter() {
        let keys = KEY_CACHE.get_from_param(*param);
        let sks_compressed = CompressedServerKey::new(keys.client_key());

        let param_name = param.name();
        let benchmark_spec = BenchmarkSpec::<str>::new_shortint(
            shortint_bench,
            &param_name,
            BenchmarkMetric::Latency,
            bench_backend_from_cfg(),
        );
        let bench_id = benchmark_spec.to_string();

        bench_group.bench_function(&bench_id, |b| {
            let clone_compressed_key = || sks_compressed.clone();

            b.iter_batched(
                clone_compressed_key,
                |sks_cloned| {
                    let _ = sks_cloned.decompress();
                },
                criterion::BatchSize::PerIteration,
            )
        });

        write_to_json::<u64, _, _>(
            &benchmark_spec,
            *param,
            "uncompress_key",
            &OperatorType::Atomic,
            param.message_modulus().0.ilog2(),
            vec![param.message_modulus().0.ilog2()],
        );
    }

    bench_group.finish();
}

macro_rules! define_server_key_unary_bench_fn (
    (method_name:$server_key_method:ident, display_name:$name:ident, shortint_bench:$bench:expr) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_unary_function(
                c,
                $bench,
                stringify!($name),
                |server_key, lhs| {
                    let _ = server_key.$server_key_method(lhs);},
            )
        }
    }
);

macro_rules! define_server_key_bench_fn (
    (method_name:$server_key_method:ident, display_name:$name:ident, shortint_bench:$bench:expr) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_binary_function(
                c,
                $bench,
                stringify!($name),
                |server_key, lhs, rhs| {
                    let _ = server_key.$server_key_method(lhs, rhs);},
            )
        }
    }
);

macro_rules! define_server_key_scalar_bench_fn (
    (method_name:$server_key_method:ident, display_name:$name:ident, shortint_bench:$bench:expr) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_binary_scalar_function(
                c,
                $bench,
                stringify!($name),
                |server_key, lhs, rhs| {
                    let _ = server_key.$server_key_method(lhs, rhs);},
            )
        }
    }
);

macro_rules! define_server_key_scalar_div_bench_fn (
    (method_name:$server_key_method:ident, display_name:$name:ident, shortint_bench:$bench:expr) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_binary_scalar_division_function(
                c,
                $bench,
                stringify!($name),
                |server_key, lhs, rhs| {
                    let _ = server_key.$server_key_method(lhs, rhs);},
            )
        }
    }
);

macro_rules! define_custom_bench_fn (
    (function_name:$function:ident) => {
        fn $function(c: &mut Criterion) {
            ::paste::paste! {
                [<$function _bench>](
                    c,
                )
            }
        }
    }
);

define_server_key_unary_bench_fn!(
    method_name: unchecked_neg,
    display_name: negation,
    shortint_bench: ShortintBench::UncheckedNeg
);
define_server_key_bench_fn!(
    method_name: unchecked_add,
    display_name: add,
    shortint_bench: ShortintBench::UncheckedAdd
);
define_server_key_bench_fn!(
    method_name: unchecked_sub,
    display_name: sub,
    shortint_bench: ShortintBench::UncheckedSub
);
define_server_key_bench_fn!(
    method_name: unchecked_mul_lsb,
    display_name: mul,
    shortint_bench: ShortintBench::UncheckedMulLsb
);
define_server_key_bench_fn!(
    method_name: unchecked_mul_msb,
    display_name: mul,
    shortint_bench: ShortintBench::UncheckedMulMsb
);
define_server_key_bench_fn!(
    method_name: unchecked_div,
    display_name: div,
    shortint_bench: ShortintBench::UncheckedDiv
);
define_server_key_bench_fn!(
    method_name: smart_bitand,
    display_name: bitand,
    shortint_bench: ShortintBench::SmartBitand
);
define_server_key_bench_fn!(
    method_name: smart_bitor,
    display_name: bitor,
    shortint_bench: ShortintBench::SmartBitor
);
define_server_key_bench_fn!(
    method_name: smart_bitxor,
    display_name: bitxor,
    shortint_bench: ShortintBench::SmartBitxor
);
define_server_key_bench_fn!(
    method_name: smart_add,
    display_name: add,
    shortint_bench: ShortintBench::SmartAdd
);
define_server_key_bench_fn!(
    method_name: smart_sub,
    display_name: sub,
    shortint_bench: ShortintBench::SmartSub
);
define_server_key_bench_fn!(
    method_name: smart_mul_lsb,
    display_name: mul,
    shortint_bench: ShortintBench::SmartMulLsb
);
define_server_key_bench_fn!(
    method_name: bitand,
    display_name: bitand,
    shortint_bench: ShortintBench::Bitand
);
define_server_key_bench_fn!(
    method_name: bitor,
    display_name: bitor,
    shortint_bench: ShortintBench::Bitor
);
define_server_key_bench_fn!(
    method_name: bitxor,
    display_name: bitxor,
    shortint_bench: ShortintBench::Bitxor
);
define_server_key_bench_fn!(
    method_name: add,
    display_name: add,
    shortint_bench: ShortintBench::Add
);
define_server_key_bench_fn!(
    method_name: sub,
    display_name: sub,
    shortint_bench: ShortintBench::Sub
);
define_server_key_bench_fn!(
    method_name: mul,
    display_name: mul,
    shortint_bench: ShortintBench::Mul
);
define_server_key_bench_fn!(
    method_name: div,
    display_name: div,
    shortint_bench: ShortintBench::Div
);
define_server_key_bench_fn!(
    method_name: greater,
    display_name: greater_than,
    shortint_bench: ShortintBench::Greater
);
define_server_key_bench_fn!(
    method_name: greater_or_equal,
    display_name: greater_or_equal,
    shortint_bench: ShortintBench::GreaterOrEqual
);
define_server_key_bench_fn!(
    method_name: less,
    display_name: less_than,
    shortint_bench: ShortintBench::Less
);
define_server_key_bench_fn!(
    method_name: less_or_equal,
    display_name: less_or_equal,
    shortint_bench: ShortintBench::LessOrEqual
);
define_server_key_bench_fn!(
    method_name: equal,
    display_name: equal,
    shortint_bench: ShortintBench::Equal
);
define_server_key_bench_fn!(
    method_name: not_equal,
    display_name: not_equal,
    shortint_bench: ShortintBench::NotEqual
);
define_server_key_unary_bench_fn!(
    method_name: neg,
    display_name: negation,
    shortint_bench: ShortintBench::Neg
);
define_server_key_bench_fn!(
    method_name: unchecked_greater,
    display_name: greater_than,
    shortint_bench: ShortintBench::UncheckedGreater
);
define_server_key_bench_fn!(
    method_name: unchecked_less,
    display_name: less_than,
    shortint_bench: ShortintBench::UncheckedLess
);
define_server_key_bench_fn!(
    method_name: unchecked_equal,
    display_name: equal,
    shortint_bench: ShortintBench::UncheckedEqual
);

define_server_key_scalar_bench_fn!(
    method_name: unchecked_scalar_add,
    display_name: add,
    shortint_bench: ShortintBench::UncheckedScalarAdd
);
define_server_key_scalar_bench_fn!(
    method_name: unchecked_scalar_sub,
    display_name: sub,
    shortint_bench: ShortintBench::UncheckedScalarSub
);
define_server_key_scalar_bench_fn!(
    method_name: unchecked_scalar_mul,
    display_name: mul,
    shortint_bench: ShortintBench::UncheckedScalarMul
);
define_server_key_scalar_bench_fn!(
    method_name: unchecked_scalar_left_shift,
    display_name: left_shift,
    shortint_bench: ShortintBench::UncheckedScalarLeftShift
);
define_server_key_scalar_bench_fn!(
    method_name: unchecked_scalar_right_shift,
    display_name: right_shift,
    shortint_bench: ShortintBench::UncheckedScalarRightShift
);

define_server_key_scalar_div_bench_fn!(
    method_name: unchecked_scalar_div,
    display_name: div,
    shortint_bench: ShortintBench::UncheckedScalarDiv
);
define_server_key_scalar_div_bench_fn!(
    method_name: unchecked_scalar_mod,
    display_name: modulo,
    shortint_bench: ShortintBench::UncheckedScalarMod
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_add,
    display_name: add,
    shortint_bench: ShortintBench::ScalarAdd
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_sub,
    display_name: sub,
    shortint_bench: ShortintBench::ScalarSub
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_mul,
    display_name: mul,
    shortint_bench: ShortintBench::ScalarMul
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_left_shift,
    display_name: left_shift,
    shortint_bench: ShortintBench::ScalarLeftShift
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_right_shift,
    display_name: right_shift,
    shortint_bench: ShortintBench::ScalarRightShift
);

define_server_key_scalar_div_bench_fn!(
    method_name: scalar_div,
    display_name: div,
    shortint_bench: ShortintBench::ScalarDiv
);
define_server_key_scalar_div_bench_fn!(
    method_name: scalar_mod,
    display_name: modulo,
    shortint_bench: ShortintBench::ScalarMod
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_greater,
    display_name: greater_than,
    shortint_bench: ShortintBench::ScalarGreater
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_greater_or_equal,
    display_name: greater_or_equal,
    shortint_bench: ShortintBench::ScalarGreaterOrEqual
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_less,
    display_name: less_than,
    shortint_bench: ShortintBench::ScalarLess
);
define_server_key_scalar_bench_fn!(
    method_name: scalar_less_or_equal,
    display_name: less_or_equal,
    shortint_bench: ShortintBench::ScalarLessOrEqual
);
define_server_key_scalar_div_bench_fn!(
    method_name: scalar_equal,
    display_name: equal,
    shortint_bench: ShortintBench::ScalarEqual
);
define_server_key_scalar_div_bench_fn!(
    method_name: scalar_not_equal,
    display_name: not_equal,
    shortint_bench: ShortintBench::ScalarNotEqual
);

define_custom_bench_fn!(function_name: carry_extract);

define_custom_bench_fn!(
    function_name: programmable_bootstrapping
);

criterion_group!(
    smart_ops,
    smart_bitand,
    smart_bitor,
    smart_bitxor,
    smart_add,
    smart_sub,
    smart_mul_lsb
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
    unchecked_scalar_right_shift
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
