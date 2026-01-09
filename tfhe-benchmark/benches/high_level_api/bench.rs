use benchmark::utilities::{
    hlapi_throughput_num_ops, write_to_json, BenchmarkType, BitSizesSet, EnvConfig, OperatorType,
};
use criterion::{black_box, Criterion, Throughput};
use oprf::oprf_any_range2;
use rand::prelude::*;
use rayon::prelude::*;
use std::marker::PhantomData;
use std::ops::*;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::integer::block_decomposition::DecomposableInto;
use tfhe::keycache::NamedParam;
use tfhe::named::Named;
use tfhe::prelude::*;
use tfhe::{
    ClientKey, CompressedServerKey, FheIntegerType, FheUint, FheUint10, FheUint12, FheUint128,
    FheUint14, FheUint16, FheUint2, FheUint32, FheUint4, FheUint6, FheUint64, FheUint8, FheUintId,
    IntegerId, KVStore,
};

mod oprf;

trait BenchWait {
    fn wait_bench(&self);
}

impl<Id: FheUintId> BenchWait for FheUint<Id> {
    fn wait_bench(&self) {
        self.wait()
    }
}

impl<T1: FheWait, T2> BenchWait for (T1, T2) {
    fn wait_bench(&self) {
        self.0.wait()
    }
}

fn bench_fhe_type_op<FheType, F, R>(
    c: &mut Criterion,
    client_key: &ClientKey,
    type_name: &str,
    bit_size: usize,
    display_name: &str,
    func_name: &str,
    func: F,
) where
    F: Fn(&FheType, &FheType) -> R,
    R: BenchWait,
    FheType: FheEncrypt<u128, ClientKey>,
    FheType: FheWait,
{
    let mut bench_group = c.benchmark_group(type_name);
    let mut bench_prefix = "hlapi".to_string();
    if cfg!(feature = "gpu") {
        bench_prefix = format!("{}::cuda", bench_prefix);
    } else if cfg!(feature = "hpu") {
        bench_prefix = format!("{}::hpu", bench_prefix);
    }

    bench_prefix = format!("{}::ops", bench_prefix);

    let mut rng = thread_rng();

    let param = client_key.computation_parameters();
    let param_name = param.name();
    let bit_size = bit_size as u32;

    let write_record = |bench_id: String, display_name| {
        write_to_json::<u64, _>(
            &bench_id,
            param,
            &param_name,
            display_name,
            &OperatorType::Atomic,
            bit_size,
            vec![],
        );
    };

    let lhs = FheType::encrypt(rng.gen(), client_key);
    let rhs = FheType::encrypt(rng.gen(), client_key);

    let bench_id = format!("{bench_prefix}::{func_name}::{param_name}::{type_name}");

    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = func(&lhs, &rhs);
            res.wait_bench();
            black_box(res)
        })
    });
    write_record(bench_id, display_name);
}

macro_rules! bench_type_op (
    (type_name: $fhe_type:ident, display_name: $display_name:literal, operation: $op:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake _ $op>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type_op::<$fhe_type, _, _>(
                    c,
                    cks,
                    stringify!($fhe_type),
                    $fhe_type::num_bits(),
                    $display_name,
                    stringify!($op),
                    |lhs, rhs| lhs.$op(rhs)
                );
            }
        }
    };
);

macro_rules! generate_typed_benches {
    ($fhe_type:ident) => {
        bench_type_op!(type_name: $fhe_type, display_name: "add", operation: add);
        bench_type_op!(type_name: $fhe_type, display_name: "overflowing_add", operation: overflowing_add);
        bench_type_op!(type_name: $fhe_type, display_name: "sub", operation: sub);
        bench_type_op!(type_name: $fhe_type, display_name: "overflowing_sub", operation: overflowing_sub);
        bench_type_op!(type_name: $fhe_type, display_name: "mul", operation: mul);
        bench_type_op!(type_name: $fhe_type, display_name: "bitand", operation: bitand);
        bench_type_op!(type_name: $fhe_type, display_name: "bitor", operation: bitor);
        bench_type_op!(type_name: $fhe_type, display_name: "bitxor", operation: bitxor);
        bench_type_op!(type_name: $fhe_type, display_name: "left_shift", operation: shl);
        bench_type_op!(type_name: $fhe_type, display_name: "right_shift", operation: shr);
        bench_type_op!(type_name: $fhe_type, display_name: "left_rotate", operation: rotate_left);
        bench_type_op!(type_name: $fhe_type, display_name: "right_rotate", operation: rotate_right);
        bench_type_op!(type_name: $fhe_type, display_name: "min", operation: min);
        bench_type_op!(type_name: $fhe_type, display_name: "max", operation: max);
    };
}

// Generate benches for all FheUint types
generate_typed_benches!(FheUint2);
generate_typed_benches!(FheUint4);
generate_typed_benches!(FheUint6);
generate_typed_benches!(FheUint8);
generate_typed_benches!(FheUint10);
generate_typed_benches!(FheUint12);
generate_typed_benches!(FheUint14);
generate_typed_benches!(FheUint16);
generate_typed_benches!(FheUint32);
generate_typed_benches!(FheUint64);
generate_typed_benches!(FheUint128);

macro_rules! run_benches {
    ($c:expr, $cks:expr, $($fhe_type:ident),+ $(,)?) => {
        $(
            ::paste::paste! {
                [<bench_ $fhe_type:snake _add>]($c, $cks);
                [<bench_ $fhe_type:snake _overflowing_add>]($c, $cks);
                [<bench_ $fhe_type:snake _sub>]($c, $cks);
                [<bench_ $fhe_type:snake _overflowing_sub>]($c, $cks);
                [<bench_ $fhe_type:snake _mul>]($c, $cks);
                [<bench_ $fhe_type:snake _bitand>]($c, $cks);
                [<bench_ $fhe_type:snake _bitor>]($c, $cks);
                [<bench_ $fhe_type:snake _bitxor>]($c, $cks);
                [<bench_ $fhe_type:snake _shl>]($c, $cks);
                [<bench_ $fhe_type:snake _shr>]($c, $cks);
                [<bench_ $fhe_type:snake _rotate_left>]($c, $cks);
                [<bench_ $fhe_type:snake _rotate_right>]($c, $cks);
                [<bench_ $fhe_type:snake _min>]($c, $cks);
                [<bench_ $fhe_type:snake _max>]($c, $cks);
            }
        )+
    };
}

trait TypeDisplay {
    fn fmt(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = std::any::type_name::<Self>();
        let pos = name.rfind(":").map_or(0, |p| p + 1);
        write!(f, "{}", &name[pos..])
    }
}

impl TypeDisplay for u8 {}
impl TypeDisplay for u16 {}
impl TypeDisplay for u32 {}
impl TypeDisplay for u64 {}
impl TypeDisplay for u128 {}

impl<Id: FheUintId> TypeDisplay for tfhe::FheUint<Id> {
    fn fmt(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_fhe_type_name::<Self>(f)
    }
}

impl<Id: tfhe::FheIntId> TypeDisplay for tfhe::FheInt<Id> {
    fn fmt(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_fhe_type_name::<Self>(f)
    }
}

struct TypeDisplayer<T: TypeDisplay>(PhantomData<T>);

impl<T: TypeDisplay> Default for TypeDisplayer<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: TypeDisplay> std::fmt::Display for TypeDisplayer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        T::fmt(f)
    }
}

fn write_fhe_type_name<'a, FheType>(f: &mut std::fmt::Formatter<'a>) -> std::fmt::Result
where
    FheType: FheIntegerType + Named,
{
    let full_name = FheType::NAME;
    let i = full_name.rfind(":").map_or(0, |p| p + 1);

    write!(f, "{}{}", &full_name[i..], FheType::Id::num_bits())
}

fn bench_kv_store<Key, FheKey, Value>(c: &mut Criterion, cks: &ClientKey, num_elements: usize)
where
    rand::distributions::Standard: rand::distributions::Distribution<Key>,
    Key: Numeric + DecomposableInto<u64> + Ord + CastInto<usize> + TypeDisplay,
    Value: FheEncrypt<u128, ClientKey> + FheIntegerType + Clone + Send + Sync + TypeDisplay,
    Value::Id: FheUintId,
    FheKey: FheEncrypt<Key, ClientKey> + FheIntegerType + Send + Sync,
    FheKey::Id: FheUintId,
{
    let mut bench_group = c.benchmark_group("kv_store");
    bench_group.sample_size(10);

    let mut kv_store = KVStore::new();
    let mut rng = rand::thread_rng();

    let format_id_bench = |op_name: &str| -> String {
        format!(
            "hlapi::kv_store::<{}, {}>::{op_name}/{num_elements}",
            TypeDisplayer::<Key>::default(),
            TypeDisplayer::<Value>::default(),
        )
    };

    match BenchmarkType::from_env().unwrap() {
        BenchmarkType::Latency => {
            while kv_store.len() != num_elements {
                let key = rng.gen::<Key>();
                let value = rng.gen::<u128>();

                let encrypted_value = Value::encrypt(value, cks);
                kv_store.insert_with_clear_key(key, encrypted_value);
            }

            let key = rng.gen::<Key>();
            let encrypted_key = FheKey::encrypt(key, cks);

            let value = rng.gen::<u128>();
            let value_to_add = Value::encrypt(value, cks);

            bench_group.bench_function(format_id_bench("get"), |b| {
                b.iter(|| {
                    let _ = kv_store.get(&encrypted_key);
                })
            });

            bench_group.bench_function(format_id_bench("update"), |b| {
                b.iter(|| {
                    let _ = kv_store.update(&encrypted_key, &value_to_add);
                })
            });

            bench_group.bench_function(format_id_bench("map"), |b| {
                b.iter(|| {
                    kv_store.map(&encrypted_key, |v| v);
                })
            });
        }
        BenchmarkType::Throughput => {
            while kv_store.len() != num_elements {
                let key = rng.gen::<Key>();
                let value = rng.gen::<u128>();

                let encrypted_value = Value::encrypt(value, cks);
                kv_store.insert_with_clear_key(key, encrypted_value);
            }

            let key = rng.gen::<Key>();
            let encrypted_key = FheKey::encrypt(key, cks);

            let value = rng.gen::<u128>();
            let value_to_add = Value::encrypt(value, cks);

            let factor = hlapi_throughput_num_ops(
                || {
                    kv_store.map(&encrypted_key, |v| v);
                },
                cks,
            );

            let mut kv_stores = vec![];
            for _ in 0..factor.saturating_sub(1) {
                kv_stores.push(kv_store.clone());
            }
            kv_stores.push(kv_store);

            bench_group.throughput(Throughput::Elements(kv_stores.len() as u64));

            bench_group.bench_function(format_id_bench("map::throughput"), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.map(&encrypted_key, |v| v);
                    })
                })
            });

            bench_group.bench_function(format_id_bench("update::throughput"), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.update(&encrypted_key, &value_to_add);
                    })
                })
            });

            bench_group.bench_function(format_id_bench("get::throughput"), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.get(&encrypted_key);
                    })
                })
            });
        }
    }
    bench_group.finish();
}

fn main() {
    let env_config = EnvConfig::new();

    #[cfg(feature = "hpu")]
    let (cks, benched_device) = {
        // Hpu is enabled, start benchmark on Hpu hw accelerator
        use tfhe::tfhe_hpu_backend::prelude::*;
        use tfhe::{set_server_key, Config};

        // Use environment variable to construct path to configuration file
        let config_path = ShellString::new(
            "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml".to_string(),
        );
        let hpu_device = HpuDevice::from_config(&config_path.expand());

        let config = Config::from_hpu_device(&hpu_device);
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        set_server_key((hpu_device, compressed_sks));
        (cks, tfhe::Device::Hpu)
    };
    #[cfg(not(feature = "hpu"))]
    let (cks, benched_device) = {
        use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        use tfhe::{set_server_key, ConfigBuilder};
        let config = ConfigBuilder::with_custom_parameters(
            BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .build();
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        let sks = compressed_sks.decompress();
        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);
        (cks, tfhe::Device::Cpu)
    };

    let mut c = Criterion::default().configure_from_args();

    match env_config.bit_sizes_set {
        BitSizesSet::Fast => {
            run_benches!(&mut c, &cks, FheUint64);

            // KVStore Benches
            if benched_device == tfhe::Device::Cpu {
                bench_kv_store::<u64, FheUint64, FheUint64>(&mut c, &cks, 1 << 10);
            }
        }
        _ => {
            // Call all benchmarks for all types
            run_benches!(
                &mut c, &cks, FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12,
                FheUint14, FheUint16, FheUint32, FheUint64, FheUint128
            );

            // KVStore Benches
            if benched_device == tfhe::Device::Cpu {
                for pow in 1..=10 {
                    bench_kv_store::<u64, FheUint64, FheUint32>(&mut c, &cks, 1 << pow);
                }

                for pow in 1..=10 {
                    bench_kv_store::<u64, FheUint64, FheUint64>(&mut c, &cks, 1 << pow);
                }

                for pow in 1..=10 {
                    bench_kv_store::<u128, FheUint128, FheUint64>(&mut c, &cks, 1 << pow);
                }
            }
        }
    }

    #[cfg(not(feature = "hpu"))]
    oprf_any_range2();

    c.final_summary();
}
