use crate::bench_common::{bench_fhe_type_op, BenchConfig};
use crate::oprf::oprf_any_range2;
use benchmark::high_level_api::benchmark_op::*;
use benchmark::high_level_api::random_generator::{random_non_zero, random_not_power_of_two};
use benchmark::utilities::{
    hlapi_throughput_num_ops, BenchmarkType, BitSizesSet, EnvConfig, OperandType,
};
use criterion::{Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use std::marker::PhantomData;
use std::ops::*;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::integer::block_decomposition::DecomposableInto;
use tfhe::named::Named;
use tfhe::prelude::*;
use tfhe::{
    ClientKey, CompressedServerKey, FheBool, FheIntegerType, FheUint128, FheUint16, FheUint2,
    FheUint32, FheUint4, FheUint64, FheUint8, FheUintId, IntegerId, KVStore,
};

mod oprf;

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

impl TypeDisplay for i8 {}
impl TypeDisplay for i16 {}
impl TypeDisplay for i32 {}
impl TypeDisplay for i64 {}
impl TypeDisplay for i128 {}

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

#[macro_use]
mod bench_common;

// Generate benches for all FheUint types
generate_typed_benches!(FheUint2, u128);
generate_typed_benches!(FheUint4, u128);
generate_typed_benches!(FheUint8, u128);
generate_typed_benches!(FheUint16, u128);
generate_typed_benches!(FheUint32, u128);
generate_typed_benches!(FheUint64, u128);
generate_typed_benches!(FheUint128, u128);

generate_typed_scalar_benches!(FheUint2, u128, u8, u8);
generate_typed_scalar_benches!(FheUint4, u128, u8, u8);
generate_typed_scalar_benches!(FheUint8, u128, u8, u8);
generate_typed_scalar_benches!(FheUint16, u128, u16, u16);
generate_typed_scalar_benches!(FheUint32, u128, u32, u32);
generate_typed_scalar_benches!(FheUint64, u128, u64, u64);
generate_typed_scalar_benches!(FheUint128, u128, u128, u128);

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
                &mut c, &cks, FheUint2, FheUint4, FheUint8, FheUint16, FheUint32, FheUint64,
                FheUint128,
            );
            run_scalar_benches!(
                &mut c, &cks, FheUint2, FheUint4, FheUint8, FheUint16, FheUint32, FheUint64,
                FheUint128,
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
