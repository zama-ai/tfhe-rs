#[cfg(not(any(feature = "gpu", feature = "hpu")))]
use benchmark::find_optimal_batch::find_optimal_batch;
use benchmark::high_level_api::type_display::*;
use benchmark::utilities::{
    bench_backend_from_cfg, write_to_json, BitSizesSet, EnvConfig, OperatorType,
};
use benchmark_spec::tfhe::hlapi::kv_store::KvStoreOp;
use benchmark_spec::{
    get_bench_type, BenchmarkSpec, CriteriaBenchType, HlapiBench, OperandType, TypedKeyValue,
};
use criterion::{Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::integer::block_decomposition::DecomposableInto;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::{
    ClientKey, CompressedServerKey, FheIntegerType, FheUint128, FheUint32, FheUint64, FheUintId,
    KVStore,
};

fn bench_kv_store<Key, FheKey, Value>(c: &mut Criterion, cks: &ClientKey, num_elements: usize)
where
    rand::distributions::Standard: Distribution<Key>,
    Key: Numeric + DecomposableInto<u64> + Ord + CastInto<usize> + TypeDisplay,
    Value: FheEncrypt<u128, ClientKey> + FheIntegerType + Clone + Send + Sync + TypeDisplay,
    Value::Id: FheUintId,
    FheKey: FheEncrypt<Key, ClientKey> + FheIntegerType + Send + Sync,
    FheKey::Id: FheUintId,
{
    let param = cks.computation_parameters();
    let mut bench_group = c.benchmark_group("kv_store");
    bench_group.sample_size(10);

    let mut kv_store = KVStore::new();
    let mut rng = rand::thread_rng();

    let key_name = TypeDisplayer::<Key>::default().to_string();
    let value_name = TypeDisplayer::<Value>::default().to_string();
    let tkv = TypedKeyValue::new(&key_name, &value_name);

    let param_name = param.name();
    let bench_type = get_bench_type();

    let bench_spec_get = BenchmarkSpec::new_hlapi(
        HlapiBench::KvStore(KvStoreOp::Get),
        &param_name,
        &OperandType::CipherText,
        Some(&tkv),
        *bench_type,
        bench_backend_from_cfg(),
        Some(num_elements),
    );
    let bench_spec_update = BenchmarkSpec::new_hlapi(
        HlapiBench::KvStore(KvStoreOp::Update),
        &param_name,
        &OperandType::CipherText,
        Some(&tkv),
        *bench_type,
        bench_backend_from_cfg(),
        Some(num_elements),
    );
    let bench_spec_map = BenchmarkSpec::new_hlapi(
        HlapiBench::KvStore(KvStoreOp::Map),
        &param_name,
        &OperandType::CipherText,
        Some(&tkv),
        *bench_type,
        bench_backend_from_cfg(),
        Some(num_elements),
    );

    match bench_type {
        CriteriaBenchType::Latency => {
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

            bench_group.bench_function(bench_spec_get.to_string(), |b| {
                b.iter(|| {
                    let _ = kv_store.get(&encrypted_key);
                })
            });

            bench_group.bench_function(bench_spec_update.to_string(), |b| {
                b.iter(|| {
                    let _ = kv_store.update(&encrypted_key, &value_to_add);
                })
            });

            bench_group.bench_function(bench_spec_map.to_string(), |b| {
                b.iter(|| {
                    kv_store.map(&encrypted_key, |v| v);
                })
            });
        }
        CriteriaBenchType::Throughput => {
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

            let (elements, mut kv_stores) = {
                #[cfg(any(feature = "gpu", feature = "hpu"))]
                {
                    use benchmark::utilities::hlapi_throughput_num_ops;
                    let factor = hlapi_throughput_num_ops(
                        || {
                            kv_store.map(&encrypted_key, |v| v);
                        },
                        cks,
                    )
                    .max(1);

                    let mut kv_stores = vec![];
                    for _ in 0..factor {
                        kv_stores.push(kv_store.clone());
                    }

                    (kv_stores.len() as u64, kv_stores)
                }
                #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                {
                    let setup = |batch_size: usize| {
                        (0..batch_size)
                            .map(|_| kv_store.clone())
                            .collect::<Vec<_>>()
                    };
                    let run = |kv_stores: &mut Vec<_>, batch_size: usize| {
                        kv_stores.par_iter_mut().take(batch_size).for_each(
                            |kv_store: &mut KVStore<Key, Value>| {
                                kv_store.map(&encrypted_key, |v| v);
                            },
                        )
                    };
                    let elements = find_optimal_batch(run, setup);
                    (elements as u64, setup(elements))
                }
            };

            bench_group.throughput(Throughput::Elements(elements));

            bench_group.bench_function(bench_spec_get.to_string(), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.get(&encrypted_key);
                    })
                })
            });

            bench_group.bench_function(bench_spec_update.to_string(), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.update(&encrypted_key, &value_to_add);
                    })
                })
            });

            bench_group.bench_function(bench_spec_map.to_string(), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.map(&encrypted_key, |v| v);
                    })
                })
            });
        }
    }

    for (bench_spec, display_name) in [
        (bench_spec_get, "get"),
        (bench_spec_update, "update"),
        (bench_spec_map, "map"),
    ] {
        write_to_json::<u64, _, _>(
            &bench_spec,
            param,
            display_name,
            &OperatorType::Atomic,
            Key::BITS as u32,
            vec![],
        );
    }

    bench_group.finish();
}

fn main() {
    let env_config = EnvConfig::new();

    let (cks, benched_device) = {
        use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS;
        use tfhe::{set_server_key, ConfigBuilder};
        let config =
            ConfigBuilder::with_custom_parameters(BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS).build();
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
            if benched_device == tfhe::Device::Cpu {
                bench_kv_store::<u64, FheUint64, FheUint64>(&mut c, &cks, 1 << 10);
            }
        }
        _ => {
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

    c.final_summary();
}
