use benchmark::high_level_api::type_display::*;
use benchmark::utilities::{
    get_bench_type, hlapi_throughput_num_ops, write_to_json, BenchmarkType, BitSizesSet, EnvConfig,
    OperatorType,
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

    let format_id_bench = |op_name: &str| -> String {
        format!(
            "hlapi::kv_store::{op_name}::{}::key_{}_value_{}_elements_{num_elements}",
            param.name(),
            TypeDisplayer::<Key>::default(),
            TypeDisplayer::<Value>::default(),
        )
    };

    let bench_id_get;
    let bench_id_update;
    let bench_id_map;

    match get_bench_type() {
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

            bench_id_get = format_id_bench("get");
            bench_group.bench_function(&bench_id_get, |b| {
                b.iter(|| {
                    let _ = kv_store.get(&encrypted_key);
                })
            });

            bench_id_update = format_id_bench("update");
            bench_group.bench_function(&bench_id_update, |b| {
                b.iter(|| {
                    let _ = kv_store.update(&encrypted_key, &value_to_add);
                })
            });

            bench_id_map = format_id_bench("map");
            bench_group.bench_function(&bench_id_map, |b| {
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
            )
            .max(1);

            let mut kv_stores = vec![];
            for _ in 0..factor {
                kv_stores.push(kv_store.clone());
            }

            bench_group.throughput(Throughput::Elements(kv_stores.len() as u64));

            bench_id_get = format_id_bench("get::throughput");
            bench_group.bench_function(&bench_id_get, |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.get(&encrypted_key);
                    })
                })
            });

            bench_id_update = format_id_bench("update::throughput");
            bench_group.bench_function(&bench_id_update, |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.update(&encrypted_key, &value_to_add);
                    })
                })
            });

            bench_id_map = format_id_bench("map::throughput");
            bench_group.bench_function(&bench_id_map, |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.map(&encrypted_key, |v| v);
                    })
                })
            });
        }
    }

    for (bench_id, display_name) in [
        (bench_id_get, "get"),
        (bench_id_update, "update"),
        (bench_id_map, "map"),
    ] {
        write_to_json::<u64, _>(
            &bench_id,
            param,
            param.name(),
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
