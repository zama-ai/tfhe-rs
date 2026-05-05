#[cfg(not(any(feature = "gpu", feature = "hpu")))]
use benchmark::find_optimal_batch::find_optimal_batch;
use benchmark::high_level_api::type_display::*;
#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::utilities::{configure_gpu, get_param_type, ParamType};
use benchmark::utilities::{write_to_json_unchecked, BitSizesSet, EnvConfig, OperatorType};
use benchmark_spec::{get_bench_type, BenchmarkType};
use criterion::{Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::integer::block_decomposition::DecomposableInto;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::{ClientKey, FheIntegerType, FheUint128, FheUint32, FheUint64, FheUintId, KVStore};

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

    let bench_id_prefix = if cfg!(feature = "gpu") {
        "hlapi::cuda"
    } else {
        "hlapi"
    };

    let format_id_bench = |op_name: &str| -> String {
        format!(
            "{bench_id_prefix}::kv_store::{op_name}::{}::key_{}_value_{}_elements_{num_elements}",
            param.name(),
            TypeDisplayer::<Key>::default(),
            TypeDisplayer::<Value>::default(),
        )
    };

    let bench_id_contains_key;
    let bench_id_contains_value;
    let bench_id_contains_clear_value;
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

            bench_id_contains_key = format_id_bench("contains_key");
            bench_group.bench_function(&bench_id_contains_key, |b| {
                b.iter(|| {
                    let _ = kv_store.contains_key(&encrypted_key);
                })
            });

            bench_id_contains_value = format_id_bench("contains_value");
            bench_group.bench_function(&bench_id_contains_value, |b| {
                b.iter(|| {
                    let _ = kv_store.contains_value(&value_to_add);
                })
            });

            bench_id_contains_clear_value = format_id_bench("contains_clear_value");
            bench_group.bench_function(&bench_id_contains_clear_value, |b| {
                b.iter(|| {
                    let _ = kv_store.contains_clear_value(value);
                })
            });

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

            let (elements, mut kv_stores) = {
                #[cfg(any(feature = "gpu", feature = "hpu"))]
                {
                    use benchmark::utilities::throughput_num_threads;
                    let bits_per_block =
                        (param.message_modulus().0 * param.carry_modulus().0).ilog2() as usize;
                    let key_num_blocks = Key::BITS.div_ceil(bits_per_block);
                    // throughput_num_threads sizes for single-ciphertext ops; each KVStore
                    // op touches all num_elements entries, so scale down proportionally
                    let factor =
                        (throughput_num_threads(key_num_blocks, 4) / num_elements as u64).max(1);

                    let kv_stores: Vec<_> = (0..factor).map(|_| kv_store.clone()).collect();

                    (factor, kv_stores)
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

            bench_id_contains_key = format_id_bench("contains_key::throughput");
            bench_group.bench_function(&bench_id_contains_key, |b| {
                b.iter(|| {
                    kv_stores.par_iter().for_each(|kv_store| {
                        kv_store.contains_key(&encrypted_key);
                    })
                })
            });

            bench_id_contains_value = format_id_bench("contains_value::throughput");
            bench_group.bench_function(&bench_id_contains_value, |b| {
                b.iter(|| {
                    kv_stores.par_iter().for_each(|kv_store| {
                        kv_store.contains_value(&value_to_add);
                    })
                })
            });

            bench_id_contains_clear_value = format_id_bench("contains_clear_value::throughput");
            bench_group.bench_function(&bench_id_contains_clear_value, |b| {
                b.iter(|| {
                    kv_stores.par_iter().for_each(|kv_store| {
                        kv_store.contains_clear_value(value);
                    })
                })
            });

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
        (bench_id_contains_key, "contains_key"),
        (bench_id_contains_value, "contains_value"),
        (bench_id_contains_clear_value, "contains_clear_value"),
        (bench_id_get, "get"),
        (bench_id_update, "update"),
        (bench_id_map, "map"),
    ] {
        write_to_json_unchecked::<u64, _>(
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

    #[cfg(feature = "gpu")]
    let cks = {
        let params: tfhe::shortint::AtomicPatternParameters = match get_param_type() {
            ParamType::Classical => BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            _ => BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
        };
        let config = tfhe::ConfigBuilder::with_custom_parameters(params).build();
        let cks = ClientKey::generate(config);
        configure_gpu(&cks);
        cks
    };

    #[cfg(not(feature = "gpu"))]
    let cks = {
        use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS;
        use tfhe::{set_server_key, CompressedServerKey, ConfigBuilder};
        let config =
            ConfigBuilder::with_custom_parameters(BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS).build();
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);
        let sks = compressed_sks.decompress();
        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);
        cks
    };

    let mut c = Criterion::default().configure_from_args();

    match env_config.bit_sizes_set {
        BitSizesSet::Fast => {
            bench_kv_store::<u64, FheUint64, FheUint64>(&mut c, &cks, 1 << 10);
        }
        _ => {
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

    c.final_summary();
}
