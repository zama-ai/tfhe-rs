use benchmark::utilities::{hlapi_throughput_num_ops, write_to_json, BenchmarkType, OperatorType};
use criterion::{black_box, Criterion, Throughput};
use rand::prelude::*;
use std::marker::PhantomData;
use std::ops::*;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::integer::block_decomposition::DecomposableInto;
use tfhe::keycache::NamedParam;
use tfhe::named::Named;
use tfhe::prelude::*;
use tfhe::{
    ClientKey, CompressedServerKey, FheIntegerType, FheUint10, FheUint12, FheUint128, FheUint14,
    FheUint16, FheUint2, FheUint32, FheUint4, FheUint6, FheUint64, FheUint8, FheUintId, IntegerId,
    KVStore,
};

use rayon::prelude::*;

fn bench_fhe_type<FheType>(
    c: &mut Criterion,
    client_key: &ClientKey,
    type_name: &str,
    bit_size: usize,
) where
    FheType: FheEncrypt<u128, ClientKey>,
    FheType: FheWait,
    for<'a> &'a FheType: Add<&'a FheType, Output = FheType>
        + Sub<&'a FheType, Output = FheType>
        + Mul<&'a FheType, Output = FheType>
        + BitAnd<&'a FheType, Output = FheType>
        + BitOr<&'a FheType, Output = FheType>
        + BitXor<&'a FheType, Output = FheType>
        + Shl<&'a FheType, Output = FheType>
        + Shr<&'a FheType, Output = FheType>
        + RotateLeft<&'a FheType, Output = FheType>
        + RotateRight<&'a FheType, Output = FheType>
        + OverflowingAdd<&'a FheType, Output = FheType>
        + OverflowingSub<&'a FheType, Output = FheType>,
    for<'a> FheType: FheMin<&'a FheType, Output = FheType> + FheMax<&'a FheType, Output = FheType>,
{
    let mut bench_group = c.benchmark_group(type_name);
    let mut bench_prefix = "hlapi::ops".to_string();
    if cfg!(feature = "gpu") {
        bench_prefix = format!("{}::cuda", bench_prefix);
    } else if cfg!(feature = "hpu") {
        bench_prefix = format!("{}::hpu", bench_prefix);
    }

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

    let mut bench_id;

    bench_id = format!("{bench_prefix}::add::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs + &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "add");

    bench_id = format!("{bench_prefix}::overflowing_add::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let (res, flag) = lhs.overflowing_add(&rhs);
            res.wait();
            black_box((res, flag))
        })
    });
    write_record(bench_id, "overflowing_add");

    bench_id = format!("{bench_prefix}::overflowing_sub::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let (res, flag) = lhs.overflowing_sub(&rhs);
            res.wait();
            black_box((res, flag))
        })
    });
    write_record(bench_id, "overflowing_sub");

    bench_id = format!("{bench_prefix}::sub::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs - &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "sub");

    bench_id = format!("{bench_prefix}::mul::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs * &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "mul");

    bench_id = format!("{bench_prefix}::bitand::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs & &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "bitand");

    bench_id = format!("{bench_prefix}::bitor::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs | &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "bitor");

    bench_id = format!("{bench_prefix}::bitxor::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs ^ &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "bitxor");

    bench_id = format!("{bench_prefix}::left_shift::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs << &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "left_shift");

    bench_id = format!("{bench_prefix}::right_shift::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs >> &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "right_shift");

    bench_id = format!("{bench_prefix}::left_rotate::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = (&lhs).rotate_left(&rhs);
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "left_rotate");

    bench_id = format!("{bench_prefix}::right_rotate::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = (&lhs).rotate_right(&rhs);
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "right_rotate");

    bench_id = format!("{bench_prefix}::min::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = lhs.min(&rhs);
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "min");

    bench_id = format!("{bench_prefix}::max::{param_name}::{bit_size}_bits");
    println!("{bench_id}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = lhs.max(&rhs);
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "max");
}

macro_rules! bench_type {
    ($fhe_type:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type::<$fhe_type>(c, cks, stringify!($fhe_type), $fhe_type::num_bits());
            }
        }
    };
}

bench_type!(FheUint2);
bench_type!(FheUint4);
bench_type!(FheUint6);
bench_type!(FheUint8);
bench_type!(FheUint10);
bench_type!(FheUint12);
bench_type!(FheUint14);
bench_type!(FheUint16);
bench_type!(FheUint32);
bench_type!(FheUint64);
bench_type!(FheUint128);

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
    let mut kv_store = KVStore::new();
    let mut rng = rand::thread_rng();

    let format_and_print_bench_id = |op_name: &str| -> String {
        let bench_id = format!(
            "KVStore::<{}, {}>::{op_name}/{num_elements}",
            TypeDisplayer::<Key>::default(),
            TypeDisplayer::<Value>::default(),
        );
        println!("{bench_id}");
        bench_id
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

            c.bench_function(&format_and_print_bench_id("Get"), |b| {
                b.iter(|| {
                    let _ = kv_store.get(&encrypted_key);
                })
            });

            c.bench_function(&format_and_print_bench_id("Update"), |b| {
                b.iter(|| {
                    let _ = kv_store.update(&encrypted_key, &value_to_add);
                })
            });

            c.bench_function(&format_and_print_bench_id("Map"), |b| {
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

            let mut group = c.benchmark_group("KVStore Throughput");
            group.throughput(Throughput::Elements(kv_stores.len() as u64));

            group.bench_function(format_and_print_bench_id("Map"), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.map(&encrypted_key, |v| v);
                    })
                })
            });

            group.bench_function(format_and_print_bench_id("Update"), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.update(&encrypted_key, &value_to_add);
                    })
                })
            });

            group.bench_function(format_and_print_bench_id("Get"), |b| {
                b.iter(|| {
                    kv_stores.par_iter_mut().for_each(|kv_store| {
                        kv_store.get(&encrypted_key);
                    })
                })
            });

            group.finish();
        }
    }
}

fn main() {
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

    bench_fhe_uint2(&mut c, &cks);
    bench_fhe_uint4(&mut c, &cks);
    bench_fhe_uint6(&mut c, &cks);
    bench_fhe_uint8(&mut c, &cks);
    bench_fhe_uint10(&mut c, &cks);
    bench_fhe_uint12(&mut c, &cks);
    bench_fhe_uint14(&mut c, &cks);
    bench_fhe_uint16(&mut c, &cks);
    bench_fhe_uint32(&mut c, &cks);
    bench_fhe_uint64(&mut c, &cks);
    bench_fhe_uint128(&mut c, &cks);

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

    c.final_summary();
}
