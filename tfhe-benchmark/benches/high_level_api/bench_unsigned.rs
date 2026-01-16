use benchmark::high_level_api::benchmark_op::*;
use benchmark::high_level_api::random_generator::random;
use benchmark::high_level_api::random_generator::*;

use crate::bench_common::bench_fhe_type_op;
use crate::bench_common::bench_kv_store;

use benchmark::utilities::{BitSizesSet, EnvConfig};
use criterion::Criterion;
use oprf::oprf_any_range2;
use std::marker::PhantomData;
use std::ops::*;
use tfhe::prelude::*;
use tfhe::{
    ClientKey, CompressedServerKey, FheBool, FheUint128, FheUint16, FheUint2, FheUint32, FheUint4,
    FheUint64, FheUint8,
};

mod oprf;

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

// generate_typed_benches!(FheInt2, i128);
// generate_typed_benches!(FheInt4, i128);
// generate_typed_benches!(FheInt8, i128);
// generate_typed_benches!(FheInt16, i128);
// generate_typed_benches!(FheInt32, i128);
// generate_typed_benches!(FheInt64, i128);
// generate_typed_benches!(FheInt128, i128);

generate_typed_scalar_benches!(FheUint2, u128, u8, u8);
generate_typed_scalar_benches!(FheUint4, u128, u8, u8);
generate_typed_scalar_benches!(FheUint8, u128, u8, u8);
generate_typed_scalar_benches!(FheUint16, u128, u16, u16);
generate_typed_scalar_benches!(FheUint32, u128, u32, u32);
generate_typed_scalar_benches!(FheUint64, u128, u64, u64);
generate_typed_scalar_benches!(FheUint128, u128, u128, u128);

// generate_typed_scalar_benches!(FheInt2, i128, i8, u8);
// generate_typed_scalar_benches!(FheInt4, i128, i8, u8);
// generate_typed_scalar_benches!(FheInt8, i128, i8, u8);
// generate_typed_scalar_benches!(FheInt16, i128, i16, u16);
// generate_typed_scalar_benches!(FheInt32, i128, i32, u32);
// generate_typed_scalar_benches!(FheInt64, i128, i64, u64);
// generate_typed_scalar_benches!(FheInt128, i128, i128, u128);

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
                FheUint128, //FheInt2, FheInt4, FheInt8, FheInt16, FheInt32, FheInt64, FheInt128
            );
            run_scalar_benches!(
                &mut c, &cks, FheUint2, FheUint4, FheUint8, FheUint16, FheUint32, FheUint64,
                FheUint128, //FheInt2, FheInt4, FheInt8, FheInt16, FheInt32, FheInt64, FheInt128
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
