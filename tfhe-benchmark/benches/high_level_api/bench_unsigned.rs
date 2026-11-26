use crate::bench_common::bench_fhe_type_op;
use crate::oprf::oprf_any_range2;
use benchmark::high_level_api::benchmark_op::*;
use benchmark::high_level_api::random_generator::{random_non_zero, random_not_power_of_two};
use benchmark::high_level_api::type_display::TypeTagExt;
use benchmark::utilities::{BitSizesSet, EnvConfig};
use benchmark_spec::{HlIntegerOp, OperandType};
use criterion::Criterion;
use std::env;
use std::marker::PhantomData;
use std::ops::*;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::prelude::*;
use tfhe::{
    ClientKey, CompressedServerKey, FheBool, FheUint128, FheUint16, FheUint2, FheUint32, FheUint4,
    FheUint64, FheUint8,
};

#[cfg(not(feature = "hpu"))]
mod numa_key_copies;
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

#[cfg(not(feature = "hpu"))]
generate_typed_scalar_benches!(FheUint2, u128, u8, u8);
#[cfg(not(feature = "hpu"))]
generate_typed_scalar_benches!(FheUint4, u128, u8, u8);
#[cfg(not(feature = "hpu"))]
generate_typed_scalar_benches!(FheUint8, u128, u8, u8);
#[cfg(not(feature = "hpu"))]
generate_typed_scalar_benches!(FheUint16, u128, u16, u16);
#[cfg(not(feature = "hpu"))]
generate_typed_scalar_benches!(FheUint32, u128, u32, u32);
#[cfg(not(feature = "hpu"))]
generate_typed_scalar_benches!(FheUint64, u128, u64, u64);
#[cfg(not(feature = "hpu"))]
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
        let hpu_device =
            HpuDevice::from_config(&config_path.expand(), false).expect("Hpu device init failed");

        let config = Config::from_hpu_device(&hpu_device);
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        set_server_key((hpu_device, compressed_sks));
        (cks, tfhe::Device::Hpu)
    };
    #[cfg(not(feature = "hpu"))]
    let (cks, _) = {
        use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS;
        use tfhe::{set_server_key, ConfigBuilder};
        let config =
            ConfigBuilder::with_custom_parameters(BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS).build();
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        let sks = compressed_sks.decompress();
        // ZOPT_NUMA=replicate: one copy of the keys per NUMA node, each PBS using the
        // copy of its node.
        let sks = if env::var("ZOPT_NUMA").as_deref() == Ok("replicate") {
            numa_key_copies::replicate(sks)
        } else {
            sks
        };
        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);
        if env::var("ZOPT_NUMA").as_deref() == Ok("replicate") {
            // The copies give the same results as the key.
            let (a, b) = (FheUint8::encrypt(200u8, &cks), FheUint8::encrypt(7u8, &cks));
            let quotient: u8 = (&a / &b).decrypt(&cks);
            let product: u8 = (&a * &b).decrypt(&cks);
            assert_eq!((quotient, product), (200 / 7, 200u8.wrapping_mul(7)));
        }
        (cks, tfhe::Device::Cpu)
    };

    let mut c = Criterion::default().configure_from_args();

    // ZOPT_HL_NUMA: the operations compared across NUMA placements, on 8, 64 and 128 bits.
    #[cfg(not(feature = "hpu"))]
    if env::var("ZOPT_HL_NUMA").is_ok() {
        macro_rules! numa_benches {
            ($($fhe_type:ident),+) => {
                $(
                    ::paste::paste! {
                        [<bench_ $fhe_type:snake _add>](&mut c, &cks);
                        [<bench_ $fhe_type:snake _bitand>](&mut c, &cks);
                        [<bench_ $fhe_type:snake _gt>](&mut c, &cks);
                        [<bench_ $fhe_type:snake _shl>](&mut c, &cks);
                        [<bench_ $fhe_type:snake _mul>](&mut c, &cks);
                        [<bench_ $fhe_type:snake _div>](&mut c, &cks);
                    }
                )+
            };
        }
        numa_benches!(FheUint8, FheUint64, FheUint128);
        c.final_summary();
        return;
    }

    match env_config.bit_sizes_set {
        BitSizesSet::Fast => {
            match env::var("__TFHE_RS_BENCH_OP_FLAVOR").as_deref() {
                Ok("fast_default") => {
                    run_benches_dedup!(&mut c, &cks, FheUint64);
                    #[cfg(not(feature = "hpu"))]
                    run_scalar_benches_dedup!(&mut c, &cks, FheUint64);
                }
                _ => {
                    run_benches!(&mut c, &cks, FheUint64);
                    #[cfg(not(feature = "hpu"))]
                    run_scalar_benches!(&mut c, &cks, FheUint64);
                }
            };
        }
        _ => {
            match env::var("__TFHE_RS_BENCH_OP_FLAVOR").as_deref() {
                // Call all benchmarks for all types
                Ok("fast_default") => {
                    run_benches_dedup!(
                        &mut c, &cks, FheUint2, FheUint4, FheUint8, FheUint16, FheUint32,
                        FheUint64, FheUint128,
                    );
                    #[cfg(not(feature = "hpu"))]
                    run_scalar_benches_dedup!(
                        &mut c, &cks, FheUint2, FheUint4, FheUint8, FheUint16, FheUint32,
                        FheUint64, FheUint128,
                    );
                }
                _ => {
                    run_benches!(
                        &mut c, &cks, FheUint2, FheUint4, FheUint8, FheUint16, FheUint32,
                        FheUint64, FheUint128,
                    );
                    #[cfg(not(feature = "hpu"))]
                    run_scalar_benches!(
                        &mut c, &cks, FheUint2, FheUint4, FheUint8, FheUint16, FheUint32,
                        FheUint64, FheUint128,
                    );
                }
            }
        }
    }

    #[cfg(not(feature = "hpu"))]
    oprf_any_range2();

    c.final_summary();
}
