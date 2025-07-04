#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(not(feature = "gpu"))]
use benchmark::params_aliases::BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(not(feature = "gpu"))]
use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use criterion::Criterion;
use rand::prelude::*;
use rand::thread_rng;
use std::fmt::Write;
use tfhe::prelude::*;

use tfhe::{
    ClientKey, CompressedServerKey, FheUint10, FheUint12, FheUint128, FheUint14, FheUint16,
    FheUint2, FheUint32, FheUint4, FheUint6, FheUint64, FheUint8,
};

fn bench_fhe_type<FheType>(c: &mut Criterion, client_key: &ClientKey, type_name: &str)
where
    FheType: FheEncrypt<u128, ClientKey>,
    FheType: SquashNoise,
{
    let mut bench_group = c.benchmark_group(type_name);

    let mut rng = thread_rng();

    let input = FheType::encrypt(rng.gen(), client_key);

    let mut name = String::with_capacity(255);

    write!(name, "noise squash({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| {
        b.iter(|| {
            let _ = input.squash_noise();
        })
    });
    name.clear();
}

macro_rules! bench_type {
    ($fhe_type:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type::<$fhe_type>(c, cks, stringify!($fhe_type));
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

fn main() {
    #[cfg(feature = "hpu")]
    panic!("Noise squashing is not supported on HPU");
    #[cfg(all(not(feature = "hpu"), not(feature = "gpu")))]
    let cks = {
        use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        use tfhe::{set_server_key, ConfigBuilder};
        let config =
            ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
                .enable_noise_squashing(
                    BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                )
                .build();
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        set_server_key(compressed_sks.decompress());
        cks
    };
    #[cfg(feature = "gpu")]
    let cks = {
        use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        use tfhe::{set_server_key, ConfigBuilder};
        let config = ConfigBuilder::with_custom_parameters(
            BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .enable_noise_squashing(
            BENCH_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .build();
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        set_server_key(compressed_sks.decompress_to_gpu());
        cks
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

    c.final_summary();
}
