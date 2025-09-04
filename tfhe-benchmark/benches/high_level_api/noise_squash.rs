#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use benchmark::params_aliases::BENCH_NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(not(feature = "gpu"))]
use benchmark::params_aliases::BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::utilities::configure_gpu;
use benchmark::utilities::{
    get_bench_type, throughput_num_threads, write_to_json, BenchmarkType, OperatorType,
};
use criterion::{Criterion, Throughput};
use rand::prelude::*;
use rand::thread_rng;
use rayon::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;

#[cfg(feature = "gpu")]
use tfhe::core_crypto::gpu::get_number_of_gpus;
#[cfg(feature = "gpu")]
use tfhe::{set_server_key, GpuIndex};
use tfhe::{
    ClientKey, CompressedServerKey, FheUint10, FheUint12, FheUint128, FheUint14, FheUint16,
    FheUint2, FheUint32, FheUint4, FheUint6, FheUint64, FheUint8,
};

fn bench_fhe_type<FheType>(
    c: &mut Criterion,
    client_key: &ClientKey,
    type_name: &str,
    num_bits: usize,
) where
    FheType: FheEncrypt<u128, ClientKey> + Send + Sync,
    FheType: SquashNoise,
{
    let mut bench_group = c.benchmark_group(type_name);
    let bench_id_prefix = if cfg!(feature = "gpu") {
        "hlapi::cuda"
    } else {
        "hlapi"
    };
    let bench_id_suffix = format!("noise_squash::{type_name}");

    let mut rng = thread_rng();

    let bench_id;

    match get_bench_type() {
        BenchmarkType::Latency => {
            bench_id = format!("{bench_id_prefix}::{bench_id_suffix}");

            #[cfg(feature = "gpu")]
            configure_gpu(client_key);

            let input = FheType::encrypt(rng.gen(), client_key);

            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    let _ = input.squash_noise();
                })
            });
        }
        BenchmarkType::Throughput => {
            bench_id = format!("{bench_id_prefix}::throughput::{bench_id_suffix}");
            let params = client_key.computation_parameters();
            let num_blocks = num_bits
                .div_ceil((params.message_modulus().0 * params.carry_modulus().0).ilog2() as usize);

            #[cfg(feature = "gpu")]
            {
                let elements = throughput_num_threads(num_blocks, 4);
                bench_group.throughput(Throughput::Elements(elements));
                println!("elements: {elements}");
                let gpu_count = get_number_of_gpus() as usize;
                let compressed_server_key = CompressedServerKey::new(client_key);
                let sks_vec = (0..gpu_count)
                    .map(|i| {
                        compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i as u32))
                    })
                    .collect::<Vec<_>>();

                bench_group.bench_function(&bench_id, |b| {
                    let encrypt_values = || {
                        (0..elements)
                            .map(|_| FheType::encrypt(rng.gen(), client_key))
                            .collect::<Vec<_>>()
                    };

                    b.iter_batched(
                        encrypt_values,
                        |inputs| {
                            inputs.par_iter().enumerate().for_each(|(i, input)| {
                                set_server_key(sks_vec[i % gpu_count].clone());

                                let _ = input.squash_noise();
                            })
                        },
                        criterion::BatchSize::SmallInput,
                    )
                });
            }

            #[cfg(all(not(feature = "hpu"), not(feature = "gpu")))]
            {
                let elements = throughput_num_threads(num_blocks, 1);
                bench_group.throughput(Throughput::Elements(elements));
                println!("elements: {elements}");
                bench_group.bench_function(&bench_id, |b| {
                    let encrypt_values = || {
                        (0..elements)
                            .map(|_| FheType::encrypt(rng.gen(), client_key))
                            .collect::<Vec<_>>()
                    };

                    b.iter_batched(
                        encrypt_values,
                        |inputs| {
                            inputs.par_iter().for_each(|input| {
                                let _ = input.squash_noise();
                            })
                        },
                        criterion::BatchSize::SmallInput,
                    )
                });
            }
        }
    }
    let params = client_key.computation_parameters();

    write_to_json::<u64, _>(
        &bench_id,
        params,
        params.name(),
        "noise_squash",
        &OperatorType::Atomic,
        64,
        vec![],
    );
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

fn main() {
    #[cfg(feature = "hpu")]
    panic!("Noise squashing is not supported on HPU");
    #[cfg(all(not(feature = "hpu"), not(feature = "gpu")))]
    let cks = {
        use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        use tfhe::{set_server_key, ConfigBuilder};
        let config = ConfigBuilder::with_custom_parameters(
            BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .enable_noise_squashing(BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
        .build();
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        let decompressed_sks = compressed_sks.decompress();
        rayon::broadcast(|_| set_server_key(decompressed_sks.clone()));
        set_server_key(decompressed_sks);
        cks
    };
    #[cfg(feature = "gpu")]
    let cks_classical = {
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

    let cks_multibit = {
        use tfhe::{set_server_key, ConfigBuilder};
        let config = ConfigBuilder::with_custom_parameters(
            BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .enable_noise_squashing(
            BENCH_NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .build();
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        set_server_key(compressed_sks.decompress_to_gpu());
        cks
    };
    let mut c = Criterion::default().configure_from_args();

    bench_fhe_uint2(&mut c, &cks_classical);
    bench_fhe_uint4(&mut c, &cks_classical);
    bench_fhe_uint6(&mut c, &cks_classical);
    bench_fhe_uint8(&mut c, &cks_classical);
    bench_fhe_uint10(&mut c, &cks_classical);
    bench_fhe_uint12(&mut c, &cks_classical);
    bench_fhe_uint14(&mut c, &cks_classical);
    bench_fhe_uint16(&mut c, &cks_classical);
    bench_fhe_uint32(&mut c, &cks_classical);
    bench_fhe_uint64(&mut c, &cks_classical);
    bench_fhe_uint128(&mut c, &cks_classical);
    bench_fhe_uint2(&mut c, &cks_multibit);
    bench_fhe_uint4(&mut c, &cks_multibit);
    bench_fhe_uint6(&mut c, &cks_multibit);
    bench_fhe_uint8(&mut c, &cks_multibit);
    bench_fhe_uint10(&mut c, &cks_multibit);
    bench_fhe_uint12(&mut c, &cks_multibit);
    bench_fhe_uint14(&mut c, &cks_multibit);
    bench_fhe_uint16(&mut c, &cks_multibit);
    bench_fhe_uint32(&mut c, &cks_multibit);
    bench_fhe_uint64(&mut c, &cks_multibit);
    bench_fhe_uint128(&mut c, &cks_multibit);

    c.final_summary();
}
