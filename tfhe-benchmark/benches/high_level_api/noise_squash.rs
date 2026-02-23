#[cfg(not(feature = "hpu"))]
use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

use benchmark::high_level_api::bench_wait::BenchWait;
use benchmark::params_aliases::{
    BENCH_COMP_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
#[cfg(feature = "gpu")]
use benchmark::params_aliases::{
    BENCH_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
#[cfg(feature = "gpu")]
use benchmark::utilities::configure_gpu;
use benchmark::utilities::{
    get_bench_type, will_this_bench_run, write_to_json, BenchmarkType, BitSizesSet, EnvConfig,
    OperatorType,
};
use criterion::{Criterion, Throughput};
use rand::prelude::*;
use rand::thread_rng;
use rayon::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;

#[cfg(feature = "gpu")]
use tfhe::core_crypto::gpu::get_number_of_gpus;
use tfhe::shortint::parameters::{
    CompressionParameters, NoiseSquashingCompressionParameters, NoiseSquashingParameters,
};
use tfhe::shortint::PBSParameters;
#[cfg(feature = "gpu")]
use tfhe::GpuIndex;
use tfhe::{
    ClientKey, CompressedCiphertextListBuilder, CompressedServerKey,
    CompressedSquashedNoiseCiphertextListBuilder, FheUint10, FheUint12, FheUint128, FheUint14,
    FheUint16, FheUint2, FheUint32, FheUint4, FheUint6, FheUint64, FheUint8, HlCompressible,
    HlExpandable, HlSquashedNoiseCompressible,
};

fn bench_sns_only_fhe_type<FheType>(
    c: &mut Criterion,
    params: (
        PBSParameters,
        NoiseSquashingParameters,
        NoiseSquashingCompressionParameters,
        CompressionParameters,
    ),
    type_name: &str,
    num_bits: usize,
) where
    FheType: FheEncrypt<u128, ClientKey> + Send + Sync + FheWait + SquashNoise,
    <FheType as SquashNoise>::Output: BenchWait,
{
    let (param, noise_param, _, _) = params;

    use tfhe::{set_server_key, ConfigBuilder};
    let config = ConfigBuilder::with_custom_parameters(param)
        .enable_noise_squashing(noise_param)
        .build();
    let client_key = ClientKey::generate(config);
    let compressed_sks = CompressedServerKey::new(&client_key);

    #[cfg(feature = "gpu")]
    set_server_key(compressed_sks.decompress_to_gpu());

    #[cfg(all(not(feature = "hpu"), not(feature = "gpu")))]
    {
        let decompressed_sks = compressed_sks.decompress();
        rayon::broadcast(|_| set_server_key(decompressed_sks.clone()));
        set_server_key(decompressed_sks);
    }

    let mut bench_group = c.benchmark_group(type_name);
    let bench_id_prefix = if cfg!(feature = "gpu") {
        "hlapi::cuda".to_string()
    } else {
        "hlapi".to_string()
    };
    let noise_param_name = noise_param.name();
    let bench_id_suffix = format!("noise_squash::{noise_param_name}::{type_name}");

    let mut rng = thread_rng();

    let bench_id;

    match get_bench_type() {
        BenchmarkType::Latency => {
            bench_id = format!("{bench_id_prefix}::{bench_id_suffix}");

            #[cfg(feature = "gpu")]
            configure_gpu(&client_key);

            let input = FheType::encrypt(rng.gen(), &client_key);

            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    let _ = input.squash_noise();
                })
            });
        }
        BenchmarkType::Throughput => {
            bench_id = format!("{bench_id_prefix}::throughput::{bench_id_suffix}");

            let elements = if will_this_bench_run(type_name, &bench_id) {
                #[cfg(feature = "gpu")]
                {
                    use benchmark::utilities::throughput_num_threads;

                    let params = client_key.computation_parameters();
                    let num_blocks = num_bits.div_ceil(
                        (params.message_modulus().0 * params.carry_modulus().0).ilog2() as usize,
                    );

                    throughput_num_threads(num_blocks, 4)
                }
                #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                {
                    use benchmark::high_level_api::find_optimal_batch::find_optimal_batch;

                    let _ = num_bits; // Avoid clippy warning since FheType::num_bits() is not available.

                    let setup = |batch_size: usize| {
                        (0..batch_size)
                            .map(|_| FheType::encrypt(random(), &client_key))
                            .collect::<Vec<_>>()
                    };
                    let run = |inputs: &Vec<_>, batch_size: usize| {
                        inputs
                            .par_iter()
                            .take(batch_size)
                            .for_each(|input: &FheType| {
                                let _ = input.squash_noise();
                            });
                    };

                    find_optimal_batch(run, setup) as u64
                }
            } else {
                0
            };

            #[cfg(feature = "gpu")]
            {
                bench_group.throughput(Throughput::Elements(elements));
                println!("elements: {elements}");
                let gpu_count = get_number_of_gpus() as usize;
                let compressed_server_key = CompressedServerKey::new(&client_key);
                let sks_vec = (0..gpu_count)
                    .map(|i| {
                        compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i as u32))
                    })
                    .collect::<Vec<_>>();

                bench_group.bench_function(&bench_id, |b| {
                    let encrypt_values = || {
                        (0..elements)
                            .map(|_| FheType::encrypt(rng.gen(), &client_key))
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
                bench_group.throughput(Throughput::Elements(elements));
                println!("elements: {elements}");
                bench_group.bench_function(&bench_id, |b| {
                    let encrypt_values = || {
                        (0..elements)
                            .map(|_| FheType::encrypt(rng.gen(), &client_key))
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

fn bench_decomp_sns_comp_fhe_type<FheType>(
    c: &mut Criterion,
    params: (
        PBSParameters,
        NoiseSquashingParameters,
        NoiseSquashingCompressionParameters,
        CompressionParameters,
    ),
    type_name: &str,
    num_bits: usize,
) where
    FheType: FheEncrypt<u128, ClientKey> + Send + Sync + FheWait,
    FheType: SquashNoise + Tagged + HlExpandable + HlCompressible,
    <FheType as SquashNoise>::Output: HlSquashedNoiseCompressible + BenchWait,
{
    let (param, noise_param, comp_noise_param, comp_param) = params;

    use tfhe::{set_server_key, ConfigBuilder};
    let config = ConfigBuilder::with_custom_parameters(param)
        .enable_noise_squashing(noise_param)
        .enable_noise_squashing_compression(comp_noise_param)
        .enable_compression(comp_param)
        .build();
    let client_key = ClientKey::generate(config);
    let compressed_sks = CompressedServerKey::new(&client_key);

    #[cfg(feature = "gpu")]
    set_server_key(compressed_sks.decompress_to_gpu());

    #[cfg(all(not(feature = "hpu"), not(feature = "gpu")))]
    {
        let decompressed_sks = compressed_sks.decompress();
        rayon::broadcast(|_| set_server_key(decompressed_sks.clone()));
        set_server_key(decompressed_sks);
    }

    let mut bench_group = c.benchmark_group(type_name);
    let bench_id_prefix = if cfg!(feature = "gpu") {
        "hlapi::cuda".to_string()
    } else {
        "hlapi".to_string()
    };
    let noise_param_name = noise_param.name();
    let bench_id_suffix = format!("decomp_noise_squash_comp::{noise_param_name}::{type_name}");

    let mut rng = thread_rng();

    let bench_id;

    match get_bench_type() {
        BenchmarkType::Latency => {
            bench_id = format!("{bench_id_prefix}::{bench_id_suffix}");

            #[cfg(feature = "gpu")]
            configure_gpu(&client_key);

            let input = FheType::encrypt(rng.gen(), &client_key);

            let mut builder = CompressedCiphertextListBuilder::new();
            builder.push(input);
            let compressed = builder.build().unwrap();

            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    let decompressed = compressed.get::<FheType>(0).unwrap().unwrap();
                    let squashed = decompressed.squash_noise().unwrap();
                    let mut builder = CompressedSquashedNoiseCiphertextListBuilder::new();
                    builder.push(squashed);
                    let _ = builder.build();
                })
            });
        }
        BenchmarkType::Throughput => {
            bench_id = format!("{bench_id_prefix}::throughput::{bench_id_suffix}");

            let elements = if will_this_bench_run(type_name, &bench_id) {
                #[cfg(feature = "gpu")]
                {
                    use benchmark::utilities::throughput_num_threads;

                    let params = client_key.computation_parameters();
                    let num_blocks = num_bits.div_ceil(
                        (params.message_modulus().0 * params.carry_modulus().0).ilog2() as usize,
                    );

                    throughput_num_threads(num_blocks, 4)
                }
                #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                {
                    use benchmark::high_level_api::find_optimal_batch::find_optimal_batch;

                    let _ = num_bits; // Avoid clippy warning since FheType::num_bits() is not available.

                    // Noise squashing is the current bottleneck.
                    // Measuring CPU load with decompression and compression operations alongside
                    // the noise squash would just increase the batch size. Then benchmark execution
                    // duration would increase dramatically (from ~1.000 seconds to ~6.000 seconds).
                    let setup = |batch_size: usize| {
                        (0..batch_size)
                            .map(|_| FheType::encrypt(random(), &client_key))
                            .collect::<Vec<_>>()
                    };
                    let run = |inputs: &Vec<_>, batch_size: usize| {
                        inputs
                            .par_iter()
                            .take(batch_size)
                            .for_each(|input: &FheType| {
                                let _ = input.squash_noise();
                            });
                    };

                    find_optimal_batch(run, setup) as u64
                }
            } else {
                0
            };

            #[cfg(feature = "gpu")]
            {
                bench_group.throughput(Throughput::Elements(elements));
                println!("elements: {elements}");
                let gpu_count = get_number_of_gpus() as usize;
                let compressed_server_key = CompressedServerKey::new(&client_key);
                let sks_vec = (0..gpu_count)
                    .map(|i| {
                        compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i as u32))
                    })
                    .collect::<Vec<_>>();

                bench_group.bench_function(&bench_id, |b| {
                    let compressed_values = || {
                        (0..elements)
                            .map(|_| {
                                let input = FheType::encrypt(rng.gen(), &client_key);
                                let mut builder = CompressedCiphertextListBuilder::new();
                                builder.push(input);
                                builder.build().unwrap()
                            })
                            .collect::<Vec<_>>()
                    };

                    b.iter_batched(
                        compressed_values,
                        |compressed_inputs| {
                            compressed_inputs
                                .par_iter()
                                .enumerate()
                                .for_each(|(i, input)| {
                                    set_server_key(sks_vec[i % gpu_count].clone());

                                    let decompressed = input.get::<FheType>(0).unwrap().unwrap();
                                    let squashed = decompressed.squash_noise().unwrap();
                                    let mut builder =
                                        CompressedSquashedNoiseCiphertextListBuilder::new();
                                    builder.push(squashed);
                                    let _ = builder.build();
                                })
                        },
                        criterion::BatchSize::SmallInput,
                    )
                });
            }

            #[cfg(all(not(feature = "hpu"), not(feature = "gpu")))]
            {
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let compressed_values = || {
                        (0..elements)
                            .map(|_| {
                                let input = FheType::encrypt(rng.gen(), &client_key);
                                let mut builder = CompressedCiphertextListBuilder::new();
                                builder.push(input);
                                builder.build().unwrap()
                            })
                            .collect::<Vec<_>>()
                    };

                    b.iter_batched(
                        compressed_values,
                        |compressed_inputs| {
                            compressed_inputs.par_iter().for_each(|input| {
                                let decompressed = input.get::<FheType>(0).unwrap().unwrap();
                                let squashed = decompressed.squash_noise().unwrap();
                                let mut builder =
                                    CompressedSquashedNoiseCiphertextListBuilder::new();
                                builder.push(squashed);
                                let _ = builder.build();
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
        "decomp_noise_squash_comp",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

macro_rules! bench_sns_only_type {
    ($fhe_type:ident) => {
        ::paste::paste! {
            fn [<bench_sns_only_ $fhe_type:snake>](c: &mut Criterion, params: &[(PBSParameters, NoiseSquashingParameters, NoiseSquashingCompressionParameters, CompressionParameters)]) {
                for param in params {
                    bench_sns_only_fhe_type::<$fhe_type>(c, *param, stringify!($fhe_type), $fhe_type::num_bits());
                }
            }
        }
    };
}

macro_rules! bench_decomp_sns_comp_type {
    ($fhe_type:ident) => {
        ::paste::paste! {
            fn [<bench_decomp_sns_comp_ $fhe_type:snake>](c: &mut Criterion, params: &[(PBSParameters, NoiseSquashingParameters, NoiseSquashingCompressionParameters, CompressionParameters)]) {
                for param in params {
                bench_decomp_sns_comp_fhe_type::<$fhe_type>(c, *param, stringify!($fhe_type), $fhe_type::num_bits());
    }
            }
        }
    };
}

bench_sns_only_type!(FheUint2);
bench_sns_only_type!(FheUint4);
bench_sns_only_type!(FheUint6);
bench_sns_only_type!(FheUint8);
bench_sns_only_type!(FheUint10);
bench_sns_only_type!(FheUint12);
bench_sns_only_type!(FheUint14);
bench_sns_only_type!(FheUint16);
bench_sns_only_type!(FheUint32);
bench_sns_only_type!(FheUint64);
bench_sns_only_type!(FheUint128);

bench_decomp_sns_comp_type!(FheUint64);

fn main() {
    let env_config = EnvConfig::new();

    #[cfg(feature = "hpu")]
    panic!("Noise squashing is not supported on HPU");

    let params: Vec<(
        PBSParameters,
        NoiseSquashingParameters,
        NoiseSquashingCompressionParameters,
        CompressionParameters,
    )> = {
        #[cfg(all(not(feature = "hpu"), not(feature = "gpu")))]
        {
            vec![(
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                BENCH_COMP_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )]
        }

        #[cfg(feature = "gpu")]
        {
            vec![(
                     BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                     BENCH_NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                     BENCH_COMP_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                     BENCH_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                 ), (
                     BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                     BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                     BENCH_COMP_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                     BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                 ),
            ]
        }
    };

    let mut c = Criterion::default().configure_from_args();

    match env_config.bit_sizes_set {
        BitSizesSet::Fast => {
            bench_sns_only_fhe_uint64(&mut c, params.as_slice());
        }
        _ => {
            bench_sns_only_fhe_uint2(&mut c, params.as_slice());
            bench_sns_only_fhe_uint4(&mut c, params.as_slice());
            bench_sns_only_fhe_uint6(&mut c, params.as_slice());
            bench_sns_only_fhe_uint8(&mut c, params.as_slice());
            bench_sns_only_fhe_uint10(&mut c, params.as_slice());
            bench_sns_only_fhe_uint12(&mut c, params.as_slice());
            bench_sns_only_fhe_uint14(&mut c, params.as_slice());
            bench_sns_only_fhe_uint16(&mut c, params.as_slice());
            bench_sns_only_fhe_uint32(&mut c, params.as_slice());
            bench_sns_only_fhe_uint64(&mut c, params.as_slice());
            bench_sns_only_fhe_uint128(&mut c, params.as_slice());
        }
    }

    bench_decomp_sns_comp_fhe_uint64(&mut c, params.as_slice());

    c.final_summary();
}
