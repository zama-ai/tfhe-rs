#[cfg(not(any(feature = "gpu", feature = "hpu")))]
use benchmark::find_optimal_batch::find_optimal_batch;
use benchmark::high_level_api::type_display::{TypeDisplay, TypeDisplayer};
#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::utilities::{get_param_type, ParamType};
use benchmark::utilities::{write_to_json, OperatorType};
use benchmark_spec::tfhe::hlapi::bitonic_shuffle::BitonicShuffleSpec;
use benchmark_spec::{get_bench_type, BenchmarkSpec, BenchmarkType, HlapiBench, OperandType};
use criterion::measurement::WallTime;
use criterion::{criterion_group, BenchmarkGroup, Criterion, Throughput};
use rand::Rng;
use rayon::prelude::*;
use std::hint::black_box;
use std::num::NonZeroU32;
use tfhe::integer::server_key::BitonicShuffleKeySize;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::{
    bitonic_shuffle, set_server_key, ClientKey, ConfigBuilder, FheIntegerType, FheUint160,
    FheUint64, IntegerId, Seed, ServerKey,
};

fn convert_key_size_to_spec(val: BitonicShuffleKeySize, num_elements: u32) -> BitonicShuffleSpec {
    let num_elements = NonZeroU32::new(num_elements).unwrap();
    match val {
        BitonicShuffleKeySize::CollisionProbability(_collision_probability) => todo!(),
        BitonicShuffleKeySize::AttackerAdvantage(attacker_advantage) => {
            BitonicShuffleSpec::AttackerAdvantage {
                advantage: attacker_advantage.advantage(),
                num_revealed: attacker_advantage.num_revealed().unwrap_or(num_elements),
            }
        }
        BitonicShuffleKeySize::NumBits(_) => todo!(),
    }
}

fn bench_shuffle_for_type<FheType>(
    bench_group: &mut BenchmarkGroup<'_, WallTime>,
    cks: &ClientKey,
    scenarios: impl Iterator<Item = (u32, BitonicShuffleKeySize)>,
) where
    FheType: FheIntegerType + FheEncrypt<u64, ClientKey> + Clone + Send + Sync + TypeDisplay,
{
    let params = cks.computation_parameters();
    let params_name = params.name();
    let bench_type = get_bench_type();
    let mut rng = rand::thread_rng();
    let bit_size = FheType::Id::num_bits() as u32;

    for (num_elements, key_size) in scenarios {
        let encrypted: Vec<FheType> = (0..num_elements)
            .map(|_| FheType::encrypt(rng.gen(), cks))
            .collect();

        let spec = BenchmarkSpec::new_hlapi(
            HlapiBench::BitonicShuffle(convert_key_size_to_spec(key_size, num_elements)),
            &params_name,
            OperandType::CipherText,
            Some(&TypeDisplayer::<FheType>::default()),
            bench_type,
            Some(num_elements as usize),
        );
        let bench_id = spec.to_string();

        let seed = Seed(0);

        match bench_type {
            BenchmarkType::Latency => {
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        let result = bitonic_shuffle(encrypted.clone(), key_size, seed)
                            .expect("shuffle failed");
                        black_box(result);
                    })
                });
            }
            BenchmarkType::Throughput => {
                let (elements, inputs) = {
                    #[cfg(any(feature = "gpu", feature = "hpu"))]
                    {
                        use benchmark::utilities::hlapi_throughput_num_ops;
                        let factor = hlapi_throughput_num_ops(
                            || {
                                let _ = bitonic_shuffle(encrypted.clone(), key_size, seed);
                            },
                            cks,
                        )
                        .max(1);

                        let inputs: Vec<Vec<FheType>> =
                            (0..factor).map(|_| encrypted.clone()).collect();
                        (inputs.len() as u64, inputs)
                    }
                    #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                    {
                        let setup = |batch_size: usize| {
                            (0..batch_size)
                                .map(|_| encrypted.clone())
                                .collect::<Vec<_>>()
                        };
                        let run = |inputs: &mut Vec<Vec<FheType>>, batch_size: usize| {
                            inputs.par_iter().take(batch_size).for_each(|input| {
                                let _ = bitonic_shuffle(input.clone(), key_size, seed)
                                    .expect("shuffle failed");
                            });
                        };
                        let elements = find_optimal_batch(run, setup);
                        let inputs = setup(elements);
                        (elements as u64, inputs)
                    }
                };

                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        inputs.par_iter().for_each(|input| {
                            let result = bitonic_shuffle(input.clone(), key_size, seed)
                                .expect("shuffle failed");
                            black_box(result);
                        });
                    });
                });
            }
        }

        write_to_json(
            &spec,
            "bitonic-shuffle",
            &OperatorType::Atomic,
            bit_size,
            vec![],
        );
    }
}

fn bench_collision_probability<FheType>(c: &mut Criterion, cks: &ClientKey)
where
    FheType: FheIntegerType + FheEncrypt<u64, ClientKey> + Clone + Send + Sync + TypeDisplay,
{
    const COLLISION_PROBABILITY: f64 = 1e-8;
    let p = BitonicShuffleKeySize::collision_probability(COLLISION_PROBABILITY);
    let mut grp = c.benchmark_group("collision_probability");
    bench_shuffle_for_type::<FheType>(
        &mut grp,
        cks,
        [8, 15, 16, 32, 52, 64]
            .into_iter()
            .zip(std::iter::repeat(p)),
    );
}

fn bench_worst_case_advantage<FheType>(c: &mut Criterion, cks: &ClientKey)
where
    FheType: FheIntegerType + FheEncrypt<u64, ClientKey> + Clone + Send + Sync + TypeDisplay,
{
    let p = BitonicShuffleKeySize::attacker_advantage(0.1, None);
    let mut grp = c.benchmark_group("worst_case_advantage");
    bench_shuffle_for_type::<FheType>(
        &mut grp,
        cks,
        [8, 15, 16, 32, 52, 64]
            .into_iter()
            .zip(std::iter::repeat(p)),
    );

    let p = BitonicShuffleKeySize::attacker_advantage(1.0 / 1_000_000.0, None);
    bench_shuffle_for_type::<FheType>(
        &mut grp,
        cks,
        [8, 15, 16, 32, 52, 64]
            .into_iter()
            .zip(std::iter::repeat(p)),
    );

    grp.finish();
}

fn bench_advantage<FheType>(c: &mut Criterion, cks: &ClientKey)
where
    FheType: FheIntegerType + FheEncrypt<u64, ClientKey> + Clone + Send + Sync + TypeDisplay,
{
    let mut grp = c.benchmark_group("worst_case_advantage");
    bench_shuffle_for_type::<FheType>(
        &mut grp,
        cks,
        [8, 15, 16, 32, 52, 64].into_iter().map(|n| {
            let p = BitonicShuffleKeySize::attacker_advantage(0.1, Some(n / 4));
            (n, p)
        }),
    );

    bench_shuffle_for_type::<FheType>(
        &mut grp,
        cks,
        [8, 15, 16, 32, 52, 64].into_iter().map(|n| {
            let p = BitonicShuffleKeySize::attacker_advantage(1.0 / 1_000_000.0, Some(n / 4));
            (n, p)
        }),
    );

    grp.finish();
}

// ============================================================================
// Unchecked bitonic_shuffle_with_keys: measured at the integer level because
// the HL API only exposes the full `bitonic_shuffle` (key generation + shuffle).
// ============================================================================

const DATA_BITS: u32 = 64;
const SHUFFLE_KEY_NUM_BITS: u32 = 32;

fn power_of_two_scenarios() -> Vec<usize> {
    vec![16, 32]
}

fn bench_unchecked_with_keys_cpu_inner(
    c: &mut Criterion,
    bench_name: &str,
    cpu_cks: &tfhe::integer::ClientKey,
) {
    let bits_per_block = cpu_cks.parameters().message_modulus().0.ilog2() as usize;
    let data_num_blocks = (DATA_BITS as usize).div_ceil(bits_per_block);
    let key_num_blocks = (SHUFFLE_KEY_NUM_BITS as usize).div_ceil(bits_per_block);

    let data_cks = tfhe::integer::RadixClientKey::from((cpu_cks.clone(), data_num_blocks));
    let key_cks = tfhe::integer::RadixClientKey::from((cpu_cks.clone(), key_num_blocks));
    let sks = tfhe::integer::ServerKey::new_radix_server_key(&data_cks);

    let mut group = c.benchmark_group(bench_name);
    group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(60));

    let mut rng = rand::thread_rng();
    for &num_elements in power_of_two_scenarios().iter() {
        let bench_id = format!("{DATA_BITS}_bits::{num_elements}_elements");
        group.bench_function(&bench_id, |b| {
            b.iter_batched(
                || {
                    let data: Vec<_> = (0..num_elements)
                        .map(|_| data_cks.encrypt(rng.gen::<u64>()))
                        .collect();
                    let keys: Vec<_> = (0..num_elements)
                        .map(|_| key_cks.encrypt(rng.gen::<u64>()))
                        .collect();
                    (data, keys)
                },
                |(data, keys)| {
                    let res = sks.unchecked_bitonic_shuffle_with_keys(data, keys);
                    black_box(res);
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

#[cfg(feature = "gpu")]
fn bench_unchecked_with_keys_gpu_inner(
    c: &mut Criterion,
    bench_name: &str,
    cpu_cks: &tfhe::integer::ClientKey,
) {
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;

    let bits_per_block = cpu_cks.parameters().message_modulus().0.ilog2() as usize;
    let data_num_blocks = (DATA_BITS as usize).div_ceil(bits_per_block);
    let key_num_blocks = (SHUFFLE_KEY_NUM_BITS as usize).div_ceil(bits_per_block);

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(cpu_cks, &streams);

    let data_cks = tfhe::integer::RadixClientKey::from((cpu_cks.clone(), data_num_blocks));
    let key_cks = tfhe::integer::RadixClientKey::from((cpu_cks.clone(), key_num_blocks));

    let mut group = c.benchmark_group(bench_name);
    group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(60));

    let mut rng = rand::thread_rng();
    for &num_elements in power_of_two_scenarios().iter() {
        let bench_id = format!("{DATA_BITS}_bits::{num_elements}_elements");
        group.bench_function(&bench_id, |b| {
            b.iter_batched(
                || {
                    let data: Vec<_> = (0..num_elements)
                        .map(|_| {
                            let ct = data_cks.encrypt(rng.gen::<u64>());
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams)
                        })
                        .collect();
                    let keys: Vec<_> = (0..num_elements)
                        .map(|_| {
                            let ct = key_cks.encrypt(rng.gen::<u64>());
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams)
                        })
                        .collect();
                    (data, keys)
                },
                |(data, keys)| {
                    let res = sks.unchecked_bitonic_shuffle_with_keys(data, keys, &streams);
                    black_box(res);
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

// ============================================================================
// CPU entry point
// ============================================================================

pub fn bitonic_shuffle_cpu(c: &mut Criterion) {
    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let config = ConfigBuilder::with_custom_parameters(param).build();
    let cks = ClientKey::generate(config);
    let sks = ServerKey::new(&cks);

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    bench_collision_probability::<FheUint64>(c, &cks);
    bench_worst_case_advantage::<FheUint64>(c, &cks);
    bench_advantage::<FheUint64>(c, &cks);
    bench_advantage::<FheUint160>(c, &cks);

    let cpu_cks = tfhe::integer::ClientKey::new(param);
    bench_unchecked_with_keys_cpu_inner(
        c,
        "hlapi::unchecked_bitonic_shuffle_with_keys_cpu",
        &cpu_cks,
    );
}

// ============================================================================
// GPU entry point
// ============================================================================

#[cfg(feature = "gpu")]
pub fn bitonic_shuffle_gpu(c: &mut Criterion) {
    let param: tfhe::shortint::AtomicPatternParameters = match get_param_type() {
        ParamType::Classical => BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
        _ => BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
    };
    let config = ConfigBuilder::with_custom_parameters(param).build();
    let cks = ClientKey::generate(config);
    let sks = tfhe::CompressedServerKey::new(&cks).decompress_to_gpu();
    set_server_key(sks);

    bench_key_size_sweep(c, &cks, "hlapi::bitonic_shuffle_gpu::key_size_sweep");
    bench_collision_probability(c, &cks, "hlapi::bitonic_shuffle_gpu::collision_probability");

    let cpu_cks = tfhe::integer::ClientKey::new(param);
    bench_unchecked_with_keys_gpu_inner(
        c,
        "hlapi::unchecked_bitonic_shuffle_with_keys_gpu",
        &cpu_cks,
    );
}

#[cfg(not(feature = "gpu"))]
criterion_group!(bitonic_shuffle_group, bitonic_shuffle_cpu);

#[cfg(feature = "gpu")]
criterion_group!(
    bitonic_shuffle_group,
    bitonic_shuffle_cpu,
    bitonic_shuffle_gpu
);

criterion::criterion_main!(bitonic_shuffle_group);
