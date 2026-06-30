#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::utilities::{get_param_type, ParamType};
use benchmark_spec::{get_bench_type, BenchmarkType};
use criterion::{black_box, criterion_group, Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use tfhe::integer::server_key::BitonicShuffleKeySize;
use tfhe::prelude::*;
use tfhe::{
    bitonic_shuffle, set_server_key, ClientKey, ConfigBuilder, FheIntegerType, FheUint160,
    FheUint64, Seed, ServerKey,
};

const DATA_BITS: u32 = 64;
const SHUFFLE_KEY_NUM_BITS: u32 = 32;
const COLLISION_PROBABILITY: f64 = 1e-8;
const KEY_BITS_SWEEP: [u32; 5] = [8, 16, 32, 64, 128];

fn power_of_two_scenarios() -> Vec<usize> {
    vec![16, 32]
}

fn non_pow2_scenarios() -> Vec<usize> {
    vec![15, 17, 31, 33]
}

fn encrypt_data(cks: &ClientKey, num_elements: usize, rng: &mut ThreadRng) -> Vec<FheUint64> {
    (0..num_elements)
        .map(|_| {
            let v: u64 = rng.gen();
            FheUint64::encrypt(v, cks)
        })
        .collect()
}

fn bench_bitonic_shuffle_inner<F>(
    c: &mut Criterion,
    cks: &ClientKey,
    bench_name: &str,
    scenarios: &[usize],
    bench_id_suffix: F,
    key_size: BitonicShuffleKeySize,
) where
    F: Fn(usize) -> String,
{
    let mut group = c.benchmark_group(bench_name);
    group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(60));

    let mut rng = rand::thread_rng();

    for &num_elements in scenarios {
        let bench_id = bench_id_suffix(num_elements);

        group.bench_function(&bench_id, |b| {
            b.iter_batched(
                || (encrypt_data(cks, num_elements, &mut rng), Seed(rng.gen())),
                |(data, seed)| {
                    let res =
                        bitonic_shuffle(data, key_size, seed).expect("bitonic_shuffle failed");
                    black_box(res);
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn bench_default(c: &mut Criterion, cks: &ClientKey, bench_name: &str) {
    bench_bitonic_shuffle_inner(
        c,
        cks,
        bench_name,
        &power_of_two_scenarios(),
        |n| format!("{DATA_BITS}_bits::{n}_elements"),
        BitonicShuffleKeySize::num_bits(SHUFFLE_KEY_NUM_BITS),
    );
}

fn bench_non_pow2(c: &mut Criterion, cks: &ClientKey, bench_name: &str) {
    bench_bitonic_shuffle_inner(
        c,
        cks,
        bench_name,
        &non_pow2_scenarios(),
        |n| format!("{DATA_BITS}_bits::{n}_elements"),
        BitonicShuffleKeySize::num_bits(SHUFFLE_KEY_NUM_BITS),
    );
}

fn bench_key_size_sweep(c: &mut Criterion, cks: &ClientKey, bench_name: &str) {
    for key_bits in KEY_BITS_SWEEP {
        bench_bitonic_shuffle_inner(
            c,
            cks,
            bench_name,
            &[16usize],
            move |n| format!("{DATA_BITS}_bits::{n}_elements::key_{key_bits}_bits"),
            BitonicShuffleKeySize::num_bits(key_bits),
        );
    }
}

fn bench_collision_probability(c: &mut Criterion, cks: &ClientKey, bench_name: &str) {
    bench_bitonic_shuffle_inner(
        c,
        cks,
        bench_name,
        &power_of_two_scenarios(),
        |n| format!("{DATA_BITS}_bits::{n}_elements::p_{COLLISION_PROBABILITY:e}"),
        BitonicShuffleKeySize::collision_probability(COLLISION_PROBABILITY),
    );
}

// ============================================================================
// Shuffle configs surfaced in the CI summary, all at 16 elements:
//   - 64b values  / 16b keys
//   - 64b values  / 32b keys
//   - 160b values / 16b keys
// ============================================================================

fn bench_shuffle_config<T>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    cks: &ClientKey,
    value_bits: u32,
    key_bits: u32,
    num_elements: usize,
) where
    T: FheIntegerType + FheEncrypt<u128, ClientKey> + Clone + Send + Sync,
{
    let mut rng = rand::thread_rng();
    let key_size = BitonicShuffleKeySize::num_bits(key_bits);
    let bench_id = format!("{value_bits}_bits::{num_elements}_elements::key_{key_bits}_bits");

    let encrypt_dataset = |rng: &mut ThreadRng| -> Vec<T> {
        (0..num_elements)
            .map(|_| T::encrypt(rng.gen::<u128>(), cks))
            .collect()
    };

    match get_bench_type() {
        BenchmarkType::Latency => {
            group.bench_function(&bench_id, |b| {
                b.iter_batched(
                    || (encrypt_dataset(&mut rng), Seed(rng.gen())),
                    |(data, seed)| {
                        let res =
                            bitonic_shuffle(data, key_size, seed).expect("bitonic_shuffle failed");
                        black_box(res);
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }
        BenchmarkType::Throughput => {
            let num_ops = {
                #[cfg(any(feature = "gpu", feature = "hpu"))]
                {
                    use benchmark::utilities::throughput_num_threads;
                    let msg_bits = (cks.computation_parameters().message_modulus().0 as f64).log2();
                    let num_block =
                        (num_elements as f64 * value_bits as f64 / msg_bits).ceil() as usize;
                    throughput_num_threads(num_block, 1).max(1) as usize
                }
                #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                {
                    use benchmark::find_optimal_batch::find_optimal_batch;
                    let setup = |batch_size: usize| -> Vec<(Vec<T>, Seed)> {
                        (0..batch_size)
                            .map(|_| (encrypt_dataset(&mut rng), Seed(rng.gen())))
                            .collect()
                    };
                    let run = |inputs: &mut Vec<(Vec<T>, Seed)>, batch_size: usize| {
                        inputs.par_iter().take(batch_size).for_each(|(data, seed)| {
                            let res = bitonic_shuffle(data.clone(), key_size, *seed)
                                .expect("bitonic_shuffle failed");
                            black_box(res);
                        });
                    };
                    find_optimal_batch(run, setup)
                }
            };

            let bench_id = format!("{bench_id}::throughput");
            group.throughput(Throughput::Elements(num_ops as u64));
            group.bench_function(&bench_id, |b| {
                b.iter_batched(
                    || {
                        (0..num_ops)
                            .map(|_| (encrypt_dataset(&mut rng), Seed(rng.gen())))
                            .collect::<Vec<_>>()
                    },
                    |inputs| {
                        inputs.into_par_iter().for_each(|(data, seed)| {
                            let res = bitonic_shuffle(data, key_size, seed)
                                .expect("bitonic_shuffle failed");
                            black_box(res);
                        });
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }
    }
}

fn bench_shuffle_configs(c: &mut Criterion, cks: &ClientKey, bench_name: &str) {
    let mut group = c.benchmark_group(bench_name);
    group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(60));

    bench_shuffle_config::<FheUint64>(&mut group, cks, 64, 16, 16);
    bench_shuffle_config::<FheUint64>(&mut group, cks, 64, 32, 16);
    bench_shuffle_config::<FheUint160>(&mut group, cks, 160, 16, 16);

    group.finish();
}

// ============================================================================
// Unchecked bitonic_shuffle_with_keys: measured at the integer level because
// the HL API only exposes the full `bitonic_shuffle` (key generation + shuffle).
// ============================================================================

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

    bench_default(c, &cks, "hlapi::bitonic_shuffle_cpu");
    bench_non_pow2(c, &cks, "hlapi::bitonic_shuffle_cpu::non_pow2");
    bench_key_size_sweep(c, &cks, "hlapi::bitonic_shuffle_cpu::key_size_sweep");
    bench_collision_probability(c, &cks, "hlapi::bitonic_shuffle_cpu::collision_probability");
    bench_shuffle_configs(c, &cks, "hlapi::bitonic_shuffle_cpu::summary");

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

    bench_default(c, &cks, "hlapi::bitonic_shuffle_gpu");
    bench_non_pow2(c, &cks, "hlapi::bitonic_shuffle_gpu::non_pow2");
    bench_key_size_sweep(c, &cks, "hlapi::bitonic_shuffle_gpu::key_size_sweep");
    bench_collision_probability(c, &cks, "hlapi::bitonic_shuffle_gpu::collision_probability");
    bench_shuffle_configs(c, &cks, "hlapi::bitonic_shuffle_gpu::summary");

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
