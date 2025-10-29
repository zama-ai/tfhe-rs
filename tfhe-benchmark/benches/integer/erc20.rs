use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use benchmark::utilities::{
    cuda_local_keys, cuda_local_streams, gen_random_u256, get_bench_type, BenchmarkType,
};
use criterion::{Criterion, Throughput};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
#[cfg(feature = "gpu")]
use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
#[cfg(feature = "gpu")]
use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
#[cfg(feature = "gpu")]
use tfhe::integer::gpu::CudaServerKey;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::IntegerKeyKind;
use tfhe::keycache::NamedParam;

fn main() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    #[cfg(feature = "gpu")]
    cuda_erc20(&mut criterion);

    Criterion::default().configure_from_args().final_summary();
}

#[cfg(feature = "gpu")]
pub fn cuda_erc20(c: &mut Criterion) {
    let bench_name = "integer::cuda::erc20";

    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));
    let mut rng = rand::thread_rng();
    let bench_id;

    let param = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let param_name = param.name();
    let num_block = 32;

    match get_bench_type() {
        BenchmarkType::Latency => {
            let streams = CudaStreams::new_multi_gpu();
            bench_id = format!("{bench_name}::{param_name}");

            bench_group.bench_function(&bench_id, |b| {
                let (cks, _cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                let gpu_sks = CudaServerKey::new(&cks, &streams);

                let encrypt_values = || {
                    let ct_0 = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                    let ct_1 = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                    let ct_2 = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                    let d_ctxt_0 =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_0, &streams);
                    let d_ctxt_1 =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_1, &streams);
                    let d_ctxt_2 =
                        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_2, &streams);

                    (d_ctxt_0, d_ctxt_1, d_ctxt_2)
                };

                b.iter_batched(
                    encrypt_values,
                    |(ct_0, ct_1, ct_2)| {
                        gpu_sks.erc20(&ct_0, &ct_1, &ct_2, &streams);
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }
        BenchmarkType::Throughput => {
            let (cks, _cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
            let gpu_sks_vec = cuda_local_keys(&cks);
            let gpu_count = get_number_of_gpus() as usize;

            bench_id = format!("{bench_name}::throughput::{param_name}");
            let elements = 800;
            bench_group.throughput(Throughput::Elements(elements));
            bench_group.bench_function(&bench_id, |b| {
                let setup_encrypted_values = || {
                    let local_streams = cuda_local_streams(num_block, elements as usize);
                    let cts_0 = (0..elements)
                        .map(|i| {
                            let ct_0 = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                &ct_0,
                                &local_streams[i as usize],
                            )
                        })
                        .collect::<Vec<_>>();
                    let cts_1 = (0..elements)
                        .map(|i| {
                            let ct_1 = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                &ct_1,
                                &local_streams[i as usize],
                            )
                        })
                        .collect::<Vec<_>>();
                    let cts_2 = (0..elements)
                        .map(|i| {
                            let ct_2 = cks.encrypt_radix(gen_random_u256(&mut rng), num_block);
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                &ct_2,
                                &local_streams[i as usize],
                            )
                        })
                        .collect::<Vec<_>>();

                    (cts_0, cts_1, cts_2, local_streams)
                };

                let pool = ThreadPoolBuilder::new().num_threads(32).build().unwrap();

                b.iter_batched(
                    setup_encrypted_values,
                    |(cts_0, cts_1, cts_2, local_streams)| {
                        pool.install(|| {
                            cts_0
                                .par_iter()
                                .zip(cts_1.par_iter())
                                .zip(cts_2.par_iter())
                                .zip(local_streams.par_iter())
                                .enumerate()
                                .for_each(|(i, (((ct_0, ct_1), ct_2), local_stream))| {
                                    gpu_sks_vec[i % gpu_count].erc20(
                                        ct_0,
                                        ct_1,
                                        ct_2,
                                        local_stream,
                                    );
                                });
                        })
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    };

    bench_group.finish();
}
