#[cfg(not(any(feature = "gpu", feature = "hpu")))]
use benchmark::find_optimal_batch::find_optimal_batch;
use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use benchmark::utilities::{write_to_json, OperatorType};
use benchmark_spec::{get_bench_type, BenchmarkSpec, BenchmarkType, HlapiBench, OperandType};
use criterion::{black_box, criterion_group, Criterion, Throughput};
use rand::Rng;
use rayon::prelude::*;
use tfhe::integer::server_key::BitonicShuffleKeySize;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::{bitonic_shuffle, set_server_key, ClientKey, ConfigBuilder, FheUint64, Seed, ServerKey};

fn bitonic_shuffle_bench(c: &mut Criterion, group_name: &str, cks: &ClientKey) {
    let mut bench_group = c.benchmark_group(group_name);
    bench_group.sample_size(10);

    let params = cks.computation_parameters();
    let params_name = params.name();
    let bench_type = get_bench_type();
    let mut rng = rand::thread_rng();

    for num_elements in [64, 128, 256] {
        let clear_values: Vec<u64> = (0..num_elements).map(|_| rng.gen()).collect();
        let encrypted: Vec<FheUint64> = clear_values
            .iter()
            .map(|&v| FheUint64::encrypt(v, cks))
            .collect();

        let spec = BenchmarkSpec::new_hlapi(
            HlapiBench::BitonicShuffle,
            &params_name,
            OperandType::CipherText,
            Some("FheUint64"),
            *bench_type,
            Some(num_elements),
        );
        let bench_id = spec.to_string();

        let seed = Seed(0);

        match bench_type {
            BenchmarkType::Latency => {
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        let result = bitonic_shuffle(
                            encrypted.clone(),
                            BitonicShuffleKeySize::collision_probability(2f64.powi(-40)),
                            seed,
                        )
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
                                let _ = bitonic_shuffle(
                                    encrypted.clone(),
                                    BitonicShuffleKeySize::collision_probability(2f64.powi(-40)),
                                    seed,
                                );
                            },
                            cks,
                        )
                        .max(1);

                        let inputs: Vec<Vec<FheUint64>> =
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
                        let run = |inputs: &mut Vec<Vec<FheUint64>>, batch_size: usize| {
                            inputs.par_iter().take(batch_size).for_each(|input| {
                                let _ = bitonic_shuffle(
                                    input.clone(),
                                    BitonicShuffleKeySize::collision_probability(2f64.powi(-40)),
                                    seed,
                                )
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
                            let result = bitonic_shuffle(
                                input.clone(),
                                BitonicShuffleKeySize::collision_probability(2f64.powi(-40)),
                                seed,
                            )
                            .expect("shuffle failed");
                            black_box(result);
                        });
                    });
                });
            }
        }

        write_to_json::<u64, _, _>(
            &spec,
            params,
            "bitonic-shuffle",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }

    bench_group.finish();
}

pub fn bitonic_shuffle_cpu(c: &mut Criterion) {
    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let config = ConfigBuilder::with_custom_parameters(param).build();
    let cks = ClientKey::generate(config);
    let sks = ServerKey::new(&cks);

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    bitonic_shuffle_bench(c, "hlapi::bitonic_shuffle_cpu", &cks);
}

criterion_group!(bitonic_shuffle_group, bitonic_shuffle_cpu);
criterion::criterion_main!(bitonic_shuffle_group);
