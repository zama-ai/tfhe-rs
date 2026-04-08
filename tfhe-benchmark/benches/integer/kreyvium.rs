use criterion::Criterion;

#[cfg(feature = "gpu")]
pub mod cuda {
    use benchmark::params_aliases::{
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use benchmark::utilities::{write_to_json_unchecked, OperatorType};
    use criterion::{black_box, criterion_group, Criterion};
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::keycache::KEY_CACHE;
    use tfhe::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::{AtomicPatternParameters, Ciphertext};

    fn encrypt_bits(cks: &RadixClientKey, bits: &[u64]) -> RadixCiphertext {
        RadixCiphertext::from(
            bits.iter()
                .map(|&bit| cks.encrypt_one_block(bit))
                .collect::<Vec<Ciphertext>>(),
        )
    }

    pub fn cuda_kreyvium(c: &mut Criterion) {
        let bench_name = "integer::cuda::kreyvium";

        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60))
            .warm_up_time(std::time::Duration::from_secs(5));

        let params = [
            (
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
            ),
            (
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
            ),
        ];

        for (atomic_param_val, param_name) in params {
            let atomic_param: AtomicPatternParameters = atomic_param_val;

            let key_bits = vec![0u64; 128];
            let iv_bits = vec![0u64; 128];

            let streams = CudaStreams::new_multi_gpu();
            let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
            let sks = CudaServerKey::new(&cpu_cks, &streams);
            let cks = RadixClientKey::from((cpu_cks, 1));

            let ct_key = encrypt_bits(&cks, &key_bits);
            let ct_iv = encrypt_bits(&cks, &iv_bits);

            let d_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_key, &streams);
            let d_iv = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_iv, &streams);

            // 1. Benchmark: init
            let init_bench_id = format!("{bench_name}::{param_name}::init");
            bench_group.bench_function(&init_bench_id, |b| {
                b.iter(|| {
                    black_box(sks.kreyvium_init(&d_key, &d_iv, &streams).unwrap());
                })
            });

            write_to_json_unchecked::<u64, _>(
                &init_bench_id,
                atomic_param,
                param_name.clone(),
                "kreyvium_init",
                &OperatorType::Atomic,
                128,
                vec![atomic_param.message_modulus().0.ilog2(); 128],
            );

            let mut state = sks.kreyvium_init(&d_key, &d_iv, &streams).unwrap();

            for num_steps in [64, 512] {
                // 2. Benchmark: next
                let next_bench_id = format!("{bench_name}::{param_name}::next_{num_steps}_bits");

                bench_group.bench_function(&next_bench_id, |b| {
                    b.iter(|| {
                        black_box(sks.kreyvium_next(&mut state, num_steps, &streams).unwrap());
                    })
                });

                write_to_json_unchecked::<u64, _>(
                    &next_bench_id,
                    atomic_param,
                    param_name.clone(),
                    &format!("kreyvium_next_{}_bits", num_steps),
                    &OperatorType::Atomic,
                    128,
                    vec![atomic_param.message_modulus().0.ilog2(); 128],
                );

                // 3. Benchmark: generate_keystream
                let gen_bench_id = format!("{bench_name}::{param_name}::generate_{num_steps}_bits");

                bench_group.bench_function(&gen_bench_id, |b| {
                    b.iter(|| {
                        black_box(
                            sks.kreyvium_generate_keystream(&d_key, &d_iv, num_steps, &streams)
                                .unwrap(),
                        );
                    })
                });

                write_to_json_unchecked::<u64, _>(
                    &gen_bench_id,
                    atomic_param,
                    param_name.clone(),
                    &format!("kreyvium_generation_{}_bits", num_steps),
                    &OperatorType::Atomic,
                    128,
                    vec![atomic_param.message_modulus().0.ilog2(); 128],
                );
            }
        }

        bench_group.finish();
    }

    criterion_group!(gpu_kreyvium, cuda_kreyvium);
}

#[cfg(feature = "gpu")]
use cuda::gpu_kreyvium;

fn main() {
    #[cfg(feature = "gpu")]
    gpu_kreyvium();

    Criterion::default().configure_from_args().final_summary();
}
