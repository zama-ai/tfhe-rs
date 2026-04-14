#[cfg(feature = "gpu")]
pub mod cuda {
    use benchmark::params_aliases::{
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    };
    use benchmark::utilities::{write_to_json_unchecked, OperatorType};
    use criterion::Criterion;
    use rand::prelude::*;
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::keycache::KEY_CACHE;
    use tfhe::integer::{IntegerKeyKind, RadixClientKey};
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::AtomicPatternParameters;

    fn bitonic_sort_scenarios() -> Vec<(usize, usize)> {
        vec![(8, 32), (16, 32), (32, 32), (64, 32)]
    }

    fn bench_cuda_unchecked_bitonic_sort_for_params<P>(c: &mut Criterion, param: P)
    where
        P: Copy + NamedParam + Into<AtomicPatternParameters>,
    {
        let bench_name = "integer::cuda::unsigned::unchecked_bitonic_sort";
        let mut group = c.benchmark_group(bench_name);
        group
            .sample_size(10)
            .measurement_time(std::time::Duration::from_secs(60));

        let atomic_param: AtomicPatternParameters = param.into();
        let param_name = param.name();
        let bits_per_block = atomic_param.message_modulus().0.ilog2() as usize;

        let streams = CudaStreams::new_multi_gpu();
        let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
        let sks = CudaServerKey::new(&cpu_cks, &streams);

        let mut rng = rand::thread_rng();

        for (num_elements, bit_size) in bitonic_sort_scenarios() {
            let num_blocks = bit_size.div_ceil(bits_per_block);
            let cks = RadixClientKey::from((cpu_cks.clone(), num_blocks));

            let bench_id =
                format!("{bench_name}::{param_name}::{bit_size}_bits::{num_elements}_elements");

            group.bench_function(&bench_id, |b| {
                b.iter_batched(
                    || {
                        (0..num_elements)
                            .map(|_| {
                                let clear: u64 = rng.gen();
                                let ct = cks.encrypt(clear);
                                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams)
                            })
                            .collect::<Vec<_>>()
                    },
                    |mut values| {
                        sks.unchecked_bitonic_sort(&mut values, &streams);
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            write_to_json_unchecked::<u64, _>(
                &bench_id,
                atomic_param,
                param_name.as_str(),
                "unchecked_bitonic_sort",
                &OperatorType::Atomic,
                bit_size as u32,
                vec![bits_per_block as u32; num_blocks],
            );
        }
        group.finish();
    }

    pub fn cuda_unchecked_bitonic_sort(c: &mut Criterion) {
        bench_cuda_unchecked_bitonic_sort_for_params(
            c,
            BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        );
        bench_cuda_unchecked_bitonic_sort_for_params(c, BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    }
}
