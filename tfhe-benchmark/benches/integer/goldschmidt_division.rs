//! Benchmarks for Goldschmidt division against the production divider.
//!
//! Both are timed on the same encrypted operands inside one run, so the ratio
//! is apples to apples, and both parameter flavours are covered. The operation
//! only exists on the GPU backend.

#[cfg(feature = "gpu")]
pub mod cuda {
    use benchmark::params_aliases::{
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use benchmark::utilities::{write_to_json_unchecked, OperatorType};
    use criterion::Criterion;
    use rand::Rng;
    use std::hint::black_box;
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::keycache::KEY_CACHE;
    use tfhe::integer::IntegerKeyKind;
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::AtomicPatternParameters;

    /// 64 bits at 2 bits per block - the only shape the divider supports.
    const NUM_BLOCKS: usize = 32;
    const BIT_SIZE: u32 = 64;

    fn param_sets() -> Vec<(AtomicPatternParameters, String)> {
        vec![
            (
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
            ),
            (
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
            ),
        ]
    }

    pub fn cuda_goldschmidt_division(c: &mut Criterion) {
        let bench_name = "integer::cuda::goldschmidt_division";
        let mut group = c.benchmark_group(bench_name);
        // A single division is hundreds of milliseconds, so keep the sample
        // count modest.
        group.sample_size(10);
        let mut rng = rand::thread_rng();

        let streams = CudaStreams::new_multi_gpu();

        for (atomic_param, param_name) in param_sets() {
            let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
            let sks = CudaServerKey::new(&cpu_cks, &streams);

            // Full-width operands: the cost is data independent, but a random
            // pair keeps the numbers honest against any accidental shortcut.
            let n: u64 = rng.gen();
            let d: u64 = rng.gen_range(1..=u64::MAX);
            let ct_n = cpu_cks.encrypt_radix(n, NUM_BLOCKS);
            let ct_d = cpu_cks.encrypt_radix(d, NUM_BLOCKS);
            let d_n = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_n, &streams);
            let d_d = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_d, &streams);

            for (label, is_goldschmidt) in [("div_rem", false), ("goldschmidt", true)] {
                let bench_id = format!("{bench_name}::{param_name}::{label}_{BIT_SIZE}bits");

                group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        if is_goldschmidt {
                            black_box(sks.goldschmidt_division(&d_n, &d_d, &streams));
                        } else {
                            black_box(sks.div_rem(&d_n, &d_d, &streams));
                        }
                    })
                });

                write_to_json_unchecked(
                    &bench_id,
                    param_name.clone(),
                    label,
                    &OperatorType::Atomic,
                    BIT_SIZE,
                    vec![atomic_param.message_modulus().0.ilog2(); NUM_BLOCKS],
                );
            }
        }
        group.finish();
    }
}
