use criterion::Criterion;

#[cfg(feature = "gpu")]
pub mod cuda {
    use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use benchmark::utilities::{write_to_json, OperatorType};
    use criterion::{black_box, criterion_group, Criterion};
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::keycache::KEY_CACHE;
    use tfhe::integer::{IntegerKeyKind, RadixClientKey};
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::AtomicPatternParameters;

    pub fn cuda_trivium(c: &mut Criterion) {
        let bench_name = "integer::cuda::trivium";

        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60))
            .warm_up_time(std::time::Duration::from_secs(5));

        let param = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let atomic_param: AtomicPatternParameters = param.into();

        let key_bits = vec![0u64; 80];
        let iv_bits = vec![0u64; 80];

        let param_name = param.name();

        let streams = CudaStreams::new_multi_gpu();
        let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
        let sks = CudaServerKey::new(&cpu_cks, &streams);
        let cks = RadixClientKey::from((cpu_cks, 1));

        let ct_key = cks.encrypt_bits_from_u64_slice_to_radix_ciphertext(&key_bits);
        let ct_iv = cks.encrypt_bits_from_u64_slice_to_radix_ciphertext(&iv_bits);

        let d_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_key, &streams);
        let d_iv = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_iv, &streams);

        {
            let num_steps = 64;
            let bench_id = format!("{bench_name}::{param_name}::generate_{num_steps}_bits");

            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    black_box(sks.trivium_generate_keystream(&d_key, &d_iv, num_steps, &streams));
                })
            });

            write_to_json::<u64, _>(
                &bench_id,
                atomic_param,
                param.name(),
                "trivium_generation_64_bits",
                &OperatorType::Atomic,
                80,
                vec![atomic_param.message_modulus().0.ilog2(); 80],
            );
        }

        {
            let num_steps = 512;
            let bench_id = format!("{bench_name}::{param_name}::generate_{num_steps}_bits");

            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    black_box(sks.trivium_generate_keystream(&d_key, &d_iv, num_steps, &streams));
                })
            });

            write_to_json::<u64, _>(
                &bench_id,
                atomic_param,
                param.name(),
                "trivium_generation_512_bits",
                &OperatorType::Atomic,
                80,
                vec![atomic_param.message_modulus().0.ilog2(); 80],
            );
        }

        bench_group.finish();
    }

    criterion_group!(gpu_trivium, cuda_trivium);
}

#[cfg(feature = "gpu")]
use cuda::gpu_trivium;

fn main() {
    #[cfg(feature = "gpu")]
    gpu_trivium();

    Criterion::default().configure_from_args().final_summary();
}
