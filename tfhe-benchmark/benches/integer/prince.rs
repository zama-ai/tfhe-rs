use criterion::Criterion;

#[cfg(feature = "gpu")]
pub mod cuda {
    use benchmark::params_aliases::{
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use benchmark::utilities::{write_to_json_unchecked, OperatorType};
    use criterion::{criterion_group, Criterion};
    use std::hint::black_box;
    use tfhe::core_crypto::gpu::{check_valid_cuda_malloc, CudaStreams};
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::keycache::KEY_CACHE;
    use tfhe::integer::{IntegerKeyKind, RadixClientKey};
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::AtomicPatternParameters;

    /// Mirrors the AES bench: key preparation apart (as the key expansion),
    /// then 2 and 384 inputs = 1 and 192 128-bit keystreams, on classical and
    /// multi-bit parameters.
    pub fn cuda_prince(c: &mut Criterion) {
        let bench_name = "integer::cuda::prince";

        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60))
            .warm_up_time(std::time::Duration::from_secs(60));

        let message: u64 = 0x0123456789abcdef;
        let k0: u64 = 0x0123456789abcdef;
        let k1: u64 = 0xfedcba9876543210;
        let prince_op_bit_size = 64;

        let params: [(AtomicPatternParameters, String); 2] = [
            (
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
            ),
            (
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
            ),
        ];

        for (atomic_param, param_name) in params {
            let streams = CudaStreams::new_multi_gpu();
            let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
            let sks = CudaServerKey::new(&cpu_cks, &streams);
            let cks = RadixClientKey::from((cpu_cks, 1));

            let ct_k0 = cks.encrypt_u64_for_prince(k0);
            let ct_k1 = cks.encrypt_u64_for_prince(k1);
            let d_k0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_k0, &streams);
            let d_k1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_k1, &streams);

            {
                let bench_id = format!("{bench_name}::{param_name}::key_prep");
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        black_box(sks.prince_encrypt_init(&d_k0, &d_k1, &streams));
                    })
                });
                write_to_json_unchecked(
                    &bench_id,
                    &param_name,
                    "prince_key_prep",
                    &OperatorType::Atomic,
                    prince_op_bit_size,
                    vec![atomic_param.message_modulus().0.ilog2(); prince_op_bit_size as usize],
                );
            }

            for num_prince_inputs in [2usize, 384] {
                let bench_id =
                    format!("{bench_name}::{param_name}::{num_prince_inputs}_inputs_encryption");

                let prince_size = sks.get_prince_encrypt_size_on_gpu(num_prince_inputs, &streams);
                if !check_valid_cuda_malloc(prince_size, streams.gpu_indexes[0]) {
                    println!("{} skipped: Not enough memory in GPU", bench_id);
                    continue;
                }

                let ct_input = cks.encrypt_u64s_for_prince(&vec![message; num_prince_inputs]);
                let d_input =
                    CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_input, &streams);

                let keys = sks.prince_encrypt_init(&d_k0, &d_k1, &streams);

                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        black_box(sks.prince_next(&keys, &d_input, num_prince_inputs, &streams));
                    })
                });

                write_to_json_unchecked(
                    &bench_id,
                    &param_name,
                    "prince_encryption",
                    &OperatorType::Atomic,
                    prince_op_bit_size,
                    vec![atomic_param.message_modulus().0.ilog2(); prince_op_bit_size as usize],
                );
            }
        }

        bench_group.finish();
    }

    criterion_group!(gpu_prince, cuda_prince);
}

#[cfg(feature = "gpu")]
use cuda::gpu_prince;

fn main() {
    #[cfg(feature = "gpu")]
    gpu_prince();

    Criterion::default().configure_from_args().final_summary();
}
