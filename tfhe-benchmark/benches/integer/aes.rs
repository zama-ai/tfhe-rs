#[cfg(feature = "gpu")]
pub mod cuda {
    use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use benchmark::utilities::{write_to_json, OperatorType};
    use criterion::{black_box, Criterion};
    use tfhe::core_crypto::gpu::{check_valid_cuda_malloc, CudaStreams};
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::keycache::KEY_CACHE;
    use tfhe::integer::{IntegerKeyKind, RadixClientKey};
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::AtomicPatternParameters;

    pub fn cuda_aes(c: &mut Criterion) {
        let bench_name = "integer::cuda::aes";

        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60))
            .warm_up_time(std::time::Duration::from_secs(60));

        let param = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let atomic_param: AtomicPatternParameters = param.into();

        let key: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
        let iv: u128 = 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff;
        let aes_op_bit_size = 128;

        let param_name = param.name();

        let streams = CudaStreams::new_multi_gpu();
        let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
        let sks = CudaServerKey::new(&cpu_cks, &streams);
        let cks = RadixClientKey::from((cpu_cks, 1));

        let ct_key = cks.encrypt_u128_for_aes_ctr(key);
        let ct_iv = cks.encrypt_u128_for_aes_ctr(iv);

        let d_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_key, &streams);
        let d_iv = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_iv, &streams);

        {
            const NUM_AES_INPUTS: usize = 1;
            const SBOX_PARALLELISM: usize = 16;
            let bench_id = format!("{param_name}::{NUM_AES_INPUTS}_input_encryption");
            println!("{bench_id}");

            let round_keys = sks.key_expansion(&d_key, &streams);

            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    black_box(sks.aes_encrypt(
                        &d_iv,
                        &round_keys,
                        0,
                        NUM_AES_INPUTS,
                        SBOX_PARALLELISM,
                        &streams,
                    ));
                })
            });

            write_to_json::<u64, _>(
                &bench_id,
                atomic_param,
                param.name(),
                "aes_encryption",
                &OperatorType::Atomic,
                aes_op_bit_size,
                vec![atomic_param.message_modulus().0.ilog2(); aes_op_bit_size as usize],
            );
        }

        {
            let bench_id = format!("{param_name}::key_expansion");
            println!("{bench_id}");
            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    black_box(sks.key_expansion(&d_key, &streams));
                })
            });

            write_to_json::<u64, _>(
                &bench_id,
                atomic_param,
                param.name(),
                "aes_key_expansion",
                &OperatorType::Atomic,
                aes_op_bit_size,
                vec![atomic_param.message_modulus().0.ilog2(); aes_op_bit_size as usize],
            );
        }

        {
            const NUM_AES_INPUTS: usize = 192;
            const SBOX_PARALLELISM: usize = 16;
            let bench_id = format!("{param_name}::{NUM_AES_INPUTS}_inputs_encryption");

            let streams = CudaStreams::new_multi_gpu();
            let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
            let sks = CudaServerKey::new(&cpu_cks, &streams);
            let cks = RadixClientKey::from((cpu_cks, 1));

            //
            // Memory checks
            //
            let gpu_index = streams.gpu_indexes[0];

            let key_expansion_size = sks.get_key_expansion_size_on_gpu(&streams);
            let aes_encrypt_size =
                sks.get_aes_encrypt_size_on_gpu(NUM_AES_INPUTS, SBOX_PARALLELISM, &streams);

            if check_valid_cuda_malloc(key_expansion_size, gpu_index)
                && check_valid_cuda_malloc(aes_encrypt_size, gpu_index)
            {
                let ct_key = cks.encrypt_u128_for_aes_ctr(key);
                let ct_iv = cks.encrypt_u128_for_aes_ctr(iv);

                let d_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_key, &streams);
                let d_iv = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_iv, &streams);

                let round_keys = sks.key_expansion(&d_key, &streams);

                println!("{bench_id}");
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        black_box(sks.aes_encrypt(
                            &d_iv,
                            &round_keys,
                            0,
                            NUM_AES_INPUTS,
                            SBOX_PARALLELISM,
                            &streams,
                        ));
                    })
                });

                write_to_json::<u64, _>(
                    &bench_id,
                    atomic_param,
                    param.name(),
                    "aes_encryption",
                    &OperatorType::Atomic,
                    aes_op_bit_size,
                    vec![atomic_param.message_modulus().0.ilog2(); aes_op_bit_size as usize],
                );
            } else {
                println!("{} skipped: Not enough memory in GPU", bench_id);
            }
        }

        bench_group.finish();
    }
}
