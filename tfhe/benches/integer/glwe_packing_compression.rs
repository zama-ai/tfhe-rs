#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, OperatorType};
use criterion::{black_box, criterion_group, Criterion};
use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
use tfhe::integer::{ClientKey, RadixCiphertext};
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

fn cpu_glwe_packing(c: &mut Criterion) {
    let bench_name = "integer::packing_compression";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let comp_param = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    let cks = ClientKey::new(param);

    let private_compression_key = cks.new_compression_private_key(comp_param);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let log_message_modulus = param.message_modulus.0.ilog2() as usize;

    for bit_size in [
        8,
        16,
        32,
        64,
        128,
        256,
        comp_param.lwe_per_glwe.0 * log_message_modulus,
    ] {
        assert_eq!(bit_size % log_message_modulus, 0);
        let num_blocks = bit_size / log_message_modulus;

        let ct = cks.encrypt_radix(0_u32, num_blocks);

        let mut builder = CompressedCiphertextListBuilder::new();

        builder.push(ct);

        let bench_id = format!("{bench_name}::pack_u{bit_size}");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let compressed = builder.build(&compression_key);

                _ = black_box(compressed);
            })
        });

        write_to_json::<u64, _>(
            &bench_id,
            comp_param,
            comp_param.name(),
            "pack",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus.0.ilog2(); num_blocks],
        );

        let compressed = builder.build(&compression_key);

        let bench_id = format!("{bench_name}::unpack_u{bit_size}");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let unpacked: RadixCiphertext =
                    compressed.get(0, &decompression_key).unwrap().unwrap();

                _ = black_box(unpacked);
            })
        });

        write_to_json::<u64, _>(
            &bench_id,
            comp_param,
            comp_param.name(),
            "unpack",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus.0.ilog2(); num_blocks],
        );
    }

    bench_group.finish()
}

#[cfg(feature = "gpu")]
mod cuda {
    use super::*;
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
    use tfhe::integer::gpu::ciphertext::{CudaRadixCiphertext, CudaUnsignedRadixCiphertext};
    use tfhe::integer::gpu::gen_keys_radix_gpu;

    fn gpu_glwe_packing(c: &mut Criterion) {
        let bench_name = "integer::cuda::packing_compression";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        let stream = CudaStreams::new_multi_gpu();

        let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let comp_param = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let log_message_modulus = param.message_modulus.0.ilog2() as usize;

        for bit_size in [
            8,
            16,
            32,
            64,
            128,
            256,
            comp_param.lwe_per_glwe.0 * log_message_modulus,
        ] {
            assert_eq!(bit_size % log_message_modulus, 0);
            let num_blocks = bit_size / log_message_modulus;

            // Generate private compression key
            let cks = ClientKey::new(param);
            let private_compression_key = cks.new_compression_private_key(comp_param);

            // Generate and convert compression keys
            let (radix_cks, _) = gen_keys_radix_gpu(param, num_blocks, &stream);
            let (compressed_compression_key, compressed_decompression_key) =
                radix_cks.new_compressed_compression_decompression_keys(&private_compression_key);
            let cuda_compression_key = compressed_compression_key.decompress_to_cuda(&stream);
            let cuda_decompression_key =
                compressed_decompression_key.decompress_to_cuda(radix_cks.parameters(), &stream);

            // Encrypt
            let ct = cks.encrypt_radix(0_u32, num_blocks);
            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &stream);

            // Benchmark
            let mut builder = CudaCompressedCiphertextListBuilder::new();

            builder.push(d_ct, &stream);

            let bench_id = format!("{bench_name}::pack_u{bit_size}");
            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    let compressed = builder.build(&cuda_compression_key, &stream);

                    _ = black_box(compressed);
                })
            });

            write_to_json::<u64, _>(
                &bench_id,
                comp_param,
                comp_param.name(),
                "pack",
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus.0.ilog2(); num_blocks],
            );

            let compressed = builder.build(&cuda_compression_key, &stream);

            let bench_id = format!("{bench_name}::unpack_u{bit_size}");
            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    let unpacked: CudaRadixCiphertext =
                        compressed.get(0, &cuda_decompression_key, &stream);

                    _ = black_box(unpacked);
                })
            });

            write_to_json::<u64, _>(
                &bench_id,
                comp_param,
                comp_param.name(),
                "unpack",
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus.0.ilog2(); num_blocks],
            );
        }

        bench_group.finish()
    }

    criterion_group!(gpu_glwe_packing2, gpu_glwe_packing);
}

criterion_group!(cpu_glwe_packing2, cpu_glwe_packing);

#[cfg(feature = "gpu")]
use cuda::gpu_glwe_packing2;

fn main() {
    #[cfg(feature = "gpu")]
    gpu_glwe_packing2();
    #[cfg(not(feature = "gpu"))]
    cpu_glwe_packing2();

    Criterion::default().configure_from_args().final_summary();
}
