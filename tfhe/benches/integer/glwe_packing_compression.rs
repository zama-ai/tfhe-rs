use criterion::{black_box, criterion_group, Criterion};
use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
use tfhe::integer::{ClientKey, RadixCiphertext};
use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

#[cfg(feature = "gpu")]
use tfhe::core_crypto::gpu::CudaStreams;

#[cfg(feature = "gpu")]
use tfhe::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;

#[cfg(feature = "gpu")]
use tfhe::integer::gpu::ciphertext::{CudaRadixCiphertext, CudaUnsignedRadixCiphertext};

#[cfg(feature = "gpu")]
use tfhe::integer::gpu::gen_keys_radix_gpu;

fn cpu_glwe_packing(c: &mut Criterion) {
    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    let comp_param = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    let bench_name = "integer_packing_compression";

    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    let cks = ClientKey::new(param);

    let private_compression_key = cks.new_compression_private_key(comp_param);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let log_message_modulus = param.message_modulus.0.ilog2() as usize;

    for num_bits in [
        8,
        16,
        32,
        64,
        128,
        256,
        comp_param.lwe_per_glwe.0 * log_message_modulus,
    ] {
        assert_eq!(num_bits % log_message_modulus, 0);
        let num_blocks = num_bits / log_message_modulus;

        let ct = cks.encrypt_radix(0_u32, num_blocks);

        let mut builder = CompressedCiphertextListBuilder::new();

        builder.push(ct);

        bench_group.bench_function(format!("pack_u{num_bits}"), |b| {
            b.iter(|| {
                let compressed = builder.build(&compression_key);

                _ = black_box(compressed);
            })
        });

        let compressed = builder.build(&compression_key);

        bench_group.bench_function(format!("unpack_u{num_bits}"), |b| {
            b.iter(|| {
                let unpacked: RadixCiphertext =
                    compressed.get(0, &decompression_key).unwrap().unwrap();

                _ = black_box(unpacked);
            })
        });

        bench_group.bench_function(format!("pack_unpack_u{num_bits}"), |b| {
            b.iter(|| {
                let compressed = builder.build(&compression_key);

                let unpacked: RadixCiphertext =
                    compressed.get(0, &decompression_key).unwrap().unwrap();

                _ = black_box(unpacked);
            })
        });
    }
}

#[cfg(feature = "gpu")]
fn gpu_glwe_packing(c: &mut Criterion) {
    let bench_name = "integer_cuda_packing_compression";
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

        let bench_id = format!("pack_u{bit_size}");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let compressed = builder.build(&cuda_compression_key, &stream);

                _ = black_box(compressed);
            })
        });

        let compressed = builder.build(&cuda_compression_key, &stream);

        let bench_id = format!("unpack_u{bit_size}");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let unpacked: CudaRadixCiphertext =
                    compressed.get(0, &cuda_decompression_key, &stream);

                _ = black_box(unpacked);
            })
        });
    }
}

#[cfg(feature = "gpu")]
criterion_group!(gpu_glwe_packing2, gpu_glwe_packing);
criterion_group!(cpu_glwe_packing2, cpu_glwe_packing);

fn main() {
    #[cfg(feature = "gpu")]
    gpu_glwe_packing2();
    #[cfg(not(feature = "gpu"))]
    cpu_glwe_packing2();

    Criterion::default().configure_from_args().final_summary();
}
