use criterion::{black_box, criterion_group, Criterion};
use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
use tfhe::integer::{ClientKey, RadixCiphertext};
use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

fn cpu_glwe_packing(c: &mut Criterion) {
    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    let comp_param = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    let bench_name = "integer_packing_compression";

    let mut bench_group = c.benchmark_group(bench_name);

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

criterion_group!(cpu_glwe_packing2, cpu_glwe_packing);

fn main() {
    cpu_glwe_packing2();

    Criterion::default().configure_from_args().final_summary();
}
