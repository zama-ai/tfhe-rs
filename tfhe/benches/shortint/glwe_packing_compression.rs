use criterion::{black_box, criterion_group, Criterion};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::prelude::*;

fn glwe_packing(c: &mut Criterion) {
    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    let comp_param = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    let number_to_pack = 256;

    let bench_name = "shortint_packing_compression";

    let mut bench_group = c.benchmark_group(bench_name);

    // Generate the client key and the server key:
    let cks = ClientKey::new(param);

    let private_compression_key = cks.new_compression_private_key(comp_param);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let ct: Vec<_> = (0..number_to_pack).map(|_| cks.encrypt(0)).collect();

    bench_group.bench_function("pack".to_owned(), |b| {
        b.iter(|| {
            let packed = compression_key.compress_ciphertexts_into_list(&ct);

            _ = black_box(packed);
        })
    });

    let packed = compression_key.compress_ciphertexts_into_list(&ct);
    bench_group.bench_function("unpack_all".to_owned(), |b| {
        b.iter(|| {
            (0..number_to_pack).into_par_iter().for_each(|i| {
                let unpacked = decompression_key.unpack(&packed, i);

                _ = black_box(unpacked);
            });
        })
    });

    bench_group.bench_function("unpack_one_lwe".to_owned(), |b| {
        b.iter(|| {
            let unpacked = decompression_key.unpack(&packed, 0);

            _ = black_box(unpacked);
        })
    });

    bench_group.bench_function("unpack_64b".to_owned(), |b| {
        b.iter(|| {
            (0..32).into_par_iter().for_each(|i| {
                let unpacked = decompression_key.unpack(&packed, i);

                _ = black_box(unpacked);
            });
        })
    });

    bench_group.bench_function("pack_unpack".to_owned(), |b| {
        b.iter(|| {
            let packed = compression_key.compress_ciphertexts_into_list(&ct);

            (0..number_to_pack).into_par_iter().for_each(|i| {
                let unpacked = decompression_key.unpack(&packed, i);

                _ = black_box(unpacked);
            });
        })
    });
}

criterion_group!(glwe_packing2, glwe_packing);

fn main() {
    glwe_packing2();
    Criterion::default().configure_from_args().final_summary();
}
