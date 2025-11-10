use benchmark::params_aliases::*;
use criterion::{black_box, criterion_group, Criterion};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tfhe::shortint::prelude::*;

fn glwe_packing(c: &mut Criterion) {
    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let comp_param = BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let number_to_pack = 256;

    let bench_name = "shortint_packing_compression";

    let mut bench_group = c.benchmark_group(bench_name);

    // Generate the client key and the server key:
    let cks = ClientKey::new(param);

    let private_compression_key = cks.new_compression_private_key(comp_param);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let ct: Vec<_> = (0..number_to_pack).map(|_| cks.encrypt(0)).collect();

    let bench_id = format!("{bench_name}::pack");
    println!("{bench_id}");
    bench_group.bench_function("pack".to_owned(), |b| {
        b.iter(|| {
            let packed = compression_key.compress_ciphertexts_into_list(&ct);

            _ = black_box(packed);
        })
    });

    let bench_id = format!("{bench_name}::unpack_all");
    println!("{bench_id}");
    let packed = compression_key.compress_ciphertexts_into_list(&ct);
    bench_group.bench_function(bench_id, |b| {
        b.iter(|| {
            (0..number_to_pack).into_par_iter().for_each(|i| {
                let unpacked = decompression_key.unpack(&packed, i);

                _ = black_box(unpacked);
            });
        })
    });

    let bench_id = format!("{bench_name}::unpack_one_lwe");
    println!("{bench_id}");
    bench_group.bench_function(bench_id, |b| {
        b.iter(|| {
            let unpacked = decompression_key.unpack(&packed, 0);

            _ = black_box(unpacked);
        })
    });

    let bench_id = format!("{bench_name}::unpack_64b");
    println!("{bench_id}");
    bench_group.bench_function(bench_id, |b| {
        b.iter(|| {
            (0..32).into_par_iter().for_each(|i| {
                let unpacked = decompression_key.unpack(&packed, i);

                _ = black_box(unpacked);
            });
        })
    });

    let bench_id = format!("{bench_name}::pack_unpack");
    println!("{bench_id}");
    bench_group.bench_function(bench_id, |b| {
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
