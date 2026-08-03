use benchmark::params_aliases::*;
use benchmark::utilities::{write_to_json, OperatorType};
use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, ShortintBench, ShortintPackingOp};
use criterion::{criterion_group, Criterion};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;
use tfhe::keycache::NamedParam;
use tfhe::shortint::prelude::*;

fn spec(packing_op: ShortintPackingOp, param_name: &str) -> BenchmarkSpec<'_, str> {
    BenchmarkSpec::<str>::new_shortint(
        ShortintBench::PackingCompression(packing_op),
        param_name,
        BenchmarkMetric::Latency,
    )
}

fn glwe_packing(c: &mut Criterion) {
    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let comp_param = BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let param_name = param.name();

    let number_to_pack = 256;

    let mut bench_group = c.benchmark_group(param_name.clone());

    // Generate the client key and the server key:
    let cks = ClientKey::new(param);

    let private_compression_key = cks.new_compression_private_key(comp_param);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let ct: Vec<_> = (0..number_to_pack).map(|_| cks.encrypt(0)).collect();

    let pack_spec = spec(ShortintPackingOp::Pack, &param_name);
    bench_group.bench_function(pack_spec.to_string(), |b| {
        b.iter(|| {
            let packed = compression_key.compress_ciphertexts_into_list(&ct);

            _ = black_box(packed);
        })
    });
    write_to_json(
        &pack_spec,
        "packing_compression",
        &OperatorType::Atomic,
        0,
        vec![],
    );

    let packed = compression_key.compress_ciphertexts_into_list(&ct);

    let unpack_all_spec = spec(ShortintPackingOp::UnpackAll, &param_name);
    bench_group.bench_function(unpack_all_spec.to_string(), |b| {
        b.iter(|| {
            (0..number_to_pack).into_par_iter().for_each(|i| {
                let unpacked = decompression_key.unpack(&packed, i);

                _ = black_box(unpacked);
            });
        })
    });
    write_to_json(
        &unpack_all_spec,
        "packing_compression",
        &OperatorType::Atomic,
        0,
        vec![],
    );

    let unpack_one_spec = spec(ShortintPackingOp::UnpackOneLwe, &param_name);
    bench_group.bench_function(unpack_one_spec.to_string(), |b| {
        b.iter(|| {
            let unpacked = decompression_key.unpack(&packed, 0);

            _ = black_box(unpacked);
        })
    });
    write_to_json(
        &unpack_one_spec,
        "packing_compression",
        &OperatorType::Atomic,
        0,
        vec![],
    );

    let unpack_64b_spec = spec(ShortintPackingOp::Unpack64b, &param_name);
    bench_group.bench_function(unpack_64b_spec.to_string(), |b| {
        b.iter(|| {
            (0..32).into_par_iter().for_each(|i| {
                let unpacked = decompression_key.unpack(&packed, i);

                _ = black_box(unpacked);
            });
        })
    });
    write_to_json(
        &unpack_64b_spec,
        "packing_compression",
        &OperatorType::Atomic,
        0,
        vec![],
    );

    let pack_unpack_spec = spec(ShortintPackingOp::PackUnpack, &param_name);
    bench_group.bench_function(pack_unpack_spec.to_string(), |b| {
        b.iter(|| {
            let packed = compression_key.compress_ciphertexts_into_list(&ct);

            (0..number_to_pack).into_par_iter().for_each(|i| {
                let unpacked = decompression_key.unpack(&packed, i);

                _ = black_box(unpacked);
            });
        })
    });
    write_to_json(
        &pack_unpack_spec,
        "packing_compression",
        &OperatorType::Atomic,
        0,
        vec![],
    );
}

criterion_group!(glwe_packing2, glwe_packing);

fn main() {
    glwe_packing2();
    Criterion::default().configure_from_args().final_summary();
}
