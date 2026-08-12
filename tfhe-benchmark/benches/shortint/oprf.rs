use benchmark::params_aliases::*;
use benchmark::utilities::{write_to_json, OperatorType};
use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, ShortintBench};
use criterion::{criterion_group, Criterion};
use std::hint::black_box;
use tfhe::keycache::NamedParam;
use tfhe::shortint::keycache::KEY_CACHE;
use tfhe::shortint::oprf::{OprfPrivateKey, OprfServerKey};
use tfhe_csprng::seeders::Seed;

fn oprf(c: &mut Criterion) {
    let shortint_bench = ShortintBench::Oprf;
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());

    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let param_name = param.name();

    let keys = KEY_CACHE.get_from_param(param);
    let cks = keys.client_key();
    let sks = keys.server_key();

    let oprf_pk = OprfPrivateKey::new(cks);
    let oprf_sk = OprfServerKey::new(&oprf_pk, cks).unwrap();

    let benchmark_spec =
        BenchmarkSpec::new_shortint(shortint_bench, &param_name, BenchmarkMetric::Latency);
    let bench_id = benchmark_spec.to_string();
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            _ = black_box(oprf_sk.generate_oblivious_pseudo_random_bits_chunks(Seed(0), &[2], sks));
        })
    });

    write_to_json(
        &benchmark_spec,
        "oprf",
        &OperatorType::Atomic,
        param.message_modulus.0.ilog2() as u64,
        vec![param.message_modulus.0.ilog2()],
    );
}

criterion_group!(oprf2, oprf);

fn main() {
    oprf2();
    Criterion::default().configure_from_args().final_summary();
}
