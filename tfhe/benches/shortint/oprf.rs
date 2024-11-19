use criterion::{black_box, criterion_group, Criterion};
use tfhe::keycache::NamedParam;
use tfhe::shortint::keycache::KEY_CACHE;
use tfhe::shortint::parameters::*;
use tfhe_csprng::seeders::Seed;

fn oprf(c: &mut Criterion) {
    let bench_name = "shortint-oprf";

    let mut bench_group = c.benchmark_group(bench_name);

    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let keys = KEY_CACHE.get_from_param(param);
    let sks = keys.server_key();

    bench_group.bench_function(format!("2-bits-oprf::{}", param.name()), |b| {
        b.iter(|| {
            _ = black_box(sks.generate_oblivious_pseudo_random(Seed(0), 2));
        })
    });
}

criterion_group!(oprf2, oprf);

fn main() {
    oprf2();
    Criterion::default().configure_from_args().final_summary();
}
