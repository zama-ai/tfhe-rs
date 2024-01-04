use concrete_csprng::seeders::Seed;
use criterion::{black_box, criterion_group, Criterion};
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::IntegerKeyKind;
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::*;

fn oprf(c: &mut Criterion) {
    let bench_name = "integer_oprf";

    let mut bench_group = c.benchmark_group(bench_name);

    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let (_, sk) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    bench_group.bench_function(&format!("64-bits-oprf::{}", param.name()), |b| {
        b.iter(|| {
            _ = black_box(sk.par_generate_oblivious_pseudo_random_unsigned_integer(
                Seed(0),
                64,
                32,
            ));
        })
    });
}

criterion_group!(oprf2, oprf);

fn main() {
    oprf2();
    Criterion::default().configure_from_args().final_summary();
}
