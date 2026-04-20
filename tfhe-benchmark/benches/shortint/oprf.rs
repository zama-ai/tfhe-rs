use benchmark::params_aliases::*;
use criterion::{black_box, criterion_group, Criterion};
use tfhe::keycache::NamedParam;
use tfhe::shortint::keycache::KEY_CACHE;
use tfhe::shortint::oprf::{OprfPrivateKey, OprfServerKey};
use tfhe_csprng::seeders::Seed;

fn oprf(c: &mut Criterion) {
    let bench_name = "shortint-oprf";

    let mut bench_group = c.benchmark_group(bench_name);

    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let keys = KEY_CACHE.get_from_param(param);
    let cks = keys.client_key();
    let sks = keys.server_key();

    let oprf_pk = OprfPrivateKey::new(cks);
    let oprf_sk = OprfServerKey::new(&oprf_pk, cks).unwrap();

    bench_group.bench_function(format!("2-bits-oprf::{}", param.name()), |b| {
        b.iter(|| {
            _ = black_box(oprf_sk.generate_oblivious_pseudo_random(Seed(0), 2, sks));
        })
    });
}

criterion_group!(oprf2, oprf);

fn main() {
    oprf2();
    Criterion::default().configure_from_args().final_summary();
}
