use crate::utilities::{write_to_json, OperatorType, ParamsAndNumBlocksIter};
use concrete_csprng::seeders::Seed;
use criterion::{black_box, Criterion};
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::IntegerKeyKind;
use tfhe::keycache::NamedParam;

pub fn unsigned_oprf(c: &mut Criterion) {
    let bench_name = "integer::unsigned_oprf";

    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let (_, sk) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

        let bench_id = format!("{}::{}::{}_bits", bench_name, param.name(), bit_size);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                _ = black_box(sk.par_generate_oblivious_pseudo_random_unsigned_integer(
                    Seed(0),
                    bit_size as u64,
                    num_block as u64,
                ));
            })
        });

        write_to_json::<u64, _>(
            &bench_id,
            param,
            param.name(),
            "oprf",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_block],
        );
    }

    bench_group.finish()
}
