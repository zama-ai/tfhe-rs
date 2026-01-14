use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

use criterion::{black_box, criterion_group, Criterion};
use std::num::NonZeroU64;
use tfhe::{set_server_key, ClientKey, ConfigBuilder, FheUint64, RangeForRandom, Seed, ServerKey};

fn oprf_any_range_bench(c: &mut Criterion, bench_name: &str) {
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    for excluded_upper_bound in [3, 52] {
        let range = RangeForRandom::new_from_excluded_upper_bound(
            NonZeroU64::new(excluded_upper_bound).unwrap(),
        );

        let bench_id_oprf = format!("{bench_name}::bound_{excluded_upper_bound}");

        bench_group.bench_function(&bench_id_oprf, |b| {
            b.iter(|| {
                _ = black_box(FheUint64::generate_oblivious_pseudo_random_custom_range(
                    Seed(0),
                    &range,
                    None,
                ));
            })
        });
    }

    bench_group.finish()
}

pub fn oprf_any_range_cpu(c: &mut Criterion) {
    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(param).build();
    let cks = ClientKey::generate(config);
    let sks = ServerKey::new(&cks);

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    oprf_any_range_bench(c, "hlapi::oprf_any_range_cpu");
}

#[cfg(feature = "gpu")]
pub fn oprf_any_range_gpu(c: &mut Criterion) {
    let param = BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(param).build();
    let cks = ClientKey::generate(config);
    let sks = tfhe::CompressedServerKey::new(&cks).decompress_to_gpu();

    set_server_key(sks);

    oprf_any_range_bench(c, "hlapi::oprf_any_range_gpu");
}

#[cfg(not(feature = "gpu"))]
criterion_group!(oprf_any_range2, oprf_any_range_cpu);

#[cfg(feature = "gpu")]
criterion_group!(oprf_any_range2, oprf_any_range_cpu, oprf_any_range_gpu);
