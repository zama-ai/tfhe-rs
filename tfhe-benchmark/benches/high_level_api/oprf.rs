use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

use benchmark::utilities::{write_to_json, OperatorType};
use benchmark_spec::tfhe::hlapi::oprf::OprfKind;
use benchmark_spec::{BenchmarkSpec, BenchmarkType, HlapiBench, OperandType};
use criterion::{black_box, criterion_group, Criterion};
use std::num::NonZeroU64;
use tfhe::keycache::NamedParam;
use tfhe::{set_server_key, ClientKey, ConfigBuilder, FheUint64, RangeForRandom, Seed, ServerKey};

fn oprf_any_range_bench(c: &mut Criterion, cks: &ClientKey) {
    let mut bench_group = c.benchmark_group("oprf");
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    let hlapi_op = HlapiBench::Oprf(OprfKind::AnyRange);
    let param = cks.computation_parameters();
    let param_name = param.name();

    for excluded_upper_bound in [3, 52] {
        let bound_type = format!("bound_{excluded_upper_bound}",);
        let benchmark_spec = BenchmarkSpec::new_hlapi(
            hlapi_op,
            &param_name,
            OperandType::CipherText,
            Some(bound_type.as_str()),
            BenchmarkType::Latency,
            None,
        );
        let bench_id = benchmark_spec.to_string();

        let range = RangeForRandom::new_from_excluded_upper_bound(
            NonZeroU64::new(excluded_upper_bound).unwrap(),
        );

        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                _ = black_box(FheUint64::generate_oblivious_pseudo_random_custom_range(
                    Seed(0),
                    &range,
                    None,
                ));
            })
        });

        write_to_json(
            &benchmark_spec,
            hlapi_op.to_string(),
            &OperatorType::Atomic,
            64,
            vec![],
        );
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

    oprf_any_range_bench(c, &cks);
}

#[cfg(feature = "gpu")]
pub fn oprf_any_range_gpu(c: &mut Criterion) {
    let param = BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(param).build();
    let cks = ClientKey::generate(config);
    let sks = tfhe::CompressedServerKey::new(&cks).decompress_to_gpu();

    set_server_key(sks);

    oprf_any_range_bench(c, &cks);
}

#[cfg(not(feature = "gpu"))]
criterion_group!(oprf_any_range2, oprf_any_range_cpu);

#[cfg(feature = "gpu")]
criterion_group!(oprf_any_range2, oprf_any_range_cpu, oprf_any_range_gpu);
