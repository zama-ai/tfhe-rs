use benchmark::params_aliases::*;
use benchmark::utilities::{bench_backend_from_cfg, write_to_json, OperatorType};
use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, ShortintBench};
use criterion::Criterion;
use rayon::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::shortint::prelude::*;

pub fn pack_cast_64(c: &mut Criterion) {
    let shortint_bench = ShortintBench::PackCast64;
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());

    let (client_key_1, server_key_1): (ClientKey, ServerKey) =
        gen_keys(BENCH_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128);
    let (client_key_2, server_key_2): (ClientKey, ServerKey) =
        gen_keys(BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

    let ks_param = BENCH_PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS_GAUSSIAN_2M128;
    let ks_param_name = ks_param.name();

    let ksk = KeySwitchingKey::new(
        (&client_key_1, Some(&server_key_1)),
        (&client_key_2, &server_key_2),
        ks_param,
    );

    let vec_ct = vec![client_key_1.encrypt(1); 64];

    let benchmark_spec = BenchmarkSpec::<str>::new_shortint(
        shortint_bench,
        &ks_param_name,
        BenchmarkMetric::Latency,
        bench_backend_from_cfg(),
    );
    let bench_id = benchmark_spec.to_string();
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let _ = (0..32)
                .into_par_iter()
                .map(|i| {
                    let byte_idx = 7 - i / 4;
                    let pair_idx = i % 4;

                    let b0 = &vec_ct[8 * byte_idx + 2 * pair_idx];
                    let b1 = &vec_ct[8 * byte_idx + 2 * pair_idx + 1];

                    ksk.cast(
                        &server_key_1.unchecked_add(b0, &server_key_1.unchecked_scalar_mul(b1, 2)),
                    )
                })
                .collect::<Vec<_>>();
        });
    });

    write_to_json::<u64, _, _>(
        &benchmark_spec,
        ks_param,
        "pack_cast_64",
        &OperatorType::Atomic,
        0,
        vec![],
    );
}

pub fn pack_cast(c: &mut Criterion) {
    let shortint_bench = ShortintBench::PackCast;
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());

    let (client_key_1, server_key_1): (ClientKey, ServerKey) =
        gen_keys(BENCH_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128);
    let (client_key_2, server_key_2): (ClientKey, ServerKey) =
        gen_keys(BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

    let ks_param = BENCH_PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS_GAUSSIAN_2M128;
    let ks_param_name = ks_param.name();

    let ksk = KeySwitchingKey::new(
        (&client_key_1, Some(&server_key_1)),
        (&client_key_2, &server_key_2),
        ks_param,
    );

    let ct_1 = client_key_1.encrypt(1);
    let ct_2 = client_key_1.encrypt(1);

    let benchmark_spec = BenchmarkSpec::<str>::new_shortint(
        shortint_bench,
        &ks_param_name,
        BenchmarkMetric::Latency,
        bench_backend_from_cfg(),
    );
    let bench_id = benchmark_spec.to_string();
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let _ = ksk.cast(
                &server_key_1.unchecked_add(&ct_1, &server_key_1.unchecked_scalar_mul(&ct_2, 2)),
            );
        });
    });

    write_to_json::<u64, _, _>(
        &benchmark_spec,
        ks_param,
        "pack_cast",
        &OperatorType::Atomic,
        0,
        vec![],
    );
}

pub fn cast(c: &mut Criterion) {
    let shortint_bench = ShortintBench::Cast;
    let mut bench_group = c.benchmark_group(shortint_bench.to_string());

    let (client_key_1, server_key_1): (ClientKey, ServerKey) =
        gen_keys(BENCH_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128);
    let (client_key_2, server_key_2): (ClientKey, ServerKey) =
        gen_keys(BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);

    let ks_param = BENCH_PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS_GAUSSIAN_2M128;
    let ks_param_name = ks_param.name();

    let ksk = KeySwitchingKey::new(
        (&client_key_1, Some(&server_key_1)),
        (&client_key_2, &server_key_2),
        ks_param,
    );

    let ct = client_key_1.encrypt(1);

    let benchmark_spec = BenchmarkSpec::<str>::new_shortint(
        shortint_bench,
        &ks_param_name,
        BenchmarkMetric::Latency,
        bench_backend_from_cfg(),
    );
    let bench_id = benchmark_spec.to_string();
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let _ = ksk.cast(&ct);
        });
    });

    write_to_json::<u64, _, _>(
        &benchmark_spec,
        ks_param,
        "cast",
        &OperatorType::Atomic,
        0,
        vec![],
    );
}
