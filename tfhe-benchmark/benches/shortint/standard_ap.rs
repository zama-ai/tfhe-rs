use criterion::{criterion_main, Criterion};
use rand::Rng;
use tfhe::shortint::keycache::KEY_CACHE;
use tfhe::shortint::parameters::v1_3::*;

fn programmable_bootstrapping_bench(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("Standard benchmarks");

    let params_64 = vec![
        V1_3_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_3_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        V1_3_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
    ];

    let params_128 = vec![
        V1_3_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_3_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        V1_3_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
    ];

    for (p_fail, params) in [("2^-64", &params_64), ("2^-128", &params_128)] {
        for param in params.iter() {
            let keys = KEY_CACHE.get_from_param(*param);
            let (cks, sks) = (keys.client_key(), keys.server_key());

            let mut rng = rand::thread_rng();

            let modulus = cks.parameters().message_modulus().0;

            let acc = sks.generate_lookup_table(|x| x);

            let clear_0 = rng.gen::<u64>() % modulus;

            let ctxt = cks.encrypt(clear_0);

            let p = param.carry_modulus.0.ilog2() + param.message_modulus.0.ilog2();

            let bench_id = format!("KS-PBS_p={p}_pfail={p_fail}");

            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    let _ = sks.apply_lookup_table(&ctxt, &acc);
                })
            });
        }
    }

    bench_group.finish();
}

pub fn group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();

    programmable_bootstrapping_bench(&mut criterion);
}

criterion_main!(group);
