use criterion::{criterion_group, criterion_main, Criterion};
use rand::RngExt;
use tfhe_zk_pok::proofs::pke_v2::{prove, verify, Bound, VerificationPairingMode};
use tfhe_zk_pok::proofs::ComputeLoad;
use utils::{init_params_v2, write_to_json, PKEV1_TEST_PARAMS, PKEV2_TEST_PARAMS};

#[path = "./utils.rs"]
mod utils;

fn bench_pke_v2_prove(c: &mut Criterion) {
    let bench_shortname = "pke_zk_proof_v2";
    let bench_name = format!("tfhe_zk_pok::{bench_shortname}");
    let mut bench_group = c.benchmark_group(&bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    let rng = &mut rand::rng();

    for ((params, param_name), load, bound) in itertools::iproduct!(
        [
            (PKEV1_TEST_PARAMS, "PKEV1_TEST_PARAMS"),
            (PKEV2_TEST_PARAMS, "PKEV2_TEST_PARAMS"),
        ],
        [ComputeLoad::Proof, ComputeLoad::Verify],
        [Bound::CS, Bound::GHL]
    ) {
        let (public_param, public_commit, private_commit, metadata) = init_params_v2(params, bound);
        let effective_t = params.t >> 1;
        let bits = (params.k as u32) * effective_t.ilog2();

        let bench_id = format!("{bench_name}::{param_name}_{bits}_bits_packed_{load}_{bound:?}");
        println!("{bench_id}");

        let seed: u128 = rng.random();

        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                prove(
                    (&public_param, &public_commit),
                    &private_commit,
                    &metadata,
                    load,
                    &seed.to_le_bytes(),
                )
            })
        });

        write_to_json(&bench_id, params, param_name, bench_shortname);
    }
}

fn bench_pke_v2_verify(c: &mut Criterion) {
    let bench_shortname = "pke_zk_verify_v2";
    let bench_name = format!("tfhe_zk_pok::{bench_shortname}");
    let mut bench_group = c.benchmark_group(&bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    let rng = &mut rand::rng();

    for ((params, param_name), load, bound, pairing_mode) in itertools::iproduct!(
        [
            (PKEV1_TEST_PARAMS, "PKEV1_TEST_PARAMS"),
            (PKEV2_TEST_PARAMS, "PKEV2_TEST_PARAMS"),
        ],
        [ComputeLoad::Proof, ComputeLoad::Verify],
        [Bound::CS, Bound::GHL],
        [
            VerificationPairingMode::TwoSteps,
            VerificationPairingMode::Batched
        ]
    ) {
        let (public_param, public_commit, private_commit, metadata) = init_params_v2(params, bound);
        let effective_t = params.t >> 1;
        let bits = (params.k as u32) * effective_t.ilog2();

        let bench_id = format!(
            "{bench_name}::{param_name}_{bits}_bits_packed_{load}_{bound:?}_{pairing_mode:?}"
        );
        println!("{bench_id}");

        let seed: u128 = rng.random();

        let proof = prove(
            (&public_param, &public_commit),
            &private_commit,
            &metadata,
            load,
            &seed.to_le_bytes(),
        );

        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                verify(
                    &proof,
                    (&public_param, &public_commit),
                    &metadata,
                    pairing_mode,
                )
                .unwrap();
            })
        });

        write_to_json(&bench_id, params, param_name, bench_shortname);
    }
}

criterion_group!(benches_pke_v2, bench_pke_v2_verify, bench_pke_v2_prove);
criterion_main!(benches_pke_v2);
