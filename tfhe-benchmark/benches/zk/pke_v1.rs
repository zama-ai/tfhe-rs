use benchmark_spec::zk::pke::{PkeBench, PkeProof, PkeVerify};
use benchmark_spec::Backend;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use tfhe_zk_pok::proofs::pke::{prove, verify};
use tfhe_zk_pok::proofs::ComputeLoad;
use utils::{pke_spec, spec_compute_load, write_pke_record, PKEV1_TEST_PARAMS, PKEV2_TEST_PARAMS};

#[path = "./utils.rs"]
mod utils;

use crate::utils::init_params_v1;

fn bench_pke_v1_prove(c: &mut Criterion) {
    let bench_shortname = "pke_zk_proof_v1";
    let bench_name = format!("tfhe_zk_pok::{bench_shortname}");
    let mut bench_group = c.benchmark_group(&bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    let rng = &mut rand::thread_rng();

    for (params, param_name) in [
        (PKEV1_TEST_PARAMS, "PKEV1_TEST_PARAMS"),
        (PKEV2_TEST_PARAMS, "PKEV2_TEST_PARAMS"),
    ] {
        let (public_param, public_commit, private_commit, metadata) = init_params_v1(params);

        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let spec = pke_spec(
                PkeBench::Proof(PkeProof::V1(spec_compute_load(load))),
                Backend::Cpu,
                params,
                param_name,
            );
            let bench_id = spec.to_string();

            let seed: u128 = rng.gen();

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

            write_pke_record(&spec, params, bench_shortname);
        }
    }
}

fn bench_pke_v1_verify(c: &mut Criterion) {
    let bench_shortname = "pke_zk_verify_v1";
    let bench_name = format!("tfhe_zk_pok::{bench_shortname}");
    let mut bench_group = c.benchmark_group(&bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    let rng = &mut rand::thread_rng();

    for (params, param_name) in [
        (PKEV1_TEST_PARAMS, "PKEV1_TEST_PARAMS"),
        (PKEV2_TEST_PARAMS, "PKEV2_TEST_PARAMS"),
    ] {
        let (public_param, public_commit, private_commit, metadata) = init_params_v1(params);

        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let spec = pke_spec(
                PkeBench::Verify(PkeVerify::V1(spec_compute_load(load))),
                Backend::Cpu,
                params,
                param_name,
            );
            let bench_id = spec.to_string();

            let seed: u128 = rng.gen();

            let proof = prove(
                (&public_param, &public_commit),
                &private_commit,
                &metadata,
                load,
                &seed.to_le_bytes(),
            );

            bench_group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    verify(&proof, (&public_param, &public_commit), &metadata).unwrap();
                })
            });

            write_pke_record(&spec, params, bench_shortname);
        }
    }
}

criterion_group!(benches_pke_v1, bench_pke_v1_verify, bench_pke_v1_prove);
criterion_main!(benches_pke_v1);
