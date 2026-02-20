use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use tfhe_zk_pok::proofs::pke::{prove, verify};
use tfhe_zk_pok::proofs::ComputeLoad;
use utils::{write_to_json, PKEV1_TEST_PARAMS, PKEV2_TEST_PARAMS};

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
        let effective_t = params.t >> 1;
        let bits = (params.k as u32) * effective_t.ilog2();

        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let bench_id = format!("{bench_name}::{param_name}_{bits}_bits_packed_{load}");

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

            write_to_json(&bench_id, params, param_name, bench_shortname);
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
        let effective_t = params.t >> 1;
        let bits = (params.k as u32) * effective_t.ilog2();

        for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
            let bench_id = format!("{bench_name}::{param_name}_{bits}_bits_packed_{load}");

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

            write_to_json(&bench_id, params, param_name, bench_shortname);
        }
    }
}

#[cfg(feature = "gpu-experimental")]
mod gpu {
    use super::*;
    use tfhe_zk_pok::proofs::pke;

    pub fn bench_pke_v1_prove_gpu(c: &mut Criterion) {
        let bench_shortname = "pke_zk_proof_v1";
        let bench_name = format!("tfhe_zk_pok::cuda::{bench_shortname}");
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
            let effective_t = params.t >> 1;
            let bits = (params.k as u32) * effective_t.ilog2();

            for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
                let bench_id = format!("{bench_name}::{param_name}_{bits}_bits_packed_{load}");

                let seed: u128 = rng.gen();

                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        pke::gpu::prove(
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
    }

    pub fn bench_pke_v1_verify_gpu(c: &mut Criterion) {
        let bench_shortname = "pke_zk_verify_v1";
        let bench_name = format!("tfhe_zk_pok::cuda::{bench_shortname}");
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
            let effective_t = params.t >> 1;
            let bits = (params.k as u32) * effective_t.ilog2();

            for load in [ComputeLoad::Proof, ComputeLoad::Verify] {
                let bench_id = format!("{bench_name}::{param_name}_{bits}_bits_packed_{load}");

                let seed: u128 = rng.gen();

                // Use GPU prove to generate the proof
                let proof = pke::gpu::prove(
                    (&public_param, &public_commit),
                    &private_commit,
                    &metadata,
                    load,
                    &seed.to_le_bytes(),
                );

                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        pke::gpu::verify(&proof, (&public_param, &public_commit), &metadata)
                            .unwrap();
                    })
                });

                write_to_json(&bench_id, params, param_name, bench_shortname);
            }
        }
    }
}

criterion_group!(benches_pke_v1, bench_pke_v1_verify, bench_pke_v1_prove);

#[cfg(feature = "gpu-experimental")]
use gpu::{bench_pke_v1_prove_gpu, bench_pke_v1_verify_gpu};

#[cfg(feature = "gpu-experimental")]
criterion_group!(
    benches_pke_v1_gpu,
    bench_pke_v1_verify_gpu,
    bench_pke_v1_prove_gpu
);

#[cfg(feature = "gpu-experimental")]
criterion_main!(benches_pke_v1, benches_pke_v1_gpu);

#[cfg(not(feature = "gpu-experimental"))]
criterion_main!(benches_pke_v1);
