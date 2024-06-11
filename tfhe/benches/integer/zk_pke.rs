#![allow(dead_code)]

#[path = "../utilities.rs"]
mod utilities;

use criterion::{criterion_group, criterion_main, Criterion};
use tfhe::core_crypto::prelude::*;
use tfhe::integer::{ClientKey, CompactPublicKey, ServerKey};
use tfhe::shortint::ciphertext::MaxNoiseLevel;
use tfhe::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};
// use tfhe::shortint::parameters::PBSParameters;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
// use utilities::{write_to_json, OperatorType};

// TODO to remove once casting is available
pub const PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M64: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1024),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -66.873,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
    };

fn pke_zk_proof(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("pke_zk_proof");
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    for (param_name, param_pke) in [(
        "PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M64",
        PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M64,
    )] {
        let cks_pke = ClientKey::new(param_pke);
        let pk = CompactPublicKey::new(&cks_pke);

        for bits in [640usize, 1280, 4096] {
            assert_eq!(bits % 64, 0);
            let num_block = 64usize.div_ceil(param_pke.message_modulus.0.ilog2() as usize);

            use rand::Rng;
            let mut rng = rand::thread_rng();

            let fhe_uint_count = bits / 64;

            let crs =
                CompactPkeCrs::from_shortint_params(param_pke, num_block * fhe_uint_count).unwrap();
            let public_params = crs.public_params();
            for compute_load in [ZkComputeLoad::Proof, ZkComputeLoad::Verify] {
                let zk_load = match compute_load {
                    ZkComputeLoad::Proof => "compute_load_prood",
                    ZkComputeLoad::Verify => "compute_load_verify",
                };
                let bench_id = format!("{param_name}_{bits}_bits_packed_{zk_load}");
                let input_msg = rng.gen::<u64>();
                let messages = vec![input_msg; fhe_uint_count];

                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        let _ct1 = tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                            .extend(messages.iter().copied())
                            .build_with_proof_packed(public_params, compute_load)
                            .unwrap();
                    })
                });

                // let shortint_params: PBSParameters = param_pke.into();

                // write_to_json::<u64, _>(
                //     &bench_id,
                //     shortint_params,
                //     param_name,
                //     "pke_zk_proof",
                //     &OperatorType::Atomic,
                //     shortint_params.message_modulus().0 as u32,
                //     vec![shortint_params.message_modulus().0.ilog2(); num_block],
                // );
            }
        }
    }

    bench_group.finish()
}

criterion_group!(zk_proof, pke_zk_proof);

fn pke_zk_verify(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("pke_zk_verify");
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    for (param_name, param_pke) in [(
        "PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M64",
        PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M64,
    )] {
        let cks_pke = ClientKey::new(param_pke);
        let pk = CompactPublicKey::new(&cks_pke);
        let sks = ServerKey::new_radix_server_key(&cks_pke);

        for bits in [640usize, 1280, 4096] {
            assert_eq!(bits % 64, 0);
            let num_block = 64usize.div_ceil(param_pke.message_modulus.0.ilog2() as usize);

            use rand::Rng;
            let mut rng = rand::thread_rng();

            let fhe_uint_count = bits / 64;

            let crs =
                CompactPkeCrs::from_shortint_params(param_pke, num_block * fhe_uint_count).unwrap();
            let public_params = crs.public_params();
            for compute_load in [ZkComputeLoad::Proof, ZkComputeLoad::Verify] {
                let zk_load = match compute_load {
                    ZkComputeLoad::Proof => "compute_load_prood",
                    ZkComputeLoad::Verify => "compute_load_verify",
                };
                let bench_id = format!("{param_name}_{bits}_bits_packed_{zk_load}");
                let input_msg = rng.gen::<u64>();
                let messages = vec![input_msg; fhe_uint_count];

                let ct1 = tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                    .extend(messages.iter().copied())
                    .build_with_proof_packed(public_params, compute_load)
                    .unwrap();

                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        let _ret = ct1.verify_and_expand(public_params, &pk, &sks).unwrap();
                    });
                });

                // let shortint_params: PBSParameters = param_pke.into();

                // write_to_json::<u64, _>(
                //     &bench_id,
                //     shortint_params,
                //     param_name,
                //     "pke_zk_verify",
                //     &OperatorType::Atomic,
                //     shortint_params.message_modulus().0 as u32,
                //     vec![shortint_params.message_modulus().0.ilog2(); num_block],
                // );
            }
        }
    }

    bench_group.finish()
}

criterion_group!(zk_verify, pke_zk_verify);

criterion_main!(zk_verify);
