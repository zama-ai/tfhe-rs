#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{throughput_num_threads, BenchmarkType, BENCH_TYPE};
use criterion::{criterion_group, Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tfhe::core_crypto::prelude::LweCiphertextCount;
use tfhe::integer::key_switching_key::KeySwitchingKey;
use tfhe::integer::parameters::IntegerCompactCiphertextListExpansionMode;
use tfhe::integer::{ClientKey, CompactPrivateKey, CompactPublicKey, ServerKey};
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::classic::tuniform::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::{
    V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V0_11_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1,
};
use tfhe::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::{
    V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V0_11_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1,
};
use tfhe::shortint::parameters::PBSParameters;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use utilities::{write_to_json, OperatorType};

fn write_result(file: &mut File, name: &str, value: usize) {
    let line = format!("{name},{value}\n");
    let error_message = format!("cannot write {name} result into file");
    file.write_all(line.as_bytes()).expect(&error_message);
}

fn pke_zk_proof(c: &mut Criterion) {
    let bench_name = "zk::pke_zk_proof";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    for (param_pke, _param_casting, param_fhe) in [
        (
            V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ),
        (
            V0_11_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1,
            V0_11_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ),
    ] {
        let param_name = param_fhe.name();
        let param_name = param_name.as_str();
        let cks = ClientKey::new(param_fhe);
        let sks = ServerKey::new_radix_server_key(&cks);
        let compact_private_key = CompactPrivateKey::new(param_pke);
        let pk = CompactPublicKey::new(&compact_private_key);
        // Kept for consistency
        let _casting_key =
            KeySwitchingKey::new((&compact_private_key, None), (&cks, &sks), _param_casting);

        // We have a use case with 320 bits of metadata
        let mut metadata = [0u8; (320 / u8::BITS) as usize];
        let mut rng = rand::thread_rng();
        metadata.fill_with(|| rng.gen());

        let zk_vers = param_pke.zk_scheme;

        for bits in [64usize, 640, 1280, 4096] {
            assert_eq!(bits % 64, 0);
            // Packing, so we take the message and carry modulus to compute our block count
            let num_block = 64usize.div_ceil(
                (param_pke.message_modulus.0 * param_pke.carry_modulus.0).ilog2() as usize,
            );

            use rand::Rng;
            let mut rng = rand::thread_rng();

            let fhe_uint_count = bits / 64;

            let crs = CompactPkeCrs::from_shortint_params(
                param_pke,
                LweCiphertextCount(num_block * fhe_uint_count),
            )
            .unwrap();

            for compute_load in [ZkComputeLoad::Proof, ZkComputeLoad::Verify] {
                let zk_load = match compute_load {
                    ZkComputeLoad::Proof => "compute_load_proof",
                    ZkComputeLoad::Verify => "compute_load_verify",
                };

                let bench_id;

                match BENCH_TYPE.get().unwrap() {
                    BenchmarkType::Latency => {
                        bench_id = format!(
                            "{bench_name}::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                        bench_group.bench_function(&bench_id, |b| {
                            let input_msg = rng.gen::<u64>();
                            let messages = vec![input_msg; fhe_uint_count];

                            b.iter(|| {
                                let _ct1 = tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                                    .extend(messages.iter().copied())
                                    .build_with_proof_packed(&crs, &metadata, compute_load)
                                    .unwrap();
                            })
                        });
                    }
                    BenchmarkType::Throughput => {
                        let elements = throughput_num_threads(num_block);
                        bench_group.throughput(Throughput::Elements(elements));

                        bench_id = format!(
                            "{bench_name}::throughput::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                        bench_group.bench_function(&bench_id, |b| {
                            let messages = (0..elements)
                                .map(|_| {
                                    let input_msg = rng.gen::<u64>();
                                    vec![input_msg; fhe_uint_count]
                                })
                                .collect::<Vec<_>>();

                            b.iter(|| {
                                messages.par_iter().for_each(|msg| {
                                    tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                                        .extend(msg.iter().copied())
                                        .build_with_proof_packed(&crs, &metadata, compute_load)
                                        .unwrap();
                                })
                            })
                        });
                    }
                }

                let shortint_params: PBSParameters = param_fhe.into();

                write_to_json::<u64, _>(
                    &bench_id,
                    shortint_params,
                    param_name,
                    "pke_zk_proof",
                    &OperatorType::Atomic,
                    shortint_params.message_modulus().0 as u32,
                    vec![shortint_params.message_modulus().0.ilog2(); num_block],
                );
            }
        }
    }

    bench_group.finish()
}

criterion_group!(zk_proof, pke_zk_proof);

fn pke_zk_verify(c: &mut Criterion, results_file: &Path) {
    let bench_name = "zk::pke_zk_verify";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    File::create(results_file).expect("create results file failed");
    let mut file = OpenOptions::new()
        .append(true)
        .open(results_file)
        .expect("cannot open results file");

    for (param_pke, param_casting, param_fhe) in [
        (
            V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ),
        (
            V0_11_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1,
            V0_11_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ),
    ] {
        let param_name = param_fhe.name();
        let param_name = param_name.as_str();
        let cks = ClientKey::new(param_fhe);
        let sks = ServerKey::new_radix_server_key(&cks);
        let compact_private_key = CompactPrivateKey::new(param_pke);
        let pk = CompactPublicKey::new(&compact_private_key);
        let casting_key =
            KeySwitchingKey::new((&compact_private_key, None), (&cks, &sks), param_casting);

        // We have a use case with 320 bits of metadata
        let mut metadata = [0u8; (320 / u8::BITS) as usize];
        let mut rng = rand::thread_rng();
        metadata.fill_with(|| rng.gen());

        let zk_vers = param_pke.zk_scheme;

        for bits in [64usize, 640, 1280, 4096] {
            assert_eq!(bits % 64, 0);
            // Packing, so we take the message and carry modulus to compute our block count
            let num_block = 64usize.div_ceil(
                (param_pke.message_modulus.0 * param_pke.carry_modulus.0).ilog2() as usize,
            );

            use rand::Rng;
            let mut rng = rand::thread_rng();

            let fhe_uint_count = bits / 64;

            println!("Generating CRS... ");
            let crs = CompactPkeCrs::from_shortint_params(
                param_pke,
                LweCiphertextCount(num_block * fhe_uint_count),
            )
            .unwrap();

            let shortint_params: PBSParameters = param_fhe.into();

            let crs_data = bincode::serialize(&crs).unwrap();

            println!("CRS size: {}", crs_data.len());

            let test_name = format!("zk::crs_sizes::{param_name}_{bits}_bits_packed_ZK{zk_vers:?}");

            write_result(&mut file, &test_name, crs_data.len());
            write_to_json::<u64, _>(
                &test_name,
                shortint_params,
                param_name,
                "pke_zk_crs",
                &OperatorType::Atomic,
                0,
                vec![],
            );

            for compute_load in [ZkComputeLoad::Proof, ZkComputeLoad::Verify] {
                let zk_load = match compute_load {
                    ZkComputeLoad::Proof => "compute_load_proof",
                    ZkComputeLoad::Verify => "compute_load_verify",
                };

                let bench_id_verify;
                let bench_id_verify_and_expand;

                match BENCH_TYPE.get().unwrap() {
                    BenchmarkType::Latency => {
                        bench_id_verify = format!(
                            "{bench_name}::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                        bench_id_verify_and_expand = format!(
                            "{bench_name}_and_expand::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );

                        let input_msg = rng.gen::<u64>();
                        let messages = vec![input_msg; fhe_uint_count];

                        println!("Generating proven ciphertext ({zk_load})... ");
                        let ct1 = tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                            .extend(messages.iter().copied())
                            .build_with_proof_packed(&crs, &metadata, compute_load)
                            .unwrap();

                        let proven_ciphertext_list_serialized = bincode::serialize(&ct1).unwrap();

                        println!(
                            "proven list size: {}",
                            proven_ciphertext_list_serialized.len()
                        );

                        let test_name = format!(
                            "zk::proven_list_size::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );

                        write_result(
                            &mut file,
                            &test_name,
                            proven_ciphertext_list_serialized.len(),
                        );
                        write_to_json::<u64, _>(
                            &test_name,
                            shortint_params,
                            param_name,
                            "pke_zk_proof",
                            &OperatorType::Atomic,
                            0,
                            vec![],
                        );

                        let proof_size = ct1.proof_size();
                        println!("proof size: {}", ct1.proof_size());

                        let test_name =
                            format!("zk::proof_sizes::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}");

                        write_result(&mut file, &test_name, proof_size);
                        write_to_json::<u64, _>(
                            &test_name,
                            shortint_params,
                            param_name,
                            "pke_zk_proof",
                            &OperatorType::Atomic,
                            0,
                            vec![],
                        );

                        bench_group.bench_function(&bench_id_verify, |b| {
                            b.iter(|| {
                                let _ret = ct1.verify(&crs, &pk, &metadata);
                            });
                        });

                        bench_group.bench_function(&bench_id_verify_and_expand, |b| {
                            b.iter(|| {
                                let _ret = ct1
                                    .verify_and_expand(
                                       &crs,
                                        &pk,
                                        &metadata,
                                        IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
                                            casting_key.as_view(),
                                        ),
                                    )
                                    .unwrap();
                            });
                        });
                    }
                    BenchmarkType::Throughput => {
                        // In throughput mode object sizes are not recorded.
                        let elements = throughput_num_threads(num_block);
                        bench_group.throughput(Throughput::Elements(elements));

                        bench_id_verify = format!(
                            "{bench_name}::throughput::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                        bench_id_verify_and_expand = format!(
                            "{bench_name}_and_expand::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );

                        println!("Generating proven ciphertexts list ({zk_load})... ");
                        let cts = (0..elements)
                            .map(|_| {
                                let input_msg = rng.gen::<u64>();
                                let messages = vec![input_msg; fhe_uint_count];
                                tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                                    .extend(messages.iter().copied())
                                    .build_with_proof_packed(&crs, &metadata, compute_load)
                                    .unwrap()
                            })
                            .collect::<Vec<_>>();

                        bench_group.bench_function(&bench_id_verify, |b| {
                            b.iter(|| {
                                cts.par_iter().for_each(|ct1| {
                                    ct1.verify(&crs, &pk, &metadata);
                                })
                            });
                        });

                        bench_group.bench_function(&bench_id_verify_and_expand, |b| {
                            b.iter(|| {
                                cts.par_iter().for_each(|ct1| {
                                    ct1
                                        .verify_and_expand(
                                            &crs,
                                            &pk,
                                            &metadata,
                                            IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
                                                casting_key.as_view(),
                                            ),
                                        )
                                        .unwrap();
                                })
                            });
                        });
                    }
                }

                write_to_json::<u64, _>(
                    &bench_id_verify,
                    shortint_params,
                    param_name,
                    "pke_zk_verify",
                    &OperatorType::Atomic,
                    shortint_params.message_modulus().0 as u32,
                    vec![shortint_params.message_modulus().0.ilog2(); num_block],
                );

                write_to_json::<u64, _>(
                    &bench_id_verify_and_expand,
                    shortint_params,
                    param_name,
                    "pke_zk_verify_and_expand",
                    &OperatorType::Atomic,
                    shortint_params.message_modulus().0 as u32,
                    vec![shortint_params.message_modulus().0.ilog2(); num_block],
                );
            }
        }
    }

    bench_group.finish()
}

pub fn zk_verify() {
    let results_file = Path::new("pke_zk_crs_sizes.csv");
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    pke_zk_verify(&mut criterion, results_file);
}

fn main() {
    BENCH_TYPE.get_or_init(|| BenchmarkType::from_env().unwrap());

    zk_verify();

    Criterion::default().configure_from_args().final_summary();
}
