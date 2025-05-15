use benchmark::params_aliases::*;
use benchmark::utilities::{
    get_bench_type, throughput_num_threads, write_to_json, BenchmarkType, OperatorType,
};
use criterion::{criterion_group, Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use std::cmp::max;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tfhe::core_crypto::prelude::LweCiphertextCount;
use tfhe::integer::key_switching_key::KeySwitchingKey;
use tfhe::integer::parameters::IntegerCompactCiphertextListExpansionMode;
use tfhe::integer::{ClientKey, CompactPrivateKey, CompactPublicKey, ServerKey};
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::*;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tfhe::{get_pbs_count, reset_pbs_count};

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
            BENCH_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            BENCH_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ),
        (
            BENCH_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
            BENCH_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
            BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
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
        let mut rng = rand::rng();
        metadata.fill_with(|| rng.random());

        let zk_vers = param_pke.zk_scheme;

        for bits in [64usize, 640, 1280, 4096] {
            assert_eq!(bits % 64, 0);
            // Packing, so we take the message and carry modulus to compute our block count
            let num_block = 64usize.div_ceil(
                (param_pke.message_modulus.0 * param_pke.carry_modulus.0).ilog2() as usize,
            );

            use rand::Rng;
            let mut rng = rand::rng();

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

                match get_bench_type() {
                    BenchmarkType::Latency => {
                        bench_id = format!(
                            "{bench_name}::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                        bench_group.bench_function(&bench_id, |b| {
                            let input_msg = rng.random::<u64>();
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
                        // Execute the operation once to know its cost.
                        let input_msg = rng.random::<u64>();
                        let messages = vec![input_msg; fhe_uint_count];

                        reset_pbs_count();
                        let _ = tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                            .extend(messages.iter().copied())
                            .build_with_proof_packed(&crs, &metadata, compute_load);
                        let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                        let elements = throughput_num_threads(num_block, pbs_count);
                        bench_group.throughput(Throughput::Elements(elements));

                        bench_id = format!(
                            "{bench_name}::throughput::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                        bench_group.bench_function(&bench_id, |b| {
                            let messages = (0..elements)
                                .map(|_| {
                                    let input_msg = rng.random::<u64>();
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

fn cpu_pke_zk_verify(c: &mut Criterion, results_file: &Path) {
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
            BENCH_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            BENCH_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ),
        (
            BENCH_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
            BENCH_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
            BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
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
        let mut rng = rand::rng();
        metadata.fill_with(|| rng.random());

        let zk_vers = param_pke.zk_scheme;

        for bits in [64usize, 640, 1280, 4096] {
            assert_eq!(bits % 64, 0);
            // Packing, so we take the message and carry modulus to compute our block count
            let num_block = 64usize.div_ceil(
                (param_pke.message_modulus.0 * param_pke.carry_modulus.0).ilog2() as usize,
            );

            use rand::Rng;
            let mut rng = rand::rng();

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

                match get_bench_type() {
                    BenchmarkType::Latency => {
                        bench_id_verify = format!(
                            "{bench_name}::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                        bench_id_verify_and_expand = format!(
                            "{bench_name}_and_expand::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );

                        let input_msg = rng.random::<u64>();
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

                        // Execute the operation once to know its cost.
                        let input_msg = rng.random::<u64>();
                        let messages = vec![input_msg; fhe_uint_count];
                        let ct1 = tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                            .extend(messages.iter().copied())
                            .build_with_proof_packed(&crs, &metadata, compute_load)
                            .unwrap();

                        reset_pbs_count();
                        let _ = ct1.verify_and_expand(
                            &crs,
                            &pk,
                            &metadata,
                            IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
                                casting_key.as_view(),
                            ),
                        );
                        let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                        let elements = throughput_num_threads(num_block, pbs_count);
                        bench_group.throughput(Throughput::Elements(elements));

                        bench_id_verify = format!(
                            "{bench_name}::throughput::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                        bench_id_verify_and_expand = format!(
                            "{bench_name}_and_expand::throughput::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );

                        println!("Generating proven ciphertexts list ({zk_load})... ");
                        let cts = (0..elements)
                            .map(|_| {
                                let input_msg = rng.random::<u64>();
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

#[cfg(all(feature = "gpu", feature = "zk-pok"))]
mod cuda {
    use super::*;
    use benchmark::utilities::{cuda_local_keys, cuda_local_streams};
    use criterion::BatchSize;
    use itertools::Itertools;
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::integer::gpu::key_switching_key::CudaKeySwitchingKey;
    use tfhe::integer::gpu::zk::CudaProvenCompactCiphertextList;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::CompressedServerKey;

    fn gpu_pke_zk_verify(c: &mut Criterion, results_file: &Path) {
        let bench_name = "zk::cuda::pke_zk_verify";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));

        let streams = CudaStreams::new_multi_gpu();

        File::create(results_file).expect("create results file failed");
        let mut file = OpenOptions::new()
            .append(true)
            .open(results_file)
            .expect("cannot open results file");

        for (param_pke, param_ksk, param_fhe) in [(
            PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            PARAM_GPU_MULTI_BIT_GROUP_4_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )] {
            let param_name = param_fhe.name();
            let param_name = param_name.as_str();
            let cks = ClientKey::new(param_fhe);
            let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
            let gpu_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);
            let compact_private_key = CompactPrivateKey::new(param_pke);
            let pk = CompactPublicKey::new(&compact_private_key);
            let d_ksk = CudaKeySwitchingKey::new(
                (&compact_private_key, None),
                (&cks, &gpu_sks),
                param_ksk,
                &streams,
            );

            // We have a use case with 320 bits of metadata
            let mut metadata = [0u8; (320 / u8::BITS) as usize];
            let mut rng = rand::rng();
            metadata.fill_with(|| rng.random());

            let zk_vers = param_pke.zk_scheme;

            for bits in [64usize, 640, 1280, 4096] {
                assert_eq!(bits % 64, 0);
                // Packing, so we take the message and carry modulus to compute our block count
                let num_block = 64usize.div_ceil(
                    (param_pke.message_modulus.0 * param_pke.carry_modulus.0).ilog2() as usize,
                );

                use rand::Rng;
                let mut rng = rand::rng();

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

                let test_name =
                    format!("zk::crs_sizes::{param_name}_{bits}_bits_packed_ZK{zk_vers:?}");

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
                    let bench_id_expand_without_verify;

                    match get_bench_type() {
                        BenchmarkType::Latency => {
                            bench_id_verify = format!(
                            "{bench_name}::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                            bench_id_verify_and_expand = format!(
                            "{bench_name}_and_expand::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                            bench_id_expand_without_verify = format!(
                            "{bench_name}_only_expand::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );

                            let input_msg = rng.random::<u64>();
                            let messages = vec![input_msg; fhe_uint_count];

                            println!("Generating proven ciphertext ({zk_load})... ");
                            let ct1 = tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                                .extend(messages.iter().copied())
                                .build_with_proof_packed(&crs, &metadata, compute_load)
                                .unwrap();
                            let gpu_ct1 =
                            CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                                &ct1, &streams,
                            );

                            let proven_ciphertext_list_serialized =
                                bincode::serialize(&ct1).unwrap();

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

                            bench_group.bench_function(&bench_id_expand_without_verify, |b| {
                                b.iter(|| {
                                    let _ret = gpu_ct1
                                        .expand_without_verification(&d_ksk, &streams)
                                        .unwrap();
                                });
                            });

                            bench_group.bench_function(&bench_id_verify_and_expand, |b| {
                                b.iter(|| {
                                    let _ret = gpu_ct1
                                        .verify_and_expand(&crs, &pk, &metadata, &d_ksk, &streams)
                                        .unwrap();
                                });
                            });
                        }
                        BenchmarkType::Throughput => {
                            let gpu_sks_vec = cuda_local_keys(&cks);
                            let gpu_count = get_number_of_gpus() as usize;

                            // Execute the operation once to know its cost.
                            let input_msg = rng.random::<u64>();
                            let messages = vec![input_msg; fhe_uint_count];
                            let ct1 = tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                                .extend(messages.iter().copied())
                                .build_with_proof_packed(&crs, &metadata, compute_load)
                                .unwrap();
                            let gpu_ct1 =
                            CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                                &ct1, &streams,
                            );

                            reset_pbs_count();
                            let _ =
                                gpu_ct1.verify_and_expand(&crs, &pk, &metadata, &d_ksk, &streams);
                            let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                            let elements = throughput_num_threads(num_block, pbs_count);
                            bench_group.throughput(Throughput::Elements(elements));

                            bench_id_verify = format!(
                            "{bench_name}::throughput::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                            bench_id_verify_and_expand = format!(
                            "{bench_name}_and_expand::throughput::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                            bench_id_expand_without_verify = format!(
                            "{bench_name}_only_expand::throughput::{param_name}_{bits}_bits_packed_{zk_load}_ZK{zk_vers:?}"
                        );
                            println!("Generating proven ciphertexts list ({zk_load})... ");
                            let cts = (0..elements)
                                .map(|_| {
                                    let input_msg = rng.random::<u64>();
                                    let messages = vec![input_msg; fhe_uint_count];
                                    tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                                        .extend(messages.iter().copied())
                                        .build_with_proof_packed(&crs, &metadata, compute_load)
                                        .unwrap()
                                })
                                .collect::<Vec<_>>();

                            let local_streams = cuda_local_streams(num_block, elements as usize);
                            let d_ksk_vec = gpu_sks_vec
                                .par_iter()
                                .zip(local_streams.par_iter())
                                .map(|(gpu_sks, local_stream)| {
                                    CudaKeySwitchingKey::new(
                                        (&compact_private_key, None),
                                        (&cks, gpu_sks),
                                        param_ksk,
                                        local_stream,
                                    )
                                })
                                .collect::<Vec<_>>();

                            assert_eq!(d_ksk_vec.len(), gpu_count);

                            bench_group.bench_function(&bench_id_verify, |b| {
                                b.iter(|| {
                                    cts.par_iter().for_each(|ct1| {
                                        ct1.verify(&crs, &pk, &metadata);
                                    })
                                });
                            });

                            bench_group.bench_function(&bench_id_expand_without_verify, |b| {
                                    let setup_encrypted_values = || {
                                        let local_streams = cuda_local_streams(num_block, elements as usize);

                                        let gpu_cts = cts.iter().enumerate().map(|(i, ct)| {
                                            CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                                                ct, &local_streams[i],
                                            )
                                        }).collect_vec();

                                        (gpu_cts, local_streams)
                                    };

                                b.iter_batched(setup_encrypted_values, |(gpu_cts, local_streams)| {
                                    gpu_cts.par_iter()
                                        .zip(local_streams.par_iter())
                                        .enumerate()
                                        .for_each(|(i, (gpu_ct, local_stream))| {
                                            gpu_ct
                                                .expand_without_verification(&d_ksk_vec[i % gpu_count], local_stream)
                                                .unwrap();
                                    });
                                }, BatchSize::SmallInput);
                            });

                            bench_group.bench_function(&bench_id_verify_and_expand, |b| {
                                    let setup_encrypted_values = || {
                                        let local_streams = cuda_local_streams(num_block, elements as usize);

                                        let gpu_cts = cts.iter().enumerate().map(|(i, ct)| {
                                            CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                                                ct, &local_streams[i],
                                            )
                                        }).collect_vec();

                                        (gpu_cts, local_streams)
                                    };

                                b.iter_batched(setup_encrypted_values, |(gpu_cts, local_streams)| {
                                       gpu_cts
                                           .par_iter()
                                           .zip(local_streams.par_iter())
                                           .for_each(|(gpu_ct, local_stream)| {
                                               gpu_ct
                                                   .verify_and_expand(
                                                       &crs, &pk, &metadata, &d_ksk, local_stream
                                                   )
                                                   .unwrap();
                                    });
                                }, BatchSize::SmallInput);
                            });
                        }
                    }

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

    pub fn gpu_zk_verify() {
        let results_file = Path::new("gpu_pke_zk_crs_sizes.csv");
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        gpu_pke_zk_verify(&mut criterion, results_file);
    }
}

pub fn zk_verify() {
    let results_file = Path::new("pke_zk_crs_sizes.csv");
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    cpu_pke_zk_verify(&mut criterion, results_file);
}

#[cfg(all(feature = "gpu", feature = "zk-pok"))]
use crate::cuda::gpu_zk_verify;

fn main() {
    #[cfg(all(feature = "gpu", feature = "zk-pok"))]
    gpu_zk_verify();
    #[cfg(not(feature = "gpu"))]
    zk_verify();

    Criterion::default().configure_from_args().final_summary();
}
