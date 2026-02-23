use benchmark::params_aliases::*;
use benchmark::utilities::{
    get_bench_type, throughput_num_threads, write_to_json, BenchmarkType, OperatorType,
};
use criterion::{criterion_group, Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use std::env;
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

struct ProofConfig {
    crs_size: usize,
    bits_to_prove: Vec<usize>,
}

impl ProofConfig {
    fn new(crs_size: usize, bits_to_prove: &[usize]) -> Self {
        Self {
            crs_size,
            bits_to_prove: bits_to_prove.to_vec(),
        }
    }
}

fn default_proof_config() -> Vec<ProofConfig> {
    let conf = vec![
        ProofConfig::new(64, &[64]),
        ProofConfig::new(2048, &[64, 4 * 64, 2048]),
        ProofConfig::new(4096, &[4096]),
    ];

    if let Ok(val) = env::var("__TFHE_RS_BENCH_OP_FLAVOR").as_deref() {
        match val.to_lowercase().as_str() {
            "fast_default" | "fast" => return vec![ProofConfig::new(2048, &[64])],
            _ => (),
        }
    };

    conf
}

fn compute_load_config() -> Vec<ZkComputeLoad> {
    let conf = vec![ZkComputeLoad::Proof, ZkComputeLoad::Verify];

    if let Ok(val) = env::var("__TFHE_RS_BENCH_OP_FLAVOR").as_deref() {
        match val.to_lowercase().as_str() {
            "fast_default" | "fast" => return vec![ZkComputeLoad::Verify],
            _ => (),
        }
    };

    conf
}

fn write_result(file: &mut File, name: &str, value: usize) {
    let line = format!("{name},{value}\n");
    let error_message = format!("cannot write {name} result into file");
    file.write_all(line.as_bytes()).expect(&error_message);
}

fn zk_throughput_num_elements() -> u64 {
    // Zk verify uses pools of 32 threads for a single verification
    let pool_size = 32;
    let pool_count = (rayon::current_num_threads() as u64 / pool_size).max(1);

    // We send batches of proof large enough to be sure starvation is not an issue
    let usable_cpu_threads = pool_count * 64;

    #[cfg(feature = "gpu")]
    {
        use tfhe::core_crypto::gpu::get_number_of_gpus;
        get_number_of_gpus() as u64 * usable_cpu_threads
    }

    #[cfg(not(feature = "gpu"))]
    {
        usable_cpu_threads
    }
}

fn cpu_pke_zk_proof(c: &mut Criterion) {
    let bench_name = "integer::zk::pke_zk_proof";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    for (param_pke, _param_casting, param_fhe) in [(
        BENCH_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )] {
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
        metadata.fill_with(|| rng.gen());

        let zk_vers = param_pke.zk_scheme;

        for proof_config in default_proof_config().iter() {
            let msg_bits =
                (param_pke.message_modulus.0 * param_pke.carry_modulus.0).ilog2() as usize;
            println!("Generating CRS... ");
            let crs_size = proof_config.crs_size;
            let crs = CompactPkeCrs::from_shortint_params(
                param_pke,
                LweCiphertextCount(crs_size / msg_bits),
            )
            .unwrap();

            for bits in proof_config.bits_to_prove.iter() {
                assert_eq!(bits % 64, 0);
                // Packing, so we take the message and carry modulus to compute our block count
                let num_block = 64usize.div_ceil(msg_bits);

                let fhe_uint_count = bits / 64;

                for compute_load in compute_load_config() {
                    let zk_load = match compute_load {
                        ZkComputeLoad::Proof => "compute_load_proof",
                        ZkComputeLoad::Verify => "compute_load_verify",
                    };

                    let bench_id;

                    match get_bench_type() {
                        BenchmarkType::Latency => {
                            bench_id = format!(
                                "{bench_name}::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                            );
                            bench_group.bench_function(&bench_id, |b| {
                                let input_msg = rng.gen::<u64>();
                                let messages = vec![input_msg; fhe_uint_count];

                                b.iter(|| {
                                    let _ct1 =
                                        tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                                            .extend(messages.iter().copied())
                                            .build_with_proof_packed(&crs, &metadata, compute_load)
                                            .unwrap();
                                })
                            });
                        }
                        BenchmarkType::Throughput => {
                            // The zk proof is currently not pooled, so we simply use the number of
                            // threads as heuristic for the batch size
                            let elements = (rayon::current_num_threads() / num_block).max(1) + 1;
                            bench_group.throughput(Throughput::Elements(elements as u64));

                            bench_id = format!(
                                "{bench_name}::throughput::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
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
    }

    bench_group.finish()
}

criterion_group!(zk_proof, cpu_pke_zk_proof);

fn cpu_pke_zk_verify(c: &mut Criterion, results_file: &Path) {
    let bench_name = "integer::zk::pke_zk_verify";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    File::create(results_file).expect("create results file failed");
    let mut file = OpenOptions::new()
        .append(true)
        .open(results_file)
        .expect("cannot open results file");

    for (param_pke, param_casting, param_fhe) in [(
        BENCH_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )] {
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
        metadata.fill_with(|| rng.gen());

        let zk_vers = param_pke.zk_scheme;

        for proof_config in default_proof_config().iter() {
            let msg_bits =
                (param_pke.message_modulus.0 * param_pke.carry_modulus.0).ilog2() as usize;
            println!("Generating CRS... ");
            let crs_size = proof_config.crs_size;
            let crs = CompactPkeCrs::from_shortint_params(
                param_pke,
                LweCiphertextCount(crs_size / msg_bits),
            )
            .unwrap();

            for bits in proof_config.bits_to_prove.iter() {
                assert_eq!(bits % 64, 0);
                // Packing, so we take the message and carry modulus to compute our block count
                let num_block = 64usize.div_ceil(msg_bits);

                let fhe_uint_count = bits / 64;

                let shortint_params: PBSParameters = param_fhe.into();

                let crs_data = bincode::serialize(&crs).unwrap();

                println!("CRS size: {}", crs_data.len());

                let test_name =
                    format!("zk::crs_sizes::{param_name}::{bits}_bits_packed_ZK{zk_vers:?}");

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

                for compute_load in compute_load_config() {
                    let zk_load = match compute_load {
                        ZkComputeLoad::Proof => "compute_load_proof",
                        ZkComputeLoad::Verify => "compute_load_verify",
                    };

                    let bench_id_verify;
                    let bench_id_verify_and_expand;

                    match get_bench_type() {
                        BenchmarkType::Latency => {
                            bench_id_verify = format!(
                            "{bench_name}::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                        );
                            bench_id_verify_and_expand = format!(
                            "{bench_name}_and_expand::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                        );

                            let input_msg = rng.gen::<u64>();
                            let messages = vec![input_msg; fhe_uint_count];

                            println!("Generating proven ciphertext ({zk_load})... ");
                            let ct1 = tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                                .extend(messages.iter().copied())
                                .build_with_proof_packed(&crs, &metadata, compute_load)
                                .unwrap();

                            let proven_ciphertext_list_serialized =
                                bincode::serialize(&ct1).unwrap();

                            println!(
                                "proven list size: {}",
                                proven_ciphertext_list_serialized.len()
                            );

                            let test_name = format!(
                            "zk::proven_list_size::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
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
                            format!("zk::proof_sizes::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}");

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

                            bench_id_verify = format!(
                            "{bench_name}::throughput::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                        );
                            bench_id_verify_and_expand = format!(
                            "{bench_name}_and_expand::throughput::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                        );

                            println!("Generating proven ciphertexts list ({zk_load})... ");

                            let verify_elements = zk_throughput_num_elements();
                            let messages = (0..verify_elements)
                                .map(|_| {
                                    let input_msg = rng.gen::<u64>();
                                    vec![input_msg; fhe_uint_count]
                                })
                                .collect::<Vec<_>>();

                            let cts = messages
                                .par_iter()
                                .map(|messages| {
                                    tfhe::integer::ProvenCompactCiphertextList::builder(&pk)
                                        .extend(messages.iter().copied())
                                        .build_with_proof_packed(&crs, &metadata, compute_load)
                                        .unwrap()
                                })
                                .collect::<Vec<_>>();

                            reset_pbs_count();
                            cts[0].verify_and_expand(
                                &crs,
                                &pk,
                                &metadata,
                                IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
                                    casting_key.as_view(),
                                ),
                            ).unwrap();
                            let pbs_count = get_pbs_count().max(1);
                            let expand_elements = throughput_num_threads(num_block, pbs_count) * 2;
                            let verify_expand_elements = expand_elements.min(verify_elements);

                            bench_group.throughput(Throughput::Elements(verify_elements));
                            bench_group.bench_function(&bench_id_verify, |b| {
                                b.iter(|| {
                                    cts.par_iter().for_each(|ct1| {
                                        ct1.verify(&crs, &pk, &metadata);
                                    })
                                });
                            });

                            bench_group.throughput(Throughput::Elements(verify_expand_elements));
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
    }

    bench_group.finish()
}

#[cfg(all(feature = "gpu", feature = "zk-pok"))]
mod cuda {
    use super::*;
    use benchmark::utilities::{cuda_local_streams, get_param_type, ParamType};
    use criterion::BatchSize;
    use itertools::Itertools;
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::integer::gpu::key_switching_key::{CudaKeySwitchingKey, CudaKeySwitchingKeyMaterial};
    use tfhe::integer::gpu::zk::CudaProvenCompactCiphertextList;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::CompressedServerKey;

    fn gpu_pke_zk_verify(c: &mut Criterion, results_file: &Path) {
        let bench_name = "integer::cuda::zk::pke_zk_verify";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));

        File::create(results_file).expect("create results file failed");
        let mut file = OpenOptions::new()
            .append(true)
            .open(results_file)
            .expect("cannot open results file");

        let (param_pke, param_ksk, param_fhe): (
            CompactPublicKeyEncryptionParameters,
            ShortintKeySwitchingParameters,
            tfhe::shortint::AtomicPatternParameters,
        ) = match get_param_type() {
            ParamType::Classical => (
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            _ => (
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
        };

        let param_name = param_fhe.name();
        let param_name = param_name.as_str();
        let cks = ClientKey::new(param_fhe);
        let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
        let sk = compressed_server_key.decompress();

        let compact_private_key = CompactPrivateKey::new(param_pke);
        let pk = CompactPublicKey::new(&compact_private_key);
        let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), param_ksk);

        // We have a use case with 320 bits of metadata
        let mut metadata = [0u8; (320 / u8::BITS) as usize];
        let mut rng = rand::rng();
        metadata.fill_with(|| rng.gen());

        let zk_vers = param_pke.zk_scheme;

        for proof_config in default_proof_config().iter() {
            let msg_bits =
                (param_pke.message_modulus.0 * param_pke.carry_modulus.0).ilog2() as usize;
            println!("Generating CRS... ");
            let crs_size = proof_config.crs_size;
            let crs = CompactPkeCrs::from_shortint_params(
                param_pke,
                LweCiphertextCount(crs_size / msg_bits),
            )
            .unwrap();

            use rand::Rng;
            let mut rng = rand::rng();

            for bits in proof_config.bits_to_prove.iter() {
                assert_eq!(bits % 64, 0);
                // Packing, so we take the message and carry modulus to compute our block count
                let num_block = 64usize.div_ceil(msg_bits);

                let fhe_uint_count = bits / 64;

                let crs_data = bincode::serialize(&crs).unwrap();

                println!("CRS size: {}", crs_data.len());

                let test_name =
                    format!("zk::crs_sizes::{param_name}::{bits}_bits_packed_ZK{zk_vers:?}");

                write_result(&mut file, &test_name, crs_data.len());
                write_to_json::<u64, _>(
                    &test_name,
                    param_fhe,
                    param_name,
                    "pke_zk_crs",
                    &OperatorType::Atomic,
                    0,
                    vec![],
                );

                for compute_load in compute_load_config() {
                    let zk_load = match compute_load {
                        ZkComputeLoad::Proof => "compute_load_proof",
                        ZkComputeLoad::Verify => "compute_load_verify",
                    };

                    let bench_id_verify;
                    let bench_id_verify_and_expand;
                    let bench_id_expand_without_verify;

                    match get_bench_type() {
                        BenchmarkType::Latency => {
                            let streams = CudaStreams::new_multi_gpu();
                            let gpu_sks = CudaServerKey::decompress_from_cpu(
                                &compressed_server_key,
                                &streams,
                            );
                            let d_ksk_material =
                                CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
                            let d_ksk = CudaKeySwitchingKey::from_cuda_key_switching_key_material(
                                &d_ksk_material,
                                &gpu_sks,
                            );

                            bench_id_verify = format!(
                                    "{bench_name}::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                                );
                            bench_id_verify_and_expand = format!(
                                    "{bench_name}_and_expand::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                                );
                            bench_id_expand_without_verify = format!(
                                    "{bench_name}_only_expand::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                                );

                            let input_msg = rng.gen::<u64>();
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
                                    "zk::proven_list_size::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                                );

                            write_result(
                                &mut file,
                                &test_name,
                                proven_ciphertext_list_serialized.len(),
                            );
                            write_to_json::<u64, _>(
                                &test_name,
                                param_fhe,
                                param_name,
                                "pke_zk_proof",
                                &OperatorType::Atomic,
                                0,
                                vec![],
                            );

                            let proof_size = ct1.proof_size();
                            println!("proof size: {}", ct1.proof_size());

                            let test_name =
                                    format!("zk::proof_sizes::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}");

                            write_result(&mut file, &test_name, proof_size);
                            write_to_json::<u64, _>(
                                &test_name,
                                param_fhe,
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
                            let mut elements_per_gpu = 100;
                            if *bits == 4096 {
                                elements_per_gpu /= 5;
                            }
                            // This value, found empirically, ensure saturation of 8XH100 SXM5
                            let elements = elements_per_gpu * get_number_of_gpus() as u64;
                            bench_group.throughput(Throughput::Elements(elements));

                            bench_id_verify = format!(
                                    "{bench_name}::throughput::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                                );
                            bench_id_verify_and_expand = format!(
                                    "{bench_name}_and_expand::throughput::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
                                );
                            bench_id_expand_without_verify = format!(
                                    "{bench_name}_only_expand::throughput::{param_name}::{bits}_bits_packed_{crs_size}_bits_crs_{zk_load}_ZK{zk_vers:?}"
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

                            let local_streams = cuda_local_streams(num_block, elements as usize);
                            let d_ksk_material_vec = local_streams
                                .par_iter()
                                .map(|local_stream| {
                                    CudaKeySwitchingKeyMaterial::from_key_switching_key(
                                        &ksk,
                                        local_stream,
                                    )
                                })
                                .collect::<Vec<_>>();

                            bench_group.bench_function(&bench_id_verify, |b| {
                                b.iter(|| {
                                    cts.par_iter().for_each(|ct1| {
                                        ct1.verify(&crs, &pk, &metadata);
                                    })
                                });
                            });

                            bench_group.bench_function(&bench_id_expand_without_verify, |b| {
                                    let setup_encrypted_values = || {
                                        let gpu_cts = cts.iter().enumerate().map(|(i, ct)| {
                                            let local_stream = &local_streams[i % local_streams.len()];
                                            CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                                                ct, local_stream,
                                            )
                                        }).collect_vec();

                                        gpu_cts
                                    };

                                    b.iter_batched(setup_encrypted_values,
                                                   |gpu_cts| {
                                                       gpu_cts.par_iter().enumerate().for_each
                                                       (|(i, gpu_ct)| {
                                                           let local_stream = &local_streams[i % local_streams.len()];

                                                           let gpu_sk = CudaServerKey::decompress_from_cpu(&compressed_server_key, local_stream);
                                                           let d_ksk =
                                                               CudaKeySwitchingKey::from_cuda_key_switching_key_material(&d_ksk_material_vec[i % local_streams.len()], &gpu_sk);

                                                           gpu_ct
                                                               .expand_without_verification(&d_ksk, local_stream)
                                                               .unwrap();
                                                       });
                                                   }, BatchSize::SmallInput);
                                });

                            bench_group.bench_function(&bench_id_verify_and_expand, |b| {
                                    let setup_encrypted_values = || {
                                        let gpu_cts = cts.iter().enumerate().map(|(i, ct)| {
                                            CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                                                ct, &local_streams[i % local_streams.len()],
                                            )
                                        }).collect_vec();

                                        gpu_cts
                                    };

                                    b.iter_batched(setup_encrypted_values,
                                                   |gpu_cts| {
                                                       gpu_cts.par_iter().enumerate().for_each
                                                       (|(i, gpu_ct)| {
                                                           let local_stream = &local_streams[i % local_streams.len()];
                                                           let gpu_sk = CudaServerKey::decompress_from_cpu(&compressed_server_key, local_stream);
                                                           let d_ksk =
                                                               CudaKeySwitchingKey::from_cuda_key_switching_key_material(&d_ksk_material_vec[i % local_streams.len()], &gpu_sk);

                                                           gpu_ct
                                                               .verify_and_expand(
                                                                   &crs, &pk, &metadata, &d_ksk, local_stream,
                                                               )
                                                               .unwrap();
                                                       });
                                                   }, BatchSize::SmallInput);
                                });
                        }
                    }

                    for (bench_id, display_name) in [
                        (bench_id_verify, "pke_zk_verify"),
                        (bench_id_expand_without_verify, "pke_zk_verify_only_expand"),
                        (bench_id_verify_and_expand, "pke_zk_verify_and_expand"),
                    ] {
                        write_to_json::<u64, _>(
                            &bench_id,
                            param_fhe,
                            param_name,
                            display_name,
                            &OperatorType::Atomic,
                            param_fhe.message_modulus().0 as u32,
                            vec![param_fhe.message_modulus().0.ilog2(); num_block],
                        );
                    }
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

pub fn zk_verify_and_proof() {
    let results_file = Path::new("pke_zk_crs_sizes.csv");
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    cpu_pke_zk_verify(&mut criterion, results_file);
    cpu_pke_zk_proof(&mut criterion);
}

#[cfg(all(feature = "gpu", feature = "zk-pok"))]
use crate::cuda::gpu_zk_verify;

fn main() {
    #[cfg(all(feature = "gpu", feature = "zk-pok"))]
    gpu_zk_verify();
    #[cfg(not(feature = "gpu"))]
    zk_verify_and_proof();

    Criterion::default().configure_from_args().final_summary();
}
