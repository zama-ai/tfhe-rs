#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rayon::prelude::*;
use serde::Serialize;
use tfhe::boolean::parameters::{
    BooleanParameters, DEFAULT_PARAMETERS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
};
use tfhe::core_crypto::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::*;

// const SHORTINT_BENCH_PARAMS: [ClassicPBSParameters; 19] = [
//     PARAM_MESSAGE_1_CARRY_0_KS_PBS,
//     PARAM_MESSAGE_1_CARRY_1_KS_PBS,
//     PARAM_MESSAGE_2_CARRY_0_KS_PBS,
//     PARAM_MESSAGE_2_CARRY_1_KS_PBS,
//     PARAM_MESSAGE_2_CARRY_2_KS_PBS,
//     PARAM_MESSAGE_3_CARRY_0_KS_PBS,
//     PARAM_MESSAGE_3_CARRY_2_KS_PBS,
//     PARAM_MESSAGE_3_CARRY_3_KS_PBS,
//     PARAM_MESSAGE_4_CARRY_0_KS_PBS,
//     PARAM_MESSAGE_4_CARRY_3_KS_PBS,
//     PARAM_MESSAGE_4_CARRY_4_KS_PBS,
//     PARAM_MESSAGE_5_CARRY_0_KS_PBS,
//     PARAM_MESSAGE_6_CARRY_0_KS_PBS,
//     PARAM_MESSAGE_7_CARRY_0_KS_PBS,
//     PARAM_MESSAGE_8_CARRY_0_KS_PBS,
//     PARAM_MESSAGE_1_CARRY_1_PBS_KS,
//     PARAM_MESSAGE_2_CARRY_2_PBS_KS,
//     PARAM_MESSAGE_3_CARRY_3_PBS_KS,
//     PARAM_MESSAGE_4_CARRY_4_PBS_KS,
// ];

// const SHORTINT_BENCH_PARAMS: [ClassicPBSParameters; 352] = ALL_SEC_PFAIL_VEC;
// const SHORTINT_BENCH_PARAMS: [ClassicPBSParameters; 8] = ALL_SEC_PFAIL_VEC_CURRENT;

const SHORTINT_BENCH_PARAMS: [ClassicPBSParameters; 4] = [
    // PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M40_SEC_128_2M40,
    // PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40_SEC_128_2M40,
    // PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS_TUNIFORM_2M40_SEC_128_2M40,
    // PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS_TUNIFORM_2M40_SEC_128_2M40,
    // PARAM_MESSAGE_1_CARRY_1_PK_PBS_KS_2M128_SEC_132,
    // PARAM_MESSAGE_1_CARRY_1_PK_KS_PBS_2M40_SEC_128,
    // PARAM_MESSAGE_1_CARRY_1_PK_PBS_KS_2M40_SEC_128,
    PARAM_MESSAGE_2_CARRY_2_PK_KS_PBS_2M80_SEC_128,
    PARAM_MESSAGE_2_CARRY_2_PK_PBS_KS_2M80_SEC_128,
    PARAM_MESSAGE_2_CARRY_2_PK_KS_PBS_2M75_SEC_132,
    PARAM_MESSAGE_2_CARRY_2_PK_PBS_KS_2M75_SEC_132,
];

const BOOLEAN_BENCH_PARAMS: [(&str, BooleanParameters); 2] = [
    ("BOOLEAN_DEFAULT_PARAMS", DEFAULT_PARAMETERS),
    (
        "BOOLEAN_TFHE_LIB_PARAMS",
        PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    ),
];

fn benchmark_parameters<Scalar: UnsignedInteger>() -> Vec<(String, CryptoParametersRecord<Scalar>)>
{
    if Scalar::BITS == 64 {
        SHORTINT_BENCH_PARAMS
            .iter()
            .map(|params| {
                (
                    params.name(),
                    <ClassicPBSParameters as Into<PBSParameters>>::into(*params)
                        .to_owned()
                        .into(),
                )
            })
            .collect()
    } else if Scalar::BITS == 32 {
        BOOLEAN_BENCH_PARAMS
            .iter()
            .map(|(name, params)| (name.to_string(), params.to_owned().into()))
            .collect()
    } else {
        vec![]
    }
}

fn throughput_benchmark_parameters<Scalar: UnsignedInteger>(
) -> Vec<(String, CryptoParametersRecord<Scalar>)> {
    let parameters = if cfg!(feature = "gpu") {
        vec![
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        ]
    } else {
        vec![
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
        ]
    };
    if Scalar::BITS == 64 {
        parameters
            .iter()
            .map(|params| {
                (
                    params.name(),
                    <ClassicPBSParameters as Into<PBSParameters>>::into(*params)
                        .to_owned()
                        .into(),
                )
            })
            .collect()
    } else if Scalar::BITS == 32 {
        BOOLEAN_BENCH_PARAMS
            .iter()
            .map(|(name, params)| (name.to_string(), params.to_owned().into()))
            .collect()
    } else {
        vec![]
    }
}

fn multi_bit_benchmark_parameters<Scalar: UnsignedInteger + Default>(
) -> Vec<(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)> {
    if Scalar::BITS == 64 {
        let parameters = if cfg!(feature = "gpu") {
            vec![
                PARAM_GPU_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
                PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            ]
        } else {
            vec![
                PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
            ]
        };

        parameters
            .iter()
            .map(|params| {
                (
                    params.name(),
                    <MultiBitPBSParameters as Into<PBSParameters>>::into(*params)
                        .to_owned()
                        .into(),
                    params.grouping_factor,
                )
            })
            .collect()
    } else {
        // For now there are no parameters available to test multi bit PBS on 32 bits.
        vec![]
    }
}

fn mem_optimized_pbs<
    Scalar: UnsignedTorus
        + CastInto<usize>
        + Serialize
        + RandomGenerable<DynamicDistribution<u64>, CustomModulus = Scalar>,
>(
    c: &mut Criterion,
) {
    let bench_name = "pbs";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(40));

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    let mut params_vec = vec![];
    let pfails = vec!["2M128", "2M40", "2M64", "2M80"];

    for (name, params) in benchmark_parameters::<Scalar>().iter() {
        let mut correct_name = name.to_string();
        if params_vec.contains(name) {
            let last_elem = params_vec.last().unwrap();
            let splited = last_elem
                .split("_")
                .map(|s| s.to_string())
                .collect::<Vec<String>>();
            let mut correct_name_splitted = splited.clone();

            let last_sec_level = splited.last().unwrap().parse::<u32>().unwrap();
            let mut pfail = splited[8].clone();
            let mut new_sec_level = last_sec_level;

            if last_sec_level < 138 {
                new_sec_level += 1;
            } else {
                new_sec_level = 128;
                let current_pfail_index = pfails.iter().position(|&r| r == pfail).unwrap();
                pfail = pfails[current_pfail_index + 1].to_string();
            }

            correct_name_splitted[8] = pfail;
            correct_name_splitted[10] = new_sec_level.to_string();
            correct_name = correct_name_splitted.join("_");
            println!(
                "---------------------------------------------------CORRECT NAME: {}",
                correct_name
            );
            params_vec.push(correct_name.to_string());
        } else {
            params_vec.push(correct_name.to_owned());
        }

        let is_ks_pbs = correct_name.contains("KS_PBS");

        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
                &mut secret_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

        let lwe_noise_distribution = params.lwe_std_dev.unwrap();

        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &output_lwe_secret_key,
            &input_lwe_secret_key,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            lwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        // // Create the empty bootstrapping key in the Fourier domain
        // let fourier_bsk = FourierLweBootstrapKey::new(
        //     params.lwe_dimension.unwrap(),
        //     params.glwe_dimension.unwrap().to_glwe_size(),
        //     params.polynomial_size.unwrap(),
        //     params.pbs_base_log.unwrap(),
        //     params.pbs_level.unwrap(),
        // );
        let mut bsk = LweBootstrapKey::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
            params.lwe_dimension.unwrap(),
            params.ciphertext_modulus.unwrap(),
        );

        par_generate_lwe_bootstrap_key(
            &input_lwe_secret_key,
            &output_glwe_secret_key,
            &mut bsk,
            lwe_noise_distribution,
            &mut encryption_generator,
        );

        let mut fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
        );

        par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);

        // let lwe_noise_distribution =
        // DynamicDistribution::new_gaussian_from_std_dev(params.lwe_std_dev.unwrap());

        let mut lwe_ciphertext_in: LweCiphertextOwned<Scalar>;
        let mut temp_ct: LweCiphertextOwned<Scalar>;
        let mut out_pbs_ct: LweCiphertextOwned<Scalar>;

        if is_ks_pbs {
            // Allocate a new LweCiphertext and encrypt our plaintext
            lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                // &input_lwe_secret_key,
                &output_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                lwe_noise_distribution,
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
                &mut encryption_generator,
            );

            temp_ct = LweCiphertext::new(
                Scalar::ZERO,
                input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );

            // Allocate the LweCiphertext to store the result of the PBS
            out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
        } else {
            lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                lwe_noise_distribution,
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
                &mut encryption_generator,
            );

            temp_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );

            // Allocate the LweCiphertext to store the result of the PBS
            out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
        }

        let accumulator = GlweCiphertext::new(
            Scalar::ONE << 62,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut buffers = ComputationBuffers::new();

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

        // let id = format!("{bench_name}::{name}");
        let id = format!("{bench_name}::{correct_name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    if is_ks_pbs {
                        keyswitch_lwe_ciphertext(
                            &ksk_big_to_small,
                            &lwe_ciphertext_in,
                            &mut temp_ct,
                        );
                        programmable_bootstrap_lwe_ciphertext_mem_optimized(
                            // &lwe_ciphertext_in,
                            &temp_ct,
                            &mut out_pbs_ct,
                            &accumulator.as_view(),
                            &fourier_bsk,
                            fft,
                            buffers.stack(),
                        );
                    } else {
                        programmable_bootstrap_lwe_ciphertext_mem_optimized(
                            &lwe_ciphertext_in,
                            // &mut out_pbs_ct,
                            &mut temp_ct,
                            &accumulator.as_view(),
                            &fourier_bsk,
                            fft,
                            buffers.stack(),
                        );
                        keyswitch_lwe_ciphertext(&ksk_big_to_small, &temp_ct, &mut out_pbs_ct);
                    }
                })
            });
        }

        let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn multi_bit_pbs<
    Scalar: UnsignedTorus
        + CastInto<usize>
        + CastFrom<usize>
        + Default
        + Sync
        + Serialize
        + RandomGenerable<DynamicDistribution<u64>, CustomModulus = Scalar>,
>(
    c: &mut Criterion,
) {
    let bench_name = "core_crypto::multi_bit_pbs";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for (name, params, grouping_factor) in multi_bit_benchmark_parameters::<Scalar>().iter() {
        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
                &mut secret_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        let multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
            *grouping_factor,
        );

        let lwe_noise_distribution = params.lwe_std_dev.unwrap();
        // DynamicDistribution::new_gaussian_from_std_dev(params.lwe_std_dev.unwrap());

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            lwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let id = format!("{bench_name}::{name}::parallelized");
        bench_group.bench_function(&id, |b| {
            b.iter(|| {
                multi_bit_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator.as_view(),
                    &multi_bit_bsk,
                    ThreadCount(10),
                    false,
                );
                black_box(&mut out_pbs_ct);
            })
        });

        let bit_size = params.message_modulus.unwrap().ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn multi_bit_deterministic_pbs<
    Scalar: UnsignedTorus
        + CastInto<usize>
        + CastFrom<usize>
        + Default
        + Serialize
        + Sync
        + RandomGenerable<DynamicDistribution<u64>, CustomModulus = Scalar>,
>(
    c: &mut Criterion,
) {
    let bench_name = "core_crypto::multi_bit_deterministic_pbs";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for (name, params, grouping_factor) in multi_bit_benchmark_parameters::<Scalar>().iter() {
        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
                &mut secret_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        let multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
            *grouping_factor,
        );

        let lwe_noise_distribution = params.lwe_std_dev.unwrap();
        // DynamicDistribution::new_gaussian_from_std_dev(params.lwe_std_dev.unwrap());

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            lwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let id = format!("{bench_name}::{name}::parallelized");
        bench_group.bench_function(&id, |b| {
            b.iter(|| {
                multi_bit_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator.as_view(),
                    &multi_bit_bsk,
                    ThreadCount(10),
                    true,
                );
                black_box(&mut out_pbs_ct);
            })
        });

        let bit_size = params.message_modulus.unwrap().ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn pbs_throughput<
    Scalar: UnsignedTorus
        + CastInto<usize>
        + Sync
        + Send
        + Serialize
        + RandomGenerable<DynamicDistribution<u64>, CustomModulus = Scalar>,
>(
    c: &mut Criterion,
) {
    let bench_name = "core_crypto::pbs_throughput";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for (name, params) in throughput_benchmark_parameters::<Scalar>().iter() {
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );

        let glwe_secret_key = GlweSecretKey::new_empty_key(
            Scalar::ZERO,
            params.glwe_dimension.unwrap(),
            params.polynomial_size.unwrap(),
        );
        let big_lwe_sk = glwe_secret_key.into_lwe_secret_key();
        let big_lwe_dimension = big_lwe_sk.lwe_dimension();

        let lwe_noise_distribution = params.lwe_std_dev.unwrap();
        // DynamicDistribution::new_gaussian_from_std_dev(params.lwe_std_dev.unwrap());

        const NUM_CTS: usize = 8192;
        let lwe_vec: Vec<_> = (0..NUM_CTS)
            .map(|_| {
                allocate_and_encrypt_new_lwe_ciphertext(
                    &input_lwe_secret_key,
                    Plaintext(Scalar::ZERO),
                    lwe_noise_distribution,
                    tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
                    &mut encryption_generator,
                )
            })
            .collect();

        let mut output_lwe_list = LweCiphertextList::new(
            Scalar::ZERO,
            big_lwe_dimension.to_lwe_size(),
            LweCiphertextCount(NUM_CTS),
            params.ciphertext_modulus.unwrap(),
        );

        let fft = Fft::new(params.polynomial_size.unwrap());
        let fft = fft.as_view();

        let mut vec_buffers: Vec<_> = (0..NUM_CTS)
            .map(|_| {
                let mut buffers = ComputationBuffers::new();
                buffers.resize(
                    programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
                        params.glwe_dimension.unwrap().to_glwe_size(),
                        params.polynomial_size.unwrap(),
                        fft,
                    )
                    .unwrap()
                    .unaligned_bytes_required(),
                );
                buffers
            })
            .collect();

        let glwe = GlweCiphertext::new(
            Scalar::ONE << 60,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.ciphertext_modulus.unwrap(),
        );

        let fbsk = FourierLweBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
        );

        for chunk_size in [1, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192] {
            let id = format!("{bench_name}::{name}::{chunk_size}chunk");
            {
                bench_group.bench_function(&id, |b| {
                    b.iter(|| {
                        lwe_vec
                            .par_iter()
                            .zip(output_lwe_list.par_iter_mut())
                            .zip(vec_buffers.par_iter_mut())
                            .take(chunk_size)
                            .for_each(|((input_lwe, mut out_lwe), buffer)| {
                                programmable_bootstrap_lwe_ciphertext_mem_optimized(
                                    input_lwe,
                                    &mut out_lwe,
                                    &glwe,
                                    &fbsk,
                                    fft,
                                    buffer.stack(),
                                );
                            });
                        black_box(&mut output_lwe_list);
                    })
                });
            }

            let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
            write_to_json(
                &id,
                *params,
                name,
                "pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }
}

#[cfg(feature = "gpu")]
mod cuda {
    use super::{multi_bit_benchmark_parameters, throughput_benchmark_parameters};
    use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
    use criterion::{black_box, criterion_group, Criterion};
    use serde::Serialize;
    use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
    use tfhe::core_crypto::gpu::vec::CudaVec;
    use tfhe::core_crypto::gpu::{
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext,
        cuda_programmable_bootstrap_lwe_ciphertext, CudaDevice, CudaStream,
    };
    use tfhe::core_crypto::prelude::*;
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::parameters::{
        PARAM_MESSAGE_1_CARRY_0_KS_PBS, PARAM_MESSAGE_1_CARRY_1_KS_PBS,
        PARAM_MESSAGE_2_CARRY_0_KS_PBS, PARAM_MESSAGE_2_CARRY_1_KS_PBS,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_0_KS_PBS,
        PARAM_MESSAGE_3_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_0_KS_PBS, PARAM_MESSAGE_4_CARRY_3_KS_PBS,
        PARAM_MESSAGE_5_CARRY_0_KS_PBS, PARAM_MESSAGE_6_CARRY_0_KS_PBS,
        PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    };
    use tfhe::shortint::{ClassicPBSParameters, PBSParameters};

    const SHORTINT_CUDA_BENCH_PARAMS: [ClassicPBSParameters; 13] = [
        PARAM_MESSAGE_1_CARRY_0_KS_PBS,
        PARAM_MESSAGE_1_CARRY_1_KS_PBS,
        PARAM_MESSAGE_2_CARRY_0_KS_PBS,
        PARAM_MESSAGE_2_CARRY_1_KS_PBS,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_0_KS_PBS,
        PARAM_MESSAGE_3_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_0_KS_PBS,
        PARAM_MESSAGE_4_CARRY_3_KS_PBS,
        PARAM_MESSAGE_5_CARRY_0_KS_PBS,
        PARAM_MESSAGE_6_CARRY_0_KS_PBS,
        PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    ];

    fn cuda_benchmark_parameters<Scalar: UnsignedInteger>(
    ) -> Vec<(String, CryptoParametersRecord<Scalar>)> {
        if Scalar::BITS == 64 {
            SHORTINT_CUDA_BENCH_PARAMS
                .iter()
                .map(|params| {
                    (
                        params.name(),
                        <ClassicPBSParameters as Into<PBSParameters>>::into(*params)
                            .to_owned()
                            .into(),
                    )
                })
                .collect()
        } else {
            vec![]
        }
    }

    fn cuda_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(c: &mut Criterion) {
        let bench_name = "core_crypto::cuda::pbs";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        for (name, params) in cuda_benchmark_parameters::<Scalar>().iter() {
            // Create the LweSecretKey
            let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                params.lwe_dimension.unwrap(),
                &mut secret_generator,
            );
            let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
                allocate_and_generate_new_binary_glwe_secret_key(
                    params.glwe_dimension.unwrap(),
                    params.polynomial_size.unwrap(),
                    &mut secret_generator,
                );
            let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

            let bsk = LweBootstrapKey::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.pbs_base_log.unwrap(),
                params.pbs_level.unwrap(),
                params.lwe_dimension.unwrap(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            let bsk_gpu = CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, &stream);

            let lwe_noise_distribution =
                DynamicDistribution::new_gaussian_from_std_dev(params.lwe_std_dev.unwrap());

            // Allocate a new LweCiphertext and encrypt our plaintext
            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                lwe_noise_distribution,
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
                &mut encryption_generator,
            );
            let lwe_ciphertext_in_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &stream);

            let accumulator = GlweCiphertext::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            let accumulator_gpu =
                CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            // Allocate the LweCiphertext to store the result of the PBS
            let out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            let mut out_pbs_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&out_pbs_ct, &stream);
            let h_indexes = &[Scalar::ZERO];
            stream.synchronize();
            let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream) };
            let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream) };
            let mut d_lut_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
                d_lut_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
            }
            stream.synchronize();

            let id = format!("{bench_name}::{name}");
            {
                bench_group.bench_function(&id, |b| {
                    b.iter(|| {
                        cuda_programmable_bootstrap_lwe_ciphertext(
                            &lwe_ciphertext_in_gpu,
                            &mut out_pbs_ct_gpu,
                            &accumulator_gpu,
                            &d_lut_indexes,
                            &d_output_indexes,
                            &d_input_indexes,
                            LweCiphertextCount(1),
                            &bsk_gpu,
                            &stream,
                        );
                        black_box(&mut out_pbs_ct_gpu);
                    })
                });
            }

            let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
            write_to_json(
                &id,
                *params,
                name,
                "pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    fn cuda_multi_bit_pbs<
        Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Default + Serialize + Sync,
    >(
        c: &mut Criterion,
    ) {
        let bench_name = "core_crypto::cuda::multi_bit_pbs";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        for (name, params, grouping_factor) in multi_bit_benchmark_parameters::<Scalar>().iter() {
            // Create the LweSecretKey
            let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                params.lwe_dimension.unwrap(),
                &mut secret_generator,
            );
            let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
                allocate_and_generate_new_binary_glwe_secret_key(
                    params.glwe_dimension.unwrap(),
                    params.polynomial_size.unwrap(),
                    &mut secret_generator,
                );
            let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

            let multi_bit_bsk = LweMultiBitBootstrapKey::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.pbs_base_log.unwrap(),
                params.pbs_level.unwrap(),
                params.lwe_dimension.unwrap(),
                *grouping_factor,
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            let multi_bit_bsk_gpu = CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(
                &multi_bit_bsk,
                &stream,
            );

            let lwe_noise_distribution =
                DynamicDistribution::new_gaussian_from_std_dev(params.lwe_std_dev.unwrap());

            // Allocate a new LweCiphertext and encrypt our plaintext
            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                lwe_noise_distribution,
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
                &mut encryption_generator,
            );
            let lwe_ciphertext_in_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &stream);

            let accumulator = GlweCiphertext::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            let accumulator_gpu =
                CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            // Allocate the LweCiphertext to store the result of the PBS
            let out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            let mut out_pbs_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&out_pbs_ct, &stream);
            let h_indexes = &[Scalar::ZERO];
            stream.synchronize();
            let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream) };
            let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream) };
            let mut d_lut_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
                d_lut_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
            }
            stream.synchronize();

            let id = format!("{bench_name}::{name}");
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                        &lwe_ciphertext_in_gpu,
                        &mut out_pbs_ct_gpu,
                        &accumulator_gpu,
                        &d_lut_indexes,
                        &d_output_indexes,
                        &d_input_indexes,
                        &multi_bit_bsk_gpu,
                        &stream,
                    );
                    black_box(&mut out_pbs_ct_gpu);
                })
            });

            let bit_size = params.message_modulus.unwrap().ilog2();
            write_to_json(
                &id,
                *params,
                name,
                "pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    fn cuda_pbs_throughput<
        Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Default + Serialize + Sync,
    >(
        c: &mut Criterion,
    ) {
        let bench_name = "core_crypto::cuda::pbs_throughput";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        for (name, params) in throughput_benchmark_parameters::<Scalar>().iter() {
            let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                params.lwe_dimension.unwrap(),
                &mut secret_generator,
            );

            let glwe_secret_key = GlweSecretKey::new_empty_key(
                Scalar::ZERO,
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
            );
            let big_lwe_sk = glwe_secret_key.into_lwe_secret_key();
            let big_lwe_dimension = big_lwe_sk.lwe_dimension();
            let bsk = LweBootstrapKey::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.pbs_base_log.unwrap(),
                params.pbs_level.unwrap(),
                params.lwe_dimension.unwrap(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            let bsk_gpu = CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, &stream);

            const NUM_CTS: usize = 8192;
            let plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(NUM_CTS));
            let lwe_noise_distribution =
                DynamicDistribution::new_gaussian_from_std_dev(params.lwe_std_dev.unwrap());

            let mut lwe_list = LweCiphertextList::new(
                Scalar::ZERO,
                params.lwe_dimension.unwrap().to_lwe_size(),
                LweCiphertextCount(NUM_CTS),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            encrypt_lwe_ciphertext_list(
                &input_lwe_secret_key,
                &mut lwe_list,
                &plaintext_list,
                lwe_noise_distribution,
                &mut encryption_generator,
            );
            let underlying_container: Vec<Scalar> = lwe_list.into_container();

            let input_lwe_list = LweCiphertextList::from_container(
                underlying_container,
                params.lwe_dimension.unwrap().to_lwe_size(),
                params.ciphertext_modulus.unwrap(),
            );

            let output_lwe_list = LweCiphertextList::new(
                Scalar::ZERO,
                big_lwe_dimension.to_lwe_size(),
                LweCiphertextCount(NUM_CTS),
                params.ciphertext_modulus.unwrap(),
            );
            let lwe_ciphertext_in_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&input_lwe_list, &stream);

            let accumulator = GlweCiphertext::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            let accumulator_gpu =
                CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            let mut out_pbs_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&output_lwe_list, &stream);
            let mut h_indexes: [Scalar; NUM_CTS] = [Scalar::ZERO; NUM_CTS];
            let mut d_lut_indexes = unsafe { CudaVec::<Scalar>::new_async(NUM_CTS, &stream) };
            unsafe {
                d_lut_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
            }
            stream.synchronize();
            for (i, index) in h_indexes.iter_mut().enumerate() {
                *index = Scalar::cast_from(i);
            }
            stream.synchronize();
            let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(NUM_CTS, &stream) };
            let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(NUM_CTS, &stream) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
            }
            stream.synchronize();

            let id = format!("{bench_name}::{name}::{NUM_CTS}chunk");
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    cuda_programmable_bootstrap_lwe_ciphertext(
                        &lwe_ciphertext_in_gpu,
                        &mut out_pbs_ct_gpu,
                        &accumulator_gpu,
                        &d_lut_indexes,
                        &d_output_indexes,
                        &d_input_indexes,
                        LweCiphertextCount(NUM_CTS),
                        &bsk_gpu,
                        &stream,
                    );
                    black_box(&mut out_pbs_ct_gpu);
                })
            });

            let bit_size = params.message_modulus.unwrap().ilog2();
            write_to_json(
                &id,
                *params,
                name,
                "pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    fn cuda_multi_bit_pbs_throughput<
        Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Default + Serialize + Sync,
    >(
        c: &mut Criterion,
    ) {
        let bench_name = "core_crypto::cuda::multi_bit_pbs_throughput";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60));

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        for (name, params, grouping_factor) in multi_bit_benchmark_parameters::<Scalar>().iter() {
            let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                params.lwe_dimension.unwrap(),
                &mut secret_generator,
            );

            let glwe_secret_key = GlweSecretKey::new_empty_key(
                Scalar::ZERO,
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
            );
            let big_lwe_sk = glwe_secret_key.into_lwe_secret_key();
            let big_lwe_dimension = big_lwe_sk.lwe_dimension();
            let multi_bit_bsk = LweMultiBitBootstrapKey::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.pbs_base_log.unwrap(),
                params.pbs_level.unwrap(),
                params.lwe_dimension.unwrap(),
                *grouping_factor,
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            let multi_bit_bsk_gpu = CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(
                &multi_bit_bsk,
                &stream,
            );

            const NUM_CTS: usize = 8192;
            let lwe_noise_distribution =
                DynamicDistribution::new_gaussian_from_std_dev(params.lwe_std_dev.unwrap());

            let plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(NUM_CTS));
            let mut lwe_list = LweCiphertextList::new(
                Scalar::ZERO,
                params.lwe_dimension.unwrap().to_lwe_size(),
                LweCiphertextCount(NUM_CTS),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            encrypt_lwe_ciphertext_list(
                &input_lwe_secret_key,
                &mut lwe_list,
                &plaintext_list,
                lwe_noise_distribution,
                &mut encryption_generator,
            );
            let underlying_container: Vec<Scalar> = lwe_list.into_container();

            let input_lwe_list = LweCiphertextList::from_container(
                underlying_container,
                params.lwe_dimension.unwrap().to_lwe_size(),
                params.ciphertext_modulus.unwrap(),
            );

            let output_lwe_list = LweCiphertextList::new(
                Scalar::ZERO,
                big_lwe_dimension.to_lwe_size(),
                LweCiphertextCount(NUM_CTS),
                params.ciphertext_modulus.unwrap(),
            );
            let lwe_ciphertext_in_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&input_lwe_list, &stream);

            let accumulator = GlweCiphertext::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            );
            let accumulator_gpu =
                CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            let mut out_pbs_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&output_lwe_list, &stream);
            let mut h_indexes: [Scalar; NUM_CTS] = [Scalar::ZERO; NUM_CTS];
            let mut d_lut_indexes = unsafe { CudaVec::<Scalar>::new_async(NUM_CTS, &stream) };
            unsafe {
                d_lut_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
            }
            stream.synchronize();
            for (i, index) in h_indexes.iter_mut().enumerate() {
                *index = Scalar::cast_from(i);
            }
            stream.synchronize();
            let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(NUM_CTS, &stream) };
            let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(NUM_CTS, &stream) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
            }
            stream.synchronize();

            let id = format!("{bench_name}::{name}::{NUM_CTS}chunk");
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                        &lwe_ciphertext_in_gpu,
                        &mut out_pbs_ct_gpu,
                        &accumulator_gpu,
                        &d_lut_indexes,
                        &d_output_indexes,
                        &d_input_indexes,
                        &multi_bit_bsk_gpu,
                        &stream,
                    );
                    black_box(&mut out_pbs_ct_gpu);
                })
            });

            let bit_size = params.message_modulus.unwrap().ilog2();
            write_to_json(
                &id,
                *params,
                name,
                "pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    criterion_group!(cuda_pbs_group, cuda_pbs::<u64>);

    criterion_group!(cuda_multi_bit_pbs_group, cuda_multi_bit_pbs::<u64>);

    criterion_group!(cuda_pbs_throughput_group, cuda_pbs_throughput::<u64>);

    criterion_group!(
        cuda_multi_bit_pbs_throughput_group,
        cuda_multi_bit_pbs_throughput::<u64>
    );
}

#[cfg(feature = "gpu")]
use cuda::{
    cuda_multi_bit_pbs_group, cuda_multi_bit_pbs_throughput_group, cuda_pbs_group,
    cuda_pbs_throughput_group,
};
use tfhe::core_crypto::algorithms::misc::check_encrypted_content_respects_mod;
use tfhe::core_crypto::commons::math::random::RandomGenerable;
use tfhe::shortint::parameters::sec_and_pfail_params::*;

criterion_group!(
    pbs_group,
    mem_optimized_pbs::<u64>,
    // mem_optimized_pbs::<u32>
);

criterion_group!(
    multi_bit_pbs_group,
    multi_bit_pbs::<u64>,
    // multi_bit_pbs::<u32>,
    multi_bit_deterministic_pbs::<u64>,
    // multi_bit_deterministic_pbs::<u32>,
);

criterion_group!(
    pbs_throughput_group,
    pbs_throughput::<u64>,
    // pbs_throughput::<u32>
);

#[cfg(not(feature = "gpu"))]
criterion_main!(pbs_group);
// criterion_main!(pbs_group, multi_bit_pbs_group, pbs_throughput_group);
#[cfg(feature = "gpu")]
criterion_main!(
    cuda_pbs_group,
    cuda_multi_bit_pbs_group,
    cuda_pbs_throughput_group,
    cuda_multi_bit_pbs_throughput_group
);
