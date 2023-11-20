#[path = "../utilities.rs"]
#[allow(dead_code)]
mod utilities;

use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
use criterion::{black_box, criterion_main, Criterion};
use rayon::prelude::*;
use serde::Serialize;
use tfhe::boolean::parameters::{
    BooleanParameters, DEFAULT_PARAMETERS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
};
use tfhe::core_crypto::commons::math::ntt::ntt64::Ntt64;
use tfhe::core_crypto::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::*;

const SHORTINT_BENCH_PARAMS: [ClassicPBSParameters; 19] = [
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
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MESSAGE_5_CARRY_0_KS_PBS,
    PARAM_MESSAGE_6_CARRY_0_KS_PBS,
    PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    PARAM_MESSAGE_8_CARRY_0_KS_PBS,
    PARAM_MESSAGE_1_CARRY_1_PBS_KS,
    PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    PARAM_MESSAGE_3_CARRY_3_PBS_KS,
    PARAM_MESSAGE_4_CARRY_4_PBS_KS,
];

const BOOLEAN_BENCH_PARAMS: [(&str, BooleanParameters); 2] = [
    ("BOOLEAN_DEFAULT_PARAMS", DEFAULT_PARAMETERS),
    (
        "BOOLEAN_TFHE_LIB_PARAMS",
        PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    ),
];

fn benchmark_parameters_64bits() -> Vec<(String, CryptoParametersRecord<u64>)> {
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
}

fn benchmark_parameters_32bits() -> Vec<(String, CryptoParametersRecord<u32>)> {
    BOOLEAN_BENCH_PARAMS
        .iter()
        .map(|(name, params)| (name.to_string(), params.to_owned().into()))
        .collect()
}

fn throughput_benchmark_parameters_64bits() -> Vec<(String, CryptoParametersRecord<u64>)> {
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
}

fn throughput_benchmark_parameters_32bits() -> Vec<(String, CryptoParametersRecord<u32>)> {
    BOOLEAN_BENCH_PARAMS
        .iter()
        .map(|(name, params)| (name.to_string(), params.to_owned().into()))
        .collect()
}

fn multi_bit_benchmark_parameters_64bits(
) -> Vec<(String, CryptoParametersRecord<u64>, LweBskGroupingFactor)> {
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
}

fn mem_optimized_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
) {
    let bench_name = "core_crypto::pbs_mem_optimized";
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

    for (name, params) in parameters.iter() {
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

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
        );

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.ciphertext_modulus.unwrap(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            params.ciphertext_modulus.unwrap(),
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

        let id = format!("{bench_name}::{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    programmable_bootstrap_lwe_ciphertext_mem_optimized(
                        &lwe_ciphertext_in,
                        &mut out_pbs_ct,
                        &accumulator.as_view(),
                        &fourier_bsk,
                        fft,
                        buffers.stack(),
                    );
                    black_box(&mut out_pbs_ct);
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
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Default + Sync + Serialize,
>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)],
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

    for (name, params, grouping_factor) in parameters.iter() {
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

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.ciphertext_modulus.unwrap(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            params.ciphertext_modulus.unwrap(),
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
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Default + Serialize + Sync,
>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)],
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

    for (name, params, grouping_factor) in parameters.iter() {
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

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.ciphertext_modulus.unwrap(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            params.ciphertext_modulus.unwrap(),
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

fn mem_optimized_pbs_ntt(c: &mut Criterion) {
    let bench_name = "core_crypto::pbs_ntt";
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

    let custom_ciphertext_modulus =
        tfhe::core_crypto::prelude::CiphertextModulus::new((1 << 64) - (1 << 32) + 1);

    for (name, params) in throughput_benchmark_parameters_64bits().iter_mut() {
        let name = format!("{name}_PLACEHOLDER_NTT");

        params.ciphertext_modulus = Some(custom_ciphertext_modulus);

        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<u64> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
                &mut secret_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

        let mut bsk = LweBootstrapKey::new(
            0u64,
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
            params.glwe_noise_distribution.unwrap(),
            &mut encryption_generator,
        );

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(0u64),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            0u64,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.ciphertext_modulus.unwrap(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            0u64,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            params.ciphertext_modulus.unwrap(),
        );

        let mut nbsk = NttLweBootstrapKeyOwned::new(
            0u64,
            bsk.input_lwe_dimension(),
            bsk.glwe_size(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
            bsk.ciphertext_modulus(),
        );

        let mut buffers = ComputationBuffers::new();

        let ntt = Ntt64::new(params.ciphertext_modulus.unwrap(), nbsk.polynomial_size());
        let ntt = ntt.as_view();

        let stack_size = programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized_requirement(
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            ntt,
        )
        .unwrap()
        .try_unaligned_bytes_required()
        .unwrap();

        buffers.resize(stack_size);

        par_convert_standard_lwe_bootstrap_key_to_ntt64(&bsk, &mut nbsk);

        drop(bsk);

        let id = format!("{bench_name}::{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized(
                        &lwe_ciphertext_in,
                        &mut out_pbs_ct,
                        &accumulator,
                        &nbsk,
                        ntt,
                        buffers.stack(),
                    );
                    black_box(&mut out_pbs_ct);
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

fn pbs_throughput<Scalar: UnsignedTorus + CastInto<usize> + Sync + Send + Serialize>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
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

    for (name, params) in parameters.iter() {
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

        const NUM_CTS: usize = 8192;
        let lwe_vec: Vec<_> = (0..NUM_CTS)
            .map(|_| {
                allocate_and_encrypt_new_lwe_ciphertext(
                    &input_lwe_secret_key,
                    Plaintext(Scalar::ZERO),
                    params.lwe_noise_distribution.unwrap(),
                    params.ciphertext_modulus.unwrap(),
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
    use super::{multi_bit_benchmark_parameters_64bits, throughput_benchmark_parameters_64bits};
    use crate::utilities::{write_to_json, CryptoParametersRecord, EnvConfig, OperatorType};
    use criterion::{black_box, Criterion};
    use serde::Serialize;
    use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
    use tfhe::core_crypto::gpu::vec::CudaVec;
    use tfhe::core_crypto::gpu::{
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext,
        cuda_programmable_bootstrap_lwe_ciphertext, CudaStreams,
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

    fn cuda_benchmark_parameters_64bits() -> Vec<(String, CryptoParametersRecord<u64>)> {
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
    }

    fn cuda_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
        c: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>)],
    ) {
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
        let stream = CudaStreams::new_single_gpu(gpu_index);

        for (name, params) in parameters.iter() {
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
                params.ciphertext_modulus.unwrap(),
            );
            let bsk_gpu = CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, &stream);

            // Allocate a new LweCiphertext and encrypt our plaintext
            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                params.lwe_noise_distribution.unwrap(),
                params.ciphertext_modulus.unwrap(),
                &mut encryption_generator,
            );
            let lwe_ciphertext_in_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &stream);

            let accumulator = GlweCiphertext::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.ciphertext_modulus.unwrap(),
            );
            let accumulator_gpu =
                CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            // Allocate the LweCiphertext to store the result of the PBS
            let out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                params.ciphertext_modulus.unwrap(),
            );
            let mut out_pbs_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&out_pbs_ct, &stream);
            let h_indexes = &[Scalar::ZERO];
            stream.synchronize();
            let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream, 0) };
            let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream, 0) };
            let mut d_lut_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream, 0) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
                d_lut_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
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
        parameters: &[(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)],
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
        let stream = CudaStreams::new_single_gpu(gpu_index);

        for (name, params, grouping_factor) in parameters.iter() {
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
                params.ciphertext_modulus.unwrap(),
            );
            let multi_bit_bsk_gpu = CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(
                &multi_bit_bsk,
                &stream,
            );

            // Allocate a new LweCiphertext and encrypt our plaintext
            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                params.lwe_noise_distribution.unwrap(),
                params.ciphertext_modulus.unwrap(),
                &mut encryption_generator,
            );
            let lwe_ciphertext_in_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &stream);

            let accumulator = GlweCiphertext::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.ciphertext_modulus.unwrap(),
            );
            let accumulator_gpu =
                CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            // Allocate the LweCiphertext to store the result of the PBS
            let out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                params.ciphertext_modulus.unwrap(),
            );
            let mut out_pbs_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&out_pbs_ct, &stream);
            let h_indexes = &[Scalar::ZERO];
            stream.synchronize();
            let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream, 0) };
            let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream, 0) };
            let mut d_lut_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream, 0) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
                d_lut_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
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
        parameters: &[(String, CryptoParametersRecord<Scalar>)],
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
        let stream = CudaStreams::new_single_gpu(gpu_index);

        for (name, params) in parameters.iter() {
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
                params.ciphertext_modulus.unwrap(),
            );
            let bsk_gpu = CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, &stream);

            const NUM_CTS: usize = 8192;
            let plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(NUM_CTS));

            let mut lwe_list = LweCiphertextList::new(
                Scalar::ZERO,
                params.lwe_dimension.unwrap().to_lwe_size(),
                LweCiphertextCount(NUM_CTS),
                params.ciphertext_modulus.unwrap(),
            );
            encrypt_lwe_ciphertext_list(
                &input_lwe_secret_key,
                &mut lwe_list,
                &plaintext_list,
                params.lwe_noise_distribution.unwrap(),
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
                params.ciphertext_modulus.unwrap(),
            );
            let accumulator_gpu =
                CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            let mut out_pbs_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&output_lwe_list, &stream);
            let mut h_indexes: [Scalar; NUM_CTS] = [Scalar::ZERO; NUM_CTS];
            let mut d_lut_indexes = unsafe { CudaVec::<Scalar>::new_async(NUM_CTS, &stream, 0) };
            unsafe {
                d_lut_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
            }
            stream.synchronize();
            for (i, index) in h_indexes.iter_mut().enumerate() {
                *index = Scalar::cast_from(i);
            }
            stream.synchronize();
            let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(NUM_CTS, &stream, 0) };
            let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(NUM_CTS, &stream, 0) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
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
        parameters: &[(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)],
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
        let stream = CudaStreams::new_single_gpu(gpu_index);

        for (name, params, grouping_factor) in parameters.iter() {
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
                params.ciphertext_modulus.unwrap(),
            );
            let multi_bit_bsk_gpu = CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(
                &multi_bit_bsk,
                &stream,
            );

            let mut num_cts: usize = 8192;
            let env_config = EnvConfig::new();
            if env_config.is_fast_bench {
                num_cts = 1024;
            }

            let plaintext_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(num_cts));
            let mut lwe_list = LweCiphertextList::new(
                Scalar::ZERO,
                params.lwe_dimension.unwrap().to_lwe_size(),
                LweCiphertextCount(num_cts),
                params.ciphertext_modulus.unwrap(),
            );
            encrypt_lwe_ciphertext_list(
                &input_lwe_secret_key,
                &mut lwe_list,
                &plaintext_list,
                params.lwe_noise_distribution.unwrap(),
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
                LweCiphertextCount(num_cts),
                params.ciphertext_modulus.unwrap(),
            );
            let lwe_ciphertext_in_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&input_lwe_list, &stream);

            let accumulator = GlweCiphertext::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.ciphertext_modulus.unwrap(),
            );
            let accumulator_gpu =
                CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            let mut out_pbs_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&output_lwe_list, &stream);
            let mut h_indexes: Vec<Scalar> = vec![Scalar::ZERO; num_cts];
            let mut d_lut_indexes = unsafe { CudaVec::<Scalar>::new_async(num_cts, &stream, 0) };
            unsafe {
                d_lut_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
            }
            stream.synchronize();
            for (i, index) in h_indexes.iter_mut().enumerate() {
                *index = Scalar::cast_from(i);
            }
            stream.synchronize();
            let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(num_cts, &stream, 0) };
            let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(num_cts, &stream, 0) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream, 0);
            }
            stream.synchronize();

            let id = format!("{bench_name}::{name}::{num_cts}chunk");
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

    pub fn cuda_pbs_group() {
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        cuda_pbs(&mut criterion, &cuda_benchmark_parameters_64bits());
    }

    pub fn cuda_pbs_throughput_group() {
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        cuda_pbs_throughput(&mut criterion, &throughput_benchmark_parameters_64bits());
    }

    pub fn cuda_multi_bit_pbs_group() {
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        cuda_multi_bit_pbs(&mut criterion, &multi_bit_benchmark_parameters_64bits());
    }

    pub fn cuda_multi_bit_pbs_throughput_group() {
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        cuda_multi_bit_pbs_throughput(&mut criterion, &multi_bit_benchmark_parameters_64bits());
    }
}

#[cfg(feature = "gpu")]
use cuda::{
    cuda_multi_bit_pbs_group, cuda_multi_bit_pbs_throughput_group, cuda_pbs_group,
    cuda_pbs_throughput_group,
};

pub fn pbs_group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    mem_optimized_pbs(&mut criterion, &benchmark_parameters_64bits());
    mem_optimized_pbs(&mut criterion, &benchmark_parameters_32bits());
    mem_optimized_pbs_ntt(&mut criterion);
}

pub fn multi_bit_pbs_group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    multi_bit_pbs(&mut criterion, &multi_bit_benchmark_parameters_64bits());
    multi_bit_deterministic_pbs(&mut criterion, &multi_bit_benchmark_parameters_64bits());
}

pub fn pbs_throughput_group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    pbs_throughput(&mut criterion, &throughput_benchmark_parameters_64bits());
    pbs_throughput(&mut criterion, &throughput_benchmark_parameters_32bits());
}

#[cfg(feature = "ly23_parallelized")]
criterion_main!(ly23_parallelized);

#[cfg(feature = "sorted_parallelized")]
criterion_main!(sorted_parallelized);

#[cfg(feature = "cms")]
criterion_main!(cms);

#[cfg(feature = "sorted")]
criterion_main!(sorted);

#[cfg(feature = "ly")]
criterion_main!(ly);

#[cfg(feature = "pbs_asiacrypt")]
criterion_main!(pbs);

#[cfg(all(not(feature = "ly23_parallelized"), not(feature = "sorted_parallelized"), not(feature = "cms"), not(feature = "sorted"),not(feature = "ly"), not(feature = "pbs_asiacrypt")))]
criterion_main!(ly23_parallelized, sorted_parallelized, cms, sorted, ly, pbs);


criterion::criterion_group!(
    name = ly23_parallelized;
    config = Criterion::default().sample_size(500);
    targets =
    pbs_ly23_parallelized,
);

criterion::criterion_group!(
    name = sorted_parallelized;
    config = Criterion::default().sample_size(500);
    targets =
    pbs_ly23_sorted_parallelized,
);

criterion::criterion_group!(
    name = cms;
    config = Criterion::default().sample_size(500);
    targets =
    ks_sorted_pbs_with_cms,
);

criterion::criterion_group!(
    name = sorted;
    config = Criterion::default().sample_size(500);
    targets =
    ks_sorted_pbs,
);

criterion::criterion_group!(
    name = ly;
    config = Criterion::default().sample_size(500);
    targets =
    ks_extended_pbs_ly23,
);

criterion::criterion_group!(
    name = pbs;
    config = Criterion::default().sample_size(500);
    targets =
    ks_pbs,
);

////////LY23///////////
struct ParametersLY23 {
    param: ClassicPBSParameters,
    log_extension_factor: u64,
}

const LY_5_40: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_5_SORTED_PBS_MS_0_EF_1_40,
    log_extension_factor: 1,
};

const LY_6_40: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_6_SORTED_PBS_MS_0_EF_3_40,
    log_extension_factor: 3,
};

const LY_7_40: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_7_SORTED_PBS_MS_0_EF_3_40,
    log_extension_factor: 3,
};

const LY_8_40: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_8_SORTED_PBS_MS_0_EF_4_40,
    log_extension_factor: 4,
};

const LY_9_40: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_9_SORTED_PBS_MS_0_EF_5_40,
    log_extension_factor: 5,
};

const LY_5_64: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_5_SORTED_PBS_MS_0_EF_2_64,
    log_extension_factor: 2,
};

const LY_6_64: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_6_SORTED_PBS_MS_0_EF_2_64,
    log_extension_factor: 2,
};

const LY_7_64: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_7_SORTED_PBS_MS_0_EF_3_64,
    log_extension_factor: 3,
};

const LY_8_64: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_8_SORTED_PBS_MS_0_EF_4_64,
    log_extension_factor: 4,
};

const LY_9_64: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_9_SORTED_PBS_MS_0_EF_5_64,
    log_extension_factor: 5,
};

const LY_5_80: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_5_SORTED_PBS_MS_0_EF_2_80,
    log_extension_factor: 2,
};

const LY_6_80: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_6_SORTED_PBS_MS_0_EF_4_80,
    log_extension_factor: 4,
};

const LY_7_81: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_7_SORTED_PBS_MS_0_EF_4_81,
    log_extension_factor: 4,
};

const LY_8_81: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_8_SORTED_PBS_MS_0_EF_5_81,
    log_extension_factor: 5,
};

const LY_9_81: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_9_SORTED_PBS_MS_0_EF_6_81,
    log_extension_factor: 6,
};

const LY_4_128: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_4_SORTED_PBS_MS_0_EF_1_128,
    log_extension_factor: 1,
};

const LY_5_128: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_5_SORTED_PBS_MS_0_EF_2_128,
    log_extension_factor: 2,
};

const LY_6_129: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_6_SORTED_PBS_MS_0_EF_3_129,
    log_extension_factor: 3,
};

const LY_7_128: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_7_SORTED_PBS_MS_0_EF_4_128,
    log_extension_factor: 4,
};

const LY_8_128: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_8_SORTED_PBS_MS_0_EF_5_128,
    log_extension_factor: 5,
};

const LY_9_129: ParametersLY23 = ParametersLY23 {
    param: PARAM_MESSAGE_9_SORTED_PBS_MS_0_EF_6_129,
    log_extension_factor: 6,
};

const PARAM_BENCHES_LY23: [ParametersLY23; 16] = [
    //LY_5_40, LY_6_40, LY_7_40, LY_8_40, LY_9_40,
    LY_5_64, LY_6_64, LY_7_64, LY_8_64, LY_9_64,
    LY_5_80, LY_6_80, LY_7_81, LY_8_81, LY_9_81,
    LY_4_128, LY_5_128, LY_6_129, LY_7_128, LY_8_128, LY_9_129,
];

struct ParametersLY23MS{
    param: ClassicPBSParameters,
    log_extension_factor: u64,
    shortcut_coeff: usize
}
const LY_5_40_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_5_BEST_PBS_MS_20_EF_1_40,
    log_extension_factor: 1,
    shortcut_coeff: 20,
};

const LY_6_40_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_6_BEST_PBS_MS_1_EF_3_40,
    log_extension_factor: 3,
    shortcut_coeff: 1,
};

const LY_7_40_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_7_BEST_PBS_MS_94_EF_3_40,
    log_extension_factor: 3,
    shortcut_coeff: 94,
};

const LY_8_40_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_8_BEST_PBS_MS_90_EF_4_40,
    log_extension_factor: 4,
    shortcut_coeff: 90,
};

const LY_9_40_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_9_BEST_PBS_MS_76_EF_5_40,
    log_extension_factor: 5,
    shortcut_coeff: 76,
};

const LY_5_80_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_5_BEST_PBS_MS_151_EF_2_80,
    log_extension_factor: 2,
    shortcut_coeff: 151,
};

const LY_6_80_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_6_BEST_PBS_MS_255_EF_3_80,
    log_extension_factor: 3,
    shortcut_coeff: 255,
};

const LY_7_80_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_7_BEST_PBS_MS_256_EF_4_80,
    log_extension_factor: 4,
    shortcut_coeff: 256,
};

const LY_8_80_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_8_BEST_PBS_MS_256_EF_5_80,
    log_extension_factor: 5,
    shortcut_coeff: 256,
};

const LY_9_80_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_9_BEST_PBS_MS_255_EF_6_80,
    log_extension_factor: 6,
    shortcut_coeff: 255,
};

const LY_4_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_4_BEST_PBS_MS_123_EF_1_128,
    log_extension_factor: 1,
    shortcut_coeff: 123,
};

const LY_5_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_5_BEST_PBS_MS_0_EF_2_128,
    log_extension_factor: 2,
    shortcut_coeff: 0,
};

const LY_6_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_6_BEST_PBS_MS_150_EF_3_128,
    log_extension_factor: 3,
    shortcut_coeff: 150,
};

const LY_7_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_7_BEST_PBS_MS_148_EF_4_128,
    log_extension_factor: 4,
    shortcut_coeff: 148,
};

const LY_8_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_8_BEST_PBS_MS_137_EF_5_128,
    log_extension_factor: 5,
    shortcut_coeff: 137,
};

const LY_9_128_MS: ParametersLY23MS = ParametersLY23MS {
    param: PARAM_MESSAGE_9_BEST_PBS_MS_96_EF_6_128,
    log_extension_factor: 6,
    shortcut_coeff: 96,
};



const PARAM_BENCHES_LY23_MS: [ParametersLY23MS; 11] = [
    //LY_5_40_MS, LY_6_40_MS, LY_7_40_MS, LY_8_40_MS, LY_9_40_MS,
    LY_5_80_MS, LY_6_80_MS, LY_7_80_MS, LY_8_80_MS, LY_9_80_MS,
    LY_4_128_MS, LY_5_128_MS, LY_6_128_MS, LY_7_128_MS, LY_8_128_MS, LY_9_128_MS,
];


const PARAM_CJP: [ClassicPBSParameters; 24] = [
    //PARAM_MESSAGE_2_PBS_MS_0_EF_0_40,PARAM_MESSAGE_3_PBS_MS_0_EF_0_40,PARAM_MESSAGE_4_PBS_MS_0_EF_0_40,PARAM_MESSAGE_5_PBS_MS_0_EF_0_40,
    //PARAM_MESSAGE_6_PBS_MS_0_EF_0_40,PARAM_MESSAGE_7_PBS_MS_0_EF_0_40,PARAM_MESSAGE_8_PBS_MS_0_EF_0_40,PARAM_MESSAGE_9_PBS_MS_0_EF_0_40,
    PARAM_MESSAGE_2_PBS_MS_0_EF_0_64,PARAM_MESSAGE_3_PBS_MS_0_EF_0_64,PARAM_MESSAGE_4_PBS_MS_0_EF_0_64,PARAM_MESSAGE_5_PBS_MS_0_EF_0_64,
    PARAM_MESSAGE_6_PBS_MS_0_EF_0_64,PARAM_MESSAGE_7_PBS_MS_0_EF_0_64,PARAM_MESSAGE_8_PBS_MS_0_EF_0_64,PARAM_MESSAGE_9_PBS_MS_0_EF_0_64,
    PARAM_MESSAGE_2_PBS_MS_0_EF_0_80,PARAM_MESSAGE_3_PBS_MS_0_EF_0_80,PARAM_MESSAGE_4_PBS_MS_0_EF_0_80,PARAM_MESSAGE_5_PBS_MS_0_EF_0_81,
    PARAM_MESSAGE_6_PBS_MS_0_EF_0_81,PARAM_MESSAGE_7_PBS_MS_0_EF_0_80,PARAM_MESSAGE_8_PBS_MS_0_EF_0_81,PARAM_MESSAGE_9_PBS_MS_0_EF_0_80,
    PARAM_MESSAGE_2_PBS_MS_0_EF_0_129,PARAM_MESSAGE_3_PBS_MS_0_EF_0_130,PARAM_MESSAGE_4_PBS_MS_0_EF_0_129,PARAM_MESSAGE_5_PBS_MS_0_EF_0_130,
    PARAM_MESSAGE_6_PBS_MS_0_EF_0_129,PARAM_MESSAGE_7_PBS_MS_0_EF_0_129,PARAM_MESSAGE_8_PBS_MS_0_EF_0_129,PARAM_MESSAGE_9_PBS_MS_0_EF_0_129,
];

const PARAM_BENCHES_LY23_PARALLEL: [ClassicPBSParameters; 32] = [
    PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_128,
    PARAM_MESSAGE_1_CARRY_2_PARALLEL_PBS_MS_0_EF_4_128,
    PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_MS_0_EF_4_128,
    PARAM_MESSAGE_2_CARRY_3_PARALLEL_PBS_MS_0_EF_4_128,
    PARAM_MESSAGE_3_CARRY_3_PARALLEL_PBS_MS_0_EF_4_128,
    PARAM_MESSAGE_3_CARRY_4_PARALLEL_PBS_MS_0_EF_4_128,
    PARAM_MESSAGE_4_CARRY_4_PARALLEL_PBS_MS_0_EF_4_128,
    PARAM_MESSAGE_4_CARRY_5_PARALLEL_PBS_MS_0_EF_4_128,
    PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_80,
    PARAM_MESSAGE_1_CARRY_2_PARALLEL_PBS_MS_0_EF_4_80,
    PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_MS_0_EF_4_80,
    PARAM_MESSAGE_2_CARRY_3_PARALLEL_PBS_MS_0_EF_4_80,
    PARAM_MESSAGE_3_CARRY_3_PARALLEL_PBS_MS_0_EF_4_80,
    PARAM_MESSAGE_3_CARRY_4_PARALLEL_PBS_MS_0_EF_4_80,
    PARAM_MESSAGE_4_CARRY_4_PARALLEL_PBS_MS_0_EF_4_80,
    PARAM_MESSAGE_4_CARRY_5_PARALLEL_PBS_MS_0_EF_4_80,
    PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_64,
    PARAM_MESSAGE_1_CARRY_2_PARALLEL_PBS_MS_0_EF_4_64,
    PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_MS_0_EF_4_64,
    PARAM_MESSAGE_2_CARRY_3_PARALLEL_PBS_MS_0_EF_4_64,
    PARAM_MESSAGE_3_CARRY_3_PARALLEL_PBS_MS_0_EF_4_64,
    PARAM_MESSAGE_3_CARRY_4_PARALLEL_PBS_MS_0_EF_4_64,
    PARAM_MESSAGE_4_CARRY_4_PARALLEL_PBS_MS_0_EF_4_64,
    PARAM_MESSAGE_4_CARRY_5_PARALLEL_PBS_MS_0_EF_4_64,
    PARAM_MESSAGE_1_CARRY_1_PARALLEL_PBS_MS_0_EF_4_40,
    PARAM_MESSAGE_1_CARRY_2_PARALLEL_PBS_MS_0_EF_4_40,
    PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_MS_0_EF_4_40,
    PARAM_MESSAGE_2_CARRY_3_PARALLEL_PBS_MS_0_EF_4_40,
    PARAM_MESSAGE_3_CARRY_3_PARALLEL_PBS_MS_0_EF_4_40,
    PARAM_MESSAGE_3_CARRY_4_PARALLEL_PBS_MS_0_EF_4_40,
    PARAM_MESSAGE_4_CARRY_4_PARALLEL_PBS_MS_0_EF_4_40,
    PARAM_MESSAGE_4_CARRY_5_PARALLEL_PBS_MS_0_EF_4_40,
];

fn ks_pbs(c: &mut Criterion) {
    type Scalar = u64;
    let bench_name = "KS_PBS";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for params in PARAM_CJP.iter() {

        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        // This is the 2^nu from the paper

        // Create the LweSecretKey
        let small_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension,
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut secret_generator,
            );
        let big_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension,
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
            params.pbs_base_log,
            params.pbs_level,
        );

        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &small_lwe_secret_key,
            params.ks_base_log,
            params.ks_level,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
            &mut encryption_generator,
        );

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &big_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.glwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.to_glwe_size(),
            polynomial_size,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            big_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the KS
        let mut out_ks_ct = LweCiphertext::new(
            Scalar::ZERO,
            small_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut buffers = ComputationBuffers::new();

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );

        let mut buffer = ComputationBuffers::new();
        buffer.resize(
            add_external_product_assign_mem_optimized_requirement::<u64>(
                glwe_dimension.to_glwe_size(),
                params.polynomial_size,
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );
        let msg_space = ((params.message_modulus.0 * params.carry_modulus.0) as f64).log2();
        let pfail = params.log2_p_fail;
        let id = format!("PRECISION_{msg_space}_BITS__PFAIL_2^{pfail}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    keyswitch_lwe_ciphertext(&ksk_big_to_small, &lwe_ciphertext_in, &mut out_ks_ct);
                    fourier_bsk.as_view().bootstrap(
                        out_pbs_ct.as_mut_view(),
                        out_ks_ct.as_view(),
                        accumulator.as_view(),
                        fft,
                        buffers.stack(),
                    );
                })  
            });
        }
    }
}
fn ks_sorted_pbs(c: &mut Criterion) {
    type Scalar = u64;
    let bench_name = "KS_Sorted_PBS";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for param in PARAM_BENCHES_LY23.iter() {
        let params = param.param;

        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        // This is the 2^nu from the paper
        let extension_factor = Ly23ExtensionFactor(1 << param.log_extension_factor);
        let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);
        // TODO adapt with parameters
        let shortcut_coeff_count = Ly23ShortcutCoeffCount(0);

        // Create the LweSecretKey
        let small_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension,
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut secret_generator,
            );
        let big_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension,
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
            params.pbs_base_log,
            params.pbs_level,
        );

        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &small_lwe_secret_key,
            params.ks_base_log,
            params.ks_level,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
            &mut encryption_generator,
        );


        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &big_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.to_glwe_size(),
            extended_polynomial_size,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            big_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the KS
        let mut out_ks_ct = LweCiphertext::new(
            Scalar::ZERO,
            small_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut buffers = ComputationBuffers::new();

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                extension_factor,
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );

        let msg_space = ((params.message_modulus.0 * params.carry_modulus.0) as f64).log2();
        let pfail = params.log2_p_fail;
        let extfact = param.log_extension_factor;
        let id = format!("PRECISION_{msg_space}_BITS__EXTENDED_FACTOR_2^{extfact}__PFAIL_2^{pfail}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    keyswitch_lwe_ciphertext(&ksk_big_to_small, &lwe_ciphertext_in, &mut out_ks_ct);
                    fourier_bsk.as_view().bootstrap_bergerat24(
                        out_pbs_ct.as_mut_view(),
                        out_ks_ct.as_view(),
                        accumulator.as_view(),
                        extension_factor,
                        shortcut_coeff_count,
                        fft,
                        buffers.stack(),
                    );
                })
            });
        }
    }
}
fn ks_sorted_pbs_with_cms(c: &mut Criterion) {
    type Scalar = u64;
    let bench_name = "KS_Sorted_PBS_With_CMS";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for param in PARAM_BENCHES_LY23_MS.iter() {
        let params = param.param;

        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        // This is the 2^nu from the paper
        let extension_factor = Ly23ExtensionFactor(1 << param.log_extension_factor);
        let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);
        let shortcut_coeff_count = Ly23ShortcutCoeffCount(param.shortcut_coeff);

        // Create the LweSecretKey
        let small_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension,
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut secret_generator,
            );
        let big_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension,
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
            params.pbs_base_log,
            params.pbs_level,
        );

        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &small_lwe_secret_key,
            params.ks_base_log,
            params.ks_level,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
            &mut encryption_generator,
        );

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &big_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.to_glwe_size(),
            extended_polynomial_size,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            big_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the KS
        let mut out_ks_ct = LweCiphertext::new(
            Scalar::ZERO,
            small_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut buffers = ComputationBuffers::new();

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                extension_factor,
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );

        let msg_space = ((params.message_modulus.0 * params.carry_modulus.0) as f64).log2();
        let pfail = params.log2_p_fail;
        let extfact = param.log_extension_factor;
        let cms = param.shortcut_coeff;
        let id = format!("PRECISION_{msg_space}_BITS__EXTENDED_FACTOR_2^{extfact}__CMS_{cms}__PFAIL_2^{pfail}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    keyswitch_lwe_ciphertext(&ksk_big_to_small, &lwe_ciphertext_in, &mut out_ks_ct);
                    fourier_bsk.as_view().bootstrap_bergerat24(
                        out_pbs_ct.as_mut_view(),
                        out_ks_ct.as_view(),
                        accumulator.as_view(),
                        extension_factor,
                        shortcut_coeff_count,
                        fft,
                        buffers.stack(),
                    );
                })
            });
        }
    }
}
fn ks_extended_pbs_ly23(c: &mut Criterion) {
    type Scalar = u64;
    let bench_name = "KS_Extended_PBS_LY23";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for param in PARAM_BENCHES_LY23.iter() {
        let params = param.param;

        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        // This is the 2^nu from the paper
        let extension_factor = Ly23ExtensionFactor(1 << param.log_extension_factor);
        let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);

        // Create the LweSecretKey
        let small_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension,
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut secret_generator,
            );
        let big_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension,
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
            params.pbs_base_log,
            params.pbs_level,
        );

        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &small_lwe_secret_key,
            params.ks_base_log,
            params.ks_level,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
            &mut encryption_generator,
        );


        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &big_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.to_glwe_size(),
            extended_polynomial_size,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            big_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the KS
        let mut out_ks_ct = LweCiphertext::new(
            Scalar::ZERO,
            small_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut buffers = ComputationBuffers::new();

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                extension_factor,
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );

        let msg_space = ((params.message_modulus.0 * params.carry_modulus.0) as f64).log2();
        let pfail = params.log2_p_fail;
        let extfact = param.log_extension_factor;
        let id = format!("PRECISION_{msg_space}_BITS__EXTENDED_FACTOR_2^{extfact}__PFAIL_2^{pfail}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    keyswitch_lwe_ciphertext(&ksk_big_to_small, &lwe_ciphertext_in, &mut out_ks_ct);
                    fourier_bsk.as_view().bootstrap_ly23(
                        out_pbs_ct.as_mut_view(),
                        out_ks_ct.as_view(),
                        accumulator.as_view(),
                        extension_factor,
                        fft,
                        buffers.stack(),
                    );
                })
            });
        }
    }
}

fn pbs_ly23_parallelized(c: &mut Criterion) {
    type Scalar = u64;
    let bench_name = "LY23_PBS_PARALLELIZED";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for param in PARAM_BENCHES_LY23_PARALLEL.iter() {
        let params = param;

        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        // This is the 2^nu from the paper
        let extension_factor = Ly23ExtensionFactor(1 << 4);
        let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);

        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension,
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut secret_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension,
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
            params.pbs_base_log,
            params.pbs_level,
        );

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.to_glwe_size(),
            extended_polynomial_size,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut buffers = ComputationBuffers::new();

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                extension_factor,
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );

        let mut thread_buffers = Vec::with_capacity(extension_factor.0);
        for _ in 0..extension_factor.0 {
            let mut buffer = ComputationBuffers::new();
            buffer.resize(
                programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
                    glwe_dimension.to_glwe_size(),
                    params.polynomial_size,
                    extension_factor,
                    fft,
                )
                    .unwrap()
                    .unaligned_bytes_required(),
            );
            thread_buffers.push(buffer);
        }

        let mut thread_stacks: Vec<_> = thread_buffers.iter_mut().map(|x| x.stack()).collect();

        

        let msg_space = ((params.message_modulus.0 * params.carry_modulus.0) as f64).log2();
        let pfail = params.log2_p_fail;
        let id = format!("PRECISION_{msg_space}_BITS__PFAIL_2^{pfail}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    fourier_bsk.as_view().bootstrap_ly23_parallelized(
                        out_pbs_ct.as_mut_view(),
                        lwe_ciphertext_in.as_view(),
                        accumulator.as_view(),
                        extension_factor,
                        fft,
                        buffers.stack(),
                        thread_stacks.as_mut_slice(),
                    );
                })
            });
        }
    }
}

fn pbs_ly23_sorted_parallelized(c: &mut Criterion) {
    type Scalar = u64;
    let bench_name = "SORTED_PBS_PARALLELIZED";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for param in PARAM_BENCHES_LY23_PARALLEL.iter() {
        let params = param;

        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        // This is the 2^nu from the paper
        let extension_factor = Ly23ExtensionFactor(1 << 4);
        let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);
        // TODO adapt with parameters
        let shortcut_coeff_count = Ly23ShortcutCoeffCount(0);

        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension,
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut secret_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension,
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
            params.pbs_base_log,
            params.pbs_level,
        );

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.to_glwe_size(),
            extended_polynomial_size,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut buffers = ComputationBuffers::new();

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                extension_factor,
                fft,
            )
                .unwrap()
                .unaligned_bytes_required(),
        );

        let mut thread_buffers = Vec::with_capacity(extension_factor.0);
        for _ in 0..extension_factor.0 {
            let mut buffer = ComputationBuffers::new();
            buffer.resize(
                programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
                    glwe_dimension.to_glwe_size(),
                    params.polynomial_size,
                    extension_factor,
                    fft,
                )
                    .unwrap()
                    .unaligned_bytes_required(),
            );
            thread_buffers.push(buffer);
        }

        let mut thread_stacks: Vec<_> = thread_buffers.iter_mut().map(|x| x.stack()).collect();

        let msg_space = ((params.message_modulus.0 * params.carry_modulus.0) as f64).log2();
        let pfail = params.log2_p_fail;
        let id = format!("PRECISION_{msg_space}_BITS__PFAIL_2^{pfail}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    fourier_bsk.as_view().bootstrap_ly23_parallelized_sorted(
                        out_pbs_ct.as_mut_view(),
                        lwe_ciphertext_in.as_view(),
                        accumulator.as_view(),
                        extension_factor,
                        shortcut_coeff_count,
                        fft,
                        buffers.stack(),
                        thread_stacks.as_mut_slice(),
                    );
                })
            });
        }
    }
}
