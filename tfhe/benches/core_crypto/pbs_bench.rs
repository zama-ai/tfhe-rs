#[path = "../utilities.rs"]
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

const SHORTINT_BENCH_PARAMS_TUNIFORM: [ClassicPBSParameters; 1] =
    [PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64];

const SHORTINT_BENCH_PARAMS_GAUSSIAN: [ClassicPBSParameters; 4] = [
    V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
];

const BOOLEAN_BENCH_PARAMS: [(&str, BooleanParameters); 2] = [
    ("BOOLEAN_DEFAULT_PARAMS", DEFAULT_PARAMETERS),
    (
        "BOOLEAN_TFHE_LIB_PARAMS",
        PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    ),
];

fn benchmark_parameters_64bits() -> Vec<(String, CryptoParametersRecord<u64>)> {
    SHORTINT_BENCH_PARAMS_TUNIFORM
        .iter()
        .chain(SHORTINT_BENCH_PARAMS_GAUSSIAN.iter())
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
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            V0_11_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        ]
    } else {
        vec![
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            V0_11_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
            V0_11_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
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
            PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        ]
    } else {
        vec![
            V0_11_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            V0_11_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            V0_11_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
            V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
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
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

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

fn mem_optimized_batched_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
) {
    let bench_name = "core_crypto::batched_pbs_mem_optimized";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(10));

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

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

        let count = 10; // FIXME Is it a representative value (big enough?)

        // Allocate a new LweCiphertext and encrypt our plaintext
        let mut lwe_ciphertext_in = LweCiphertextListOwned::<Scalar>::new(
            Scalar::ZERO,
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            LweCiphertextCount(count),
            params.ciphertext_modulus.unwrap(),
        );

        encrypt_lwe_ciphertext_list(
            &input_lwe_secret_key,
            &mut lwe_ciphertext_in,
            &PlaintextList::from_container(vec![Scalar::ZERO; count]),
            params.lwe_noise_distribution.unwrap(),
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertextList::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            GlweCiphertextCount(count),
            params.ciphertext_modulus.unwrap(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertextList::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            LweCiphertextCount(count),
            params.ciphertext_modulus.unwrap(),
        );

        let mut buffers = ComputationBuffers::new();

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        buffers.resize(
            batch_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                CiphertextCount(count),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

        let id = format!("{bench_name}::{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    batch_programmable_bootstrap_lwe_ciphertext_mem_optimized(
                        &lwe_ciphertext_in,
                        &mut out_pbs_ct,
                        &accumulator,
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
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

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
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

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
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    let custom_ciphertext_modulus =
        tfhe::core_crypto::prelude::CiphertextModulus::new((1 << 64) - (1 << 32) + 1);

    for (name, params) in throughput_benchmark_parameters_64bits().iter_mut() {
        if let (Some(lwe_noise), Some(glwe_noise)) = (
            params.lwe_noise_distribution,
            params.glwe_noise_distribution,
        ) {
            match (lwe_noise, glwe_noise) {
                (DynamicDistribution::Gaussian(_), DynamicDistribution::Gaussian(_)) => (),
                _ => {
                    println!(
                        "Skip {name} parameters set: custom modulus generation is not supported"
                    );
                    continue;
                }
            }
        };

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
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

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
    use tfhe::core_crypto::gpu::vec::{CudaVec, GpuIndex};
    use tfhe::core_crypto::gpu::{
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext,
        cuda_programmable_bootstrap_lwe_ciphertext, CudaStreams,
    };
    use tfhe::core_crypto::prelude::*;
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    };
    use tfhe::shortint::{ClassicPBSParameters, PBSParameters};

    const SHORTINT_CUDA_BENCH_PARAMS: [ClassicPBSParameters; 14] = [
        // TUniform
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        // Gaussian
        V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        V0_11_PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
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
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let stream = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

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
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let stream = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

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
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let stream = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

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
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let stream = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

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
    mem_optimized_batched_pbs(&mut criterion, &benchmark_parameters_64bits());
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

#[cfg(not(feature = "gpu"))]
criterion_main!(pbs_group, multi_bit_pbs_group, pbs_throughput_group);
#[cfg(feature = "gpu")]
criterion_main!(
    cuda_pbs_group,
    cuda_multi_bit_pbs_group,
    cuda_pbs_throughput_group,
    cuda_multi_bit_pbs_throughput_group
);
