#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{
    filter_parameters, init_parameters_set, multi_bit_num_threads, write_to_json,
    CryptoParametersRecord, DesiredBackend, DesiredNoiseDistribution, OperatorType, ParametersSet,
    PARAMETERS_SET,
};
use criterion::{black_box, Criterion};
use serde::Serialize;
use std::env;
use tfhe::core_crypto::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::current_params::*;
use tfhe::shortint::parameters::*;

const SHORTINT_BENCH_PARAMS_TUNIFORM: [ClassicPBSParameters; 4] = [
    V1_0_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
    V1_0_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
];

const SHORTINT_BENCH_PARAMS_GAUSSIAN: [ClassicPBSParameters; 4] = [
    V1_0_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
];

#[cfg(feature = "gpu")]
const SHORTINT_MULTI_BIT_BENCH_PARAMS: [MultiBitPBSParameters; 6] = [
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
];

#[cfg(not(feature = "gpu"))]
const SHORTINT_MULTI_BIT_BENCH_PARAMS: [MultiBitPBSParameters; 6] = [
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
];

fn benchmark_parameters() -> Vec<(String, CryptoParametersRecord<u64>)> {
    match PARAMETERS_SET.get().unwrap() {
        ParametersSet::Default => SHORTINT_BENCH_PARAMS_TUNIFORM
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
            .collect(),
        ParametersSet::All => {
            filter_parameters(
                &VEC_ALL_CLASSIC_PBS_PARAMETERS,
                DesiredNoiseDistribution::Both,
                DesiredBackend::Cpu, // No parameters set are specific to GPU in this vector
            )
            .into_iter()
            .map(|(params, name)| {
                (
                    name.to_string(),
                    <ClassicPBSParameters as Into<PBSParameters>>::into(*params)
                        .to_owned()
                        .into(),
                )
            })
            .collect()
        }
    }
}

fn multi_bit_benchmark_parameters(
) -> Vec<(String, CryptoParametersRecord<u64>, LweBskGroupingFactor)> {
    match PARAMETERS_SET.get().unwrap() {
        ParametersSet::Default => SHORTINT_MULTI_BIT_BENCH_PARAMS
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
            .collect(),
        ParametersSet::All => {
            let desired_backend = if cfg!(feature = "gpu") {
                DesiredBackend::Gpu
            } else {
                DesiredBackend::Cpu
            };
            filter_parameters(
                &VEC_ALL_MULTI_BIT_PBS_PARAMETERS,
                DesiredNoiseDistribution::Both,
                desired_backend,
            )
            .into_iter()
            .map(|(params, name)| {
                (
                    name.to_string(),
                    <MultiBitPBSParameters as Into<PBSParameters>>::into(*params)
                        .to_owned()
                        .into(),
                    params.grouping_factor,
                )
            })
            .collect()
        }
    }
}

fn ks_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
) {
    let bench_name = "core_crypto::ks_pbs";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30));

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

        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &output_lwe_secret_key,
            &input_lwe_secret_key,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
        );

        // Allocate a new LweCiphertext and encrypt our plaintext
        let input_ks_ct: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &output_lwe_secret_key,
            Plaintext(Scalar::ONE),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let mut output_ks_ct: LweCiphertextOwned<Scalar> = LweCiphertext::new(
            Scalar::ZERO,
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            params.ciphertext_modulus.unwrap(),
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.ciphertext_modulus.unwrap(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut output_pbs_ct = LweCiphertext::new(
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
                    keyswitch_lwe_ciphertext(&ksk_big_to_small, &input_ks_ct, &mut output_ks_ct);
                    programmable_bootstrap_lwe_ciphertext_mem_optimized(
                        &output_ks_ct,
                        &mut output_pbs_ct,
                        &accumulator.as_view(),
                        &fourier_bsk,
                        fft,
                        buffers.stack(),
                    );
                    black_box(&mut output_pbs_ct);
                })
            });
        }

        let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "ks-pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn multi_bit_ks_pbs<
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Default + Sync + Serialize,
>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)],
    deterministic_pbs: bool,
) {
    let bench_name = if deterministic_pbs {
        "core_crypto::multi_bit_deterministic_ks_pbs"
    } else {
        "core_crypto::multi_bit_ks_pbs"
    };
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30));

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

        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &output_lwe_secret_key,
            &input_lwe_secret_key,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
            *grouping_factor,
        );

        // Allocate a new LweCiphertext and encrypt our plaintext
        let input_ks_ct: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &output_lwe_secret_key,
            Plaintext(Scalar::ONE),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let mut output_ks_ct: LweCiphertextOwned<Scalar> = LweCiphertext::new(
            Scalar::ZERO,
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            params.ciphertext_modulus.unwrap(),
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.ciphertext_modulus.unwrap(),
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut output_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
            params.ciphertext_modulus.unwrap(),
        );

        let thread_count = multi_bit_num_threads(
            params.message_modulus.unwrap(),
            params.carry_modulus.unwrap(),
            grouping_factor.0,
        )
        .unwrap() as usize;

        let id = format!("{bench_name}::{name}::parallelized");
        bench_group.bench_function(&id, |b| {
            b.iter(|| {
                keyswitch_lwe_ciphertext(&ksk_big_to_small, &input_ks_ct, &mut output_ks_ct);
                multi_bit_programmable_bootstrap_lwe_ciphertext(
                    &output_ks_ct,
                    &mut output_pbs_ct,
                    &accumulator.as_view(),
                    &multi_bit_bsk,
                    ThreadCount(thread_count),
                    deterministic_pbs,
                );
                black_box(&mut output_pbs_ct);
            })
        });

        let bit_size = params.message_modulus.unwrap().ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "ks-pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

#[cfg(feature = "gpu")]
mod cuda {
    use super::{benchmark_parameters, multi_bit_benchmark_parameters};
    use crate::utilities::{
        write_to_json, CryptoParametersRecord, OperatorType, GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE,
    };
    use criterion::{black_box, Criterion};
    use serde::Serialize;
    use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
    use tfhe::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
    use tfhe::core_crypto::gpu::vec::{CudaVec, GpuIndex};
    use tfhe::core_crypto::gpu::{
        cuda_keyswitch_lwe_ciphertext, cuda_multi_bit_programmable_bootstrap_lwe_ciphertext,
        cuda_programmable_bootstrap_lwe_ciphertext, CudaStreams,
    };
    use tfhe::core_crypto::prelude::*;

    fn cuda_ks_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
        c: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>)],
    ) {
        let bench_name = "core_crypto::cuda::ks_pbs";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(10)
            .measurement_time(std::time::Duration::from_secs(30));

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

        for (name, params) in parameters.iter() {
            if params.polynomial_size.unwrap().0 > GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE {
                println!("[WARNING] polynomial size is too large for parameters set '{}' (max: {}, got: {})", name, GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE, params.polynomial_size.unwrap().0);
                continue;
            }

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

            let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
                &output_lwe_secret_key,
                &input_lwe_secret_key,
                params.ks_base_log.unwrap(),
                params.ks_level.unwrap(),
                params.lwe_noise_distribution.unwrap(),
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            );
            let ksk_big_to_small_gpu =
                CudaLweKeyswitchKey::from_lwe_keyswitch_key(&ksk_big_to_small, &stream);

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
            let input_ks_ct = allocate_and_encrypt_new_lwe_ciphertext(
                &output_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                params.lwe_noise_distribution.unwrap(),
                params.ciphertext_modulus.unwrap(),
                &mut encryption_generator,
            );
            let input_ks_ct_gpu = CudaLweCiphertextList::from_lwe_ciphertext(&input_ks_ct, &stream);

            let output_ks_ct: LweCiphertextOwned<Scalar> = LweCiphertext::new(
                Scalar::ZERO,
                input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                params.ciphertext_modulus.unwrap(),
            );
            let mut output_ks_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&output_ks_ct, &stream);

            let accumulator = GlweCiphertext::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.ciphertext_modulus.unwrap(),
            );
            let accumulator_gpu =
                CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            // Allocate the LweCiphertext to store the result of the PBS
            let output_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                params.ciphertext_modulus.unwrap(),
            );
            let mut output_pbs_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&output_pbs_ct, &stream);

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
                        cuda_keyswitch_lwe_ciphertext(
                            &ksk_big_to_small_gpu,
                            &input_ks_ct_gpu,
                            &mut output_ks_ct_gpu,
                            &d_input_indexes,
                            &d_output_indexes,
                            &stream,
                        );
                        cuda_programmable_bootstrap_lwe_ciphertext(
                            &output_ks_ct_gpu,
                            &mut output_pbs_ct_gpu,
                            &accumulator_gpu,
                            &d_lut_indexes,
                            &d_output_indexes,
                            &d_input_indexes,
                            LweCiphertextCount(1),
                            &bsk_gpu,
                            &stream,
                        );
                        black_box(&mut output_pbs_ct_gpu);
                    })
                });
            }

            let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
            write_to_json(
                &id,
                *params,
                name,
                "ks-pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    fn cuda_multi_bit_ks_pbs<
        Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Default + Serialize + Sync,
    >(
        c: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)],
    ) {
        let bench_name = "core_crypto::cuda::multi_bit_ks_pbs";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(10)
            .measurement_time(std::time::Duration::from_secs(30));

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

        for (name, params, grouping_factor) in parameters.iter() {
            if params.polynomial_size.unwrap().0 > GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE {
                println!("[WARNING] polynomial size is too large for parameters set '{}' (max: {}, got: {})", name, GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE, params.polynomial_size.unwrap().0);
                continue;
            }

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

            let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
                &output_lwe_secret_key,
                &input_lwe_secret_key,
                params.ks_base_log.unwrap(),
                params.ks_level.unwrap(),
                params.lwe_noise_distribution.unwrap(),
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            );
            let ksk_big_to_small_gpu =
                CudaLweKeyswitchKey::from_lwe_keyswitch_key(&ksk_big_to_small, &stream);

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
            let input_ks_ct = allocate_and_encrypt_new_lwe_ciphertext(
                &output_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                params.lwe_noise_distribution.unwrap(),
                params.ciphertext_modulus.unwrap(),
                &mut encryption_generator,
            );
            let input_ks_ct_gpu = CudaLweCiphertextList::from_lwe_ciphertext(&input_ks_ct, &stream);

            let output_ks_ct: LweCiphertextOwned<Scalar> = LweCiphertext::new(
                Scalar::ZERO,
                input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                params.ciphertext_modulus.unwrap(),
            );
            let mut output_ks_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&output_ks_ct, &stream);

            let accumulator = GlweCiphertext::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.ciphertext_modulus.unwrap(),
            );
            let accumulator_gpu =
                CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            // Allocate the LweCiphertext to store the result of the PBS
            let output_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                params.ciphertext_modulus.unwrap(),
            );
            let mut output_pbs_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&output_pbs_ct, &stream);

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
                    cuda_keyswitch_lwe_ciphertext(
                        &ksk_big_to_small_gpu,
                        &input_ks_ct_gpu,
                        &mut output_ks_ct_gpu,
                        &d_input_indexes,
                        &d_output_indexes,
                        &stream,
                    );
                    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                        &output_ks_ct_gpu,
                        &mut output_pbs_ct_gpu,
                        &accumulator_gpu,
                        &d_lut_indexes,
                        &d_output_indexes,
                        &d_input_indexes,
                        &multi_bit_bsk_gpu,
                        &stream,
                    );
                    black_box(&mut output_ks_ct_gpu);
                })
            });

            let bit_size = params.message_modulus.unwrap().ilog2();
            write_to_json(
                &id,
                *params,
                name,
                "ks-pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    pub fn cuda_ks_pbs_group() {
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        cuda_ks_pbs(&mut criterion, &benchmark_parameters());
    }

    pub fn cuda_multi_bit_ks_pbs_group() {
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        cuda_multi_bit_ks_pbs(&mut criterion, &multi_bit_benchmark_parameters());
    }
}

#[cfg(feature = "gpu")]
use cuda::{cuda_ks_pbs_group, cuda_multi_bit_ks_pbs_group};

pub fn ks_pbs_group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    ks_pbs(&mut criterion, &benchmark_parameters());
}

pub fn multi_bit_ks_pbs_group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    multi_bit_ks_pbs(&mut criterion, &multi_bit_benchmark_parameters(), false);
    multi_bit_ks_pbs(&mut criterion, &multi_bit_benchmark_parameters(), true);
}

#[cfg(feature = "gpu")]
fn go_through_gpu_bench_groups(val: &str) {
    match val.to_lowercase().as_str() {
        "classical" => cuda_ks_pbs_group(),
        "multi_bit" => cuda_multi_bit_ks_pbs_group(),
        _ => panic!("unknown benchmark operations flavor"),
    };
}

#[cfg(not(feature = "gpu"))]
fn go_through_cpu_bench_groups(val: &str) {
    match val.to_lowercase().as_str() {
        "classical" => ks_pbs_group(),
        "multi_bit" => multi_bit_ks_pbs_group(),
        _ => panic!("unknown benchmark operations flavor"),
    }
}

fn main() {
    init_parameters_set();

    match env::var("__TFHE_RS_PARAM_TYPE") {
        Ok(val) => {
            #[cfg(feature = "gpu")]
            go_through_gpu_bench_groups(&val);
            #[cfg(not(feature = "gpu"))]
            go_through_cpu_bench_groups(&val);
        }
        Err(_) => {
            ks_pbs_group();
            multi_bit_ks_pbs_group()
        }
    };

    Criterion::default().configure_from_args().final_summary();
}
