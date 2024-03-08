#[path = "../utilities.rs"]
mod utilities;
use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
use rayon::prelude::*;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde::Serialize;
use tfhe::boolean::parameters::{
    BooleanParameters, DEFAULT_PARAMETERS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
};

use tfhe::core_crypto::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::*;
use tfhe::shortint::ClassicPBSParameters;

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
    if Scalar::BITS == 64 {
        vec![
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
        ]
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
                PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
                PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
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

fn mem_optimized_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(c: &mut Criterion) {
    let bench_name = "core_crypto::pbs_mem_optimized";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for (name, params) in benchmark_parameters::<Scalar>().iter() {
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
            params.lwe_modular_std_dev.unwrap(),
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

        let id = format!("{bench_name}_{name}");
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
) {
    let bench_name = "core_crypto::multi_bit_pbs";
    let mut bench_group = c.benchmark_group(bench_name);

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

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_modular_std_dev.unwrap(),
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

        let id = format!("{bench_name}_{name}_parallelized");
        bench_group.bench_function(&id, |b| {
            b.iter(|| {
                multi_bit_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator.as_view(),
                    &multi_bit_bsk,
                    ThreadCount(10),
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
) {
    let bench_name = "core_crypto::multi_bit_deterministic_pbs";
    let mut bench_group = c.benchmark_group(bench_name);

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

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_modular_std_dev.unwrap(),
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

        let id = format!("{bench_name}_{name}_parallelized");
        bench_group.bench_function(&id, |b| {
            b.iter(|| {
                multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator.as_view(),
                    &multi_bit_bsk,
                    ThreadCount(10),
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

fn pbs_throughput<Scalar: UnsignedTorus + CastInto<usize> + Sync + Send + Serialize>(
    c: &mut Criterion,
) {
    let bench_name = "core_crypto::pbs_throughput";
    let mut bench_group = c.benchmark_group(bench_name);

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

        const NUM_CTS: usize = 512;
        let lwe_vec: Vec<_> = (0..NUM_CTS)
            .map(|_| {
                allocate_and_encrypt_new_lwe_ciphertext(
                    &input_lwe_secret_key,
                    Plaintext(Scalar::ZERO),
                    params.lwe_modular_std_dev.unwrap(),
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

        for chunk_size in [1, 16, 32, 64, 128, 256, 512] {
            let id = format!("{bench_name}_{name}_{chunk_size}chunk");
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
    use super::{benchmark_parameters, multi_bit_benchmark_parameters};
    use crate::utilities::{write_to_json, OperatorType};
    use criterion::{black_box, criterion_group, Criterion};
    use serde::Serialize;
    use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
    use tfhe::core_crypto::gpu::{
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext,
        cuda_programmable_bootstrap_lwe_ciphertext, CudaDevice, CudaStream,
    };
    use tfhe::core_crypto::prelude::*;

    fn cuda_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(c: &mut Criterion) {
        let bench_name = "core_crypto::cuda::pbs";
        let mut bench_group = c.benchmark_group(bench_name);

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

        for (name, params) in benchmark_parameters::<Scalar>().iter() {
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

            // Allocate a new LweCiphertext and encrypt our plaintext
            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                params.lwe_modular_std_dev.unwrap(),
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
            let mut d_input_indexes = unsafe { stream.malloc_async::<Scalar>(1u32) };
            let mut d_output_indexes = unsafe { stream.malloc_async::<Scalar>(1u32) };
            let mut d_lut_indexes = unsafe { stream.malloc_async::<Scalar>(1u32) };
            unsafe {
                stream.copy_to_gpu_async(&mut d_input_indexes, h_indexes.as_ref());
                stream.copy_to_gpu_async(&mut d_output_indexes, h_indexes.as_ref());
                stream.copy_to_gpu_async(&mut d_lut_indexes, h_indexes.as_ref());
            }
            stream.synchronize();

            let id = format!("{bench_name}_{name}");
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

            // Allocate a new LweCiphertext and encrypt our plaintext
            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                params.lwe_modular_std_dev.unwrap(),
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
            let mut d_input_indexes = unsafe { stream.malloc_async::<Scalar>(1u32) };
            let mut d_output_indexes = unsafe { stream.malloc_async::<Scalar>(1u32) };
            let mut d_lut_indexes = unsafe { stream.malloc_async::<Scalar>(1u32) };
            unsafe {
                stream.copy_to_gpu_async(&mut d_input_indexes, h_indexes.as_ref());
                stream.copy_to_gpu_async(&mut d_output_indexes, h_indexes.as_ref());
                stream.copy_to_gpu_async(&mut d_lut_indexes, h_indexes.as_ref());
            }
            stream.synchronize();

            let id = format!("{bench_name}_{name}");
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

    criterion_group!(
        name = cuda_pbs_group;
        config = Criterion::default().sample_size(2000);
        targets = cuda_pbs::<u64>
    );

    criterion_group!(
        name = cuda_multi_bit_pbs_group;
        config = Criterion::default().sample_size(2000);
        targets = cuda_multi_bit_pbs::<u64>
    );
}

#[cfg(feature = "gpu")]
use cuda::{cuda_multi_bit_pbs_group, cuda_pbs_group};

fn tensor_prod_with_relin_benchmark_parameters<Scalar: UnsignedInteger + Default + Serialize>(
) -> Vec<(String, CryptoParametersRecord<Scalar>)> {
    if Scalar::BITS == 64 {
        vec![
            (
                "message_1_carry_1_clot21mult".to_string(),
                (CryptoParametersRecord {
                    relin_base_log: Some(DecompositionBaseLog(23)),
                    relin_level: Some(DecompositionLevelCount(1)),
                    packing_base_log: Some(DecompositionBaseLog(23)),
                    packing_level: Some(DecompositionLevelCount(1)),
                    pbs_base_log: Some(DecompositionBaseLog(23)),
                    pbs_level: Some(DecompositionLevelCount(1)),
                    ks_base_log: Some(DecompositionBaseLog(4)),
                    ks_level: Some(DecompositionLevelCount(3)),
                    lwe_dimension: Some(LweDimension(663)),
                    glwe_dimension: Some(GlweDimension(4)),
                    polynomial_size: Some(PolynomialSize(1 << 9)),
                    glwe_modular_std_dev: Some(StandardDev(0.00000000000000031529322391500584)), //actual value matters only for correctness not for benches
                    lwe_modular_std_dev: Some(StandardDev(0.00003879148821333555)),
                    ..Default::default()
                }),
            ),
            (
                "message_2_carry_2_clot21mult".to_string(),
                (CryptoParametersRecord {
                    relin_base_log: Some(DecompositionBaseLog(23)),
                    relin_level: Some(DecompositionLevelCount(1)),
                    packing_base_log: Some(DecompositionBaseLog(23)),
                    packing_level: Some(DecompositionLevelCount(1)),
                    pbs_base_log: Some(DecompositionBaseLog(15)),
                    pbs_level: Some(DecompositionLevelCount(2)),
                    ks_base_log: Some(DecompositionBaseLog(3)),
                    ks_level: Some(DecompositionLevelCount(5)),
                    lwe_dimension: Some(LweDimension(730)),
                    glwe_dimension: Some(GlweDimension(2)),
                    polynomial_size: Some(PolynomialSize(1 << 10)),
                    glwe_modular_std_dev: Some(StandardDev(0.00000000000000031529322391500584)), //actual value matters only for correctness not for benches
                    lwe_modular_std_dev: Some(StandardDev(0.000011278507355490732)),
                    ..Default::default()
                }),
            ),
            (
                "message_3_carry_3_clot21mult".to_string(),
                (CryptoParametersRecord {
                    relin_base_log: Some(DecompositionBaseLog(20)),
                    relin_level: Some(DecompositionLevelCount(1)),
                    packing_base_log: Some(DecompositionBaseLog(28)),
                    packing_level: Some(DecompositionLevelCount(1)),
                    pbs_base_log: Some(DecompositionBaseLog(11)),
                    pbs_level: Some(DecompositionLevelCount(3)),
                    ks_base_log: Some(DecompositionBaseLog(3)),
                    ks_level: Some(DecompositionLevelCount(5)),
                    lwe_dimension: Some(LweDimension(847)),
                    glwe_dimension: Some(GlweDimension(1)),
                    polynomial_size: Some(PolynomialSize(1 << 12)),
                    glwe_modular_std_dev: Some(StandardDev(0.0000000000000000002168404344971009)), //actual value matters only for correctness not for benches
                    lwe_modular_std_dev: Some(StandardDev(0.0000013043826430106891)),
                    ..Default::default()
                }),
            ),
            (
                "message_4_carry_4_clot21mult".to_string(),
                (CryptoParametersRecord {
                    relin_base_log: Some(DecompositionBaseLog(19)),
                    relin_level: Some(DecompositionLevelCount(1)),
                    packing_base_log: Some(DecompositionBaseLog(18)),
                    packing_level: Some(DecompositionLevelCount(2)),
                    pbs_base_log: Some(DecompositionBaseLog(6)),
                    pbs_level: Some(DecompositionLevelCount(7)),
                    ks_base_log: Some(DecompositionBaseLog(2)),
                    ks_level: Some(DecompositionLevelCount(10)),
                    lwe_dimension: Some(LweDimension(970)),
                    glwe_dimension: Some(GlweDimension(1)),
                    polynomial_size: Some(PolynomialSize(1 << 14)),
                    glwe_modular_std_dev: Some(StandardDev(0.0000000000000000002168404344971009)), //actual value matters only for correctness not for benches
                    lwe_modular_std_dev: Some(StandardDev(0.00000013505634085553605)),
                    ..Default::default()
                }),
            ),
        ]
    } else if Scalar::BITS == 128 {
        vec![
            (
                "message_1_carry_1_clot21mult".to_string(),
                (CryptoParametersRecord {
                    lwe_dimension: Some(LweDimension(616)),
                    relin_base_log: Some(DecompositionBaseLog(18)),
                    relin_level: Some(DecompositionLevelCount(1)),
                    packing_base_log: Some(DecompositionBaseLog(18)),
                    packing_level: Some(DecompositionLevelCount(1)),
                    glwe_dimension: Some(GlweDimension(6)),
                    glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)), //actual value matters only for correctness not for benches
                    polynomial_size: Some(PolynomialSize(1 << 8)),
                    ..Default::default()
                }),
            ),
            (
                "message_2_carry_2_clot21mult".to_string(),
                (CryptoParametersRecord {
                    lwe_dimension: Some(LweDimension(714)),
                    relin_base_log: Some(DecompositionBaseLog(32)),
                    relin_level: Some(DecompositionLevelCount(1)),
                    packing_base_log: Some(DecompositionBaseLog(18)),
                    packing_level: Some(DecompositionLevelCount(1)),
                    glwe_dimension: Some(GlweDimension(3)),
                    glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                    polynomial_size: Some(PolynomialSize(1 << 10)),
                    ..Default::default()
                }),
            ),
            (
                "message_3_carry_3_clot21mult".to_string(),
                (CryptoParametersRecord {
                    lwe_dimension: Some(LweDimension(804)),
                    relin_base_log: Some(DecompositionBaseLog(29)),
                    relin_level: Some(DecompositionLevelCount(1)),
                    packing_base_log: Some(DecompositionBaseLog(18)),
                    packing_level: Some(DecompositionLevelCount(1)),
                    glwe_dimension: Some(GlweDimension(1)),
                    glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                    polynomial_size: Some(PolynomialSize(1 << 12)),
                    ..Default::default()
                }),
            ),
            (
                "message_4_carry_4_clot21mult".to_string(),
                (CryptoParametersRecord {
                    lwe_dimension: Some(LweDimension(926)),
                    relin_base_log: Some(DecompositionBaseLog(55)),
                    relin_level: Some(DecompositionLevelCount(1)),
                    packing_base_log: Some(DecompositionBaseLog(18)),
                    packing_level: Some(DecompositionLevelCount(1)),
                    glwe_dimension: Some(GlweDimension(1)),
                    glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                    polynomial_size: Some(PolynomialSize(1 << 14)),
                    ..Default::default()
                }),
            ),
            (
                "message_5_carry_5_clot21mult".to_string(),
                (CryptoParametersRecord {
                    lwe_dimension: Some(LweDimension(1087)),
                    relin_base_log: Some(DecompositionBaseLog(27)),
                    relin_level: Some(DecompositionLevelCount(1)),
                    packing_base_log: Some(DecompositionBaseLog(18)),
                    packing_level: Some(DecompositionLevelCount(1)),
                    glwe_dimension: Some(GlweDimension(1)),
                    glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                    polynomial_size: Some(PolynomialSize(1 << 16)),
                    ..Default::default()
                }),
            ),
        ]
    } else {
        // For now there are no parameters available to test multi bit PBS on 32 bits.
        vec![]
    }
}

fn tensor_product_with_relin<Scalar: UnsignedTorus + CastInto<usize> + Default + Serialize>(
    c: &mut Criterion,
) {
    //only written for local development benchmarking
    let bench_name = "leveled_mult_and_relin";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    //let ciphertext_modulus: tfhe::core_crypto::prelude::CiphertextModulus<Scalar> = tfhe::core_crypto::prelude::CiphertextModulus::new_native();

    for (name, params) in tensor_prod_with_relin_benchmark_parameters::<Scalar>().iter() {
        // Create the GlweSecretKey
        let glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
                &mut secret_generator,
            );

        let glwe_relin_key = allocate_and_generate_glwe_relinearisation_key(
            &glwe_secret_key,
            params.relin_base_log.unwrap(),
            params.relin_level.unwrap(),
            params.glwe_modular_std_dev.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let log_delta1 = 59;
        let log_delta2 = 60;
        let log_delta = std::cmp::min(log_delta1, log_delta2);
        //let output_log_delta = log_delta1 + log_delta2 - log_delta;

        // Allocate a new GlweCiphertext and encrypt our plaintext
        let mut glwe_1 = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );
        encrypt_glwe_ciphertext_assign(
            &glwe_secret_key,
            &mut glwe_1,
            params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
        );
        let mut glwe_2 = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );
        encrypt_glwe_ciphertext_assign(
            &glwe_secret_key,
            &mut glwe_2,
            params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
        );

        // Perform the tensor product
        let scale = Scalar::ONE << log_delta;
        //let tensor_output = glwe_tensor_product(&glwe_1, &glwe_2, scale);

        let mut output_glwe_ciphertext = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        //glwe_relinearisation(&tensor_output, &glwe_relin_key, &mut output_glwe_ciphertext);

        let id = format!("{bench_name}_{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    tensor_mult_with_relin(
                        &glwe_1,
                        &glwe_2,
                        scale,
                        &glwe_relin_key,
                        &mut output_glwe_ciphertext,
                    );
                    black_box(&mut output_glwe_ciphertext);
                })
            });
        }

        let bit_size = (params.message_modulus.unwrap_or(2) as u64).ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "lev mult",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn mult_circuit_clot21<
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u32> + CastFrom<usize> + Default + Serialize,
>(
    c: &mut Criterion,
) {
    //only written for local development benchmarking
    let bench_name = "full_mult_circuit_clot21";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    //let ciphertext_modulus: tfhe::core_crypto::prelude::CiphertextModulus<Scalar> = tfhe::core_crypto::prelude::CiphertextModulus::new_native();

    for (name, params) in tensor_prod_with_relin_benchmark_parameters::<Scalar>().iter() {
        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );

        // Create the GlweSecretKey
        let glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
                &mut secret_generator,
            );

        //Create packing key switching key
        let lwe_pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
            &input_lwe_secret_key,
            &glwe_secret_key,
            params.packing_base_log.unwrap(), //TODO
            params.packing_level.unwrap(),    //TODO
            params.glwe_modular_std_dev.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        // Create new LweCiphertext list
        let mut input_lwe_list1 = LweCiphertextList::new(
            Scalar::ZERO,
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            LweCiphertextCount(glwe_secret_key.polynomial_size().0),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut input_lwe_list2 = LweCiphertextList::new(
            Scalar::ZERO,
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            LweCiphertextCount(glwe_secret_key.polynomial_size().0),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut input_plaintext_list = PlaintextList::new(
            Scalar::ZERO,
            PlaintextCount(glwe_secret_key.polynomial_size().0),
        );

        //need to change these values if we do not work with u64
        let modulus = Scalar::cast_from(16u32);
        let shift = 60usize;
        input_plaintext_list
            .iter_mut()
            .enumerate()
            .for_each(|(idx, dst)| *dst.0 = (Scalar::cast_from(idx) % modulus) << shift);

        encrypt_lwe_ciphertext_list(
            &input_lwe_secret_key,
            &mut input_lwe_list1,
            &input_plaintext_list,
            params.lwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
        );

        encrypt_lwe_ciphertext_list(
            &input_lwe_secret_key,
            &mut input_lwe_list2,
            &input_plaintext_list,
            params.lwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
        );

        // Allocate a new GlweCiphertext and encrypt our plaintext
        //let mut packed_glwe1 = GlweCiphertext::new(Scalar::ZERO,
        //    params.glwe_dimension.unwrap().to_glwe_size(),
        //    params.polynomial_size.unwrap(),
        //    tfhe::core_crypto::prelude::CiphertextModulus::new_native());

        //let mut packed_glwe2 = GlweCiphertext::new(Scalar::ZERO,
        //    params.glwe_dimension.unwrap().to_glwe_size(),
        //    params.polynomial_size.unwrap(),
        //    tfhe::core_crypto::prelude::CiphertextModulus::new_native());

        //the actual value does not matter for benchmarking we only need to know how expensive the operation is, it does not necessarily needs to be correct
        let log_delta1 = 59;
        let log_delta2 = 60;
        let log_delta = std::cmp::min(log_delta1, log_delta2);
        let scale = Scalar::ONE << log_delta;

        let relinearisation_key = allocate_and_generate_glwe_relinearisation_key(
            &glwe_secret_key,
            params.relin_base_log.unwrap(),
            params.relin_level.unwrap(),
            params.glwe_modular_std_dev.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let mut output_relin = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let equivalent_lwe_sk = glwe_secret_key.clone().into_lwe_secret_key();
        print!("{}", equivalent_lwe_sk.lwe_dimension().0);
        let mut extracted_sample = LweCiphertext::new(
            Scalar::ZERO,
            equivalent_lwe_sk.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
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

        // Allocate the LweCiphertext to store the result of the PBS
        let mut output_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            fourier_bsk.output_lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let id = format!("{bench_name}_{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    pack_lwe_list_into_glwe_tensor_mult_with_relin_pbs(
                        &lwe_pksk,
                        &input_lwe_list1,
                        &input_lwe_list2,
                        scale,
                        &relinearisation_key,
                        &mut output_relin,
                        &mut extracted_sample,
                        &accumulator,
                        &fourier_bsk,
                        fft,
                        &mut buffers,
                        &mut output_pbs_ct,
                    );
                    black_box(&mut output_pbs_ct);
                })
            });
        }

        let bit_size = (params.message_modulus.unwrap_or(2) as u64).ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "circuit lev mult with clot21",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn square_trick_benchmark_parameters<Scalar: UnsignedInteger + Default + Serialize>(
) -> Vec<(String, CryptoParametersRecord<Scalar>)> {
    if Scalar::BITS == 64 {
        vec![
            (
                "message_1_carry_1_square_trick".to_string(),
                (CryptoParametersRecord {
                    pbs_base_log: Some(DecompositionBaseLog(15)),
                    pbs_level: Some(DecompositionLevelCount(1)),
                    ks_base_log: Some(DecompositionBaseLog(4)),
                    ks_level: Some(DecompositionLevelCount(3)),
                    lwe_dimension: Some(LweDimension(670)),
                    glwe_dimension: Some(GlweDimension(5)),
                    polynomial_size: Some(PolynomialSize(1 << 8)),
                    glwe_modular_std_dev: Some(StandardDev(0.000000000444909632492578)), //actual value matters only for correctness not for benches
                    lwe_modular_std_dev: Some(StandardDev(0.0000340946148770733)),
                    ..Default::default()
                }),
            ),
            (
                "message_2_carry_2_square_trick".to_string(),
                (CryptoParametersRecord {
                    pbs_base_log: Some(DecompositionBaseLog(23)),
                    pbs_level: Some(DecompositionLevelCount(1)),
                    ks_base_log: Some(DecompositionBaseLog(4)),
                    ks_level: Some(DecompositionLevelCount(3)),
                    lwe_dimension: Some(LweDimension(784)),
                    glwe_dimension: Some(GlweDimension(2)),
                    polynomial_size: Some(PolynomialSize(1 << 10)),
                    glwe_modular_std_dev: Some(StandardDev(0.000000000000000315293223915005)), //actual value matters only for correctness not for benches
                    lwe_modular_std_dev: Some(StandardDev(0.00000416735867973491)),
                    ..Default::default()
                }),
            ),
            (
                "message_3_carry_3_square_trick".to_string(),
                (CryptoParametersRecord {
                    pbs_base_log: Some(DecompositionBaseLog(22)),
                    pbs_level: Some(DecompositionLevelCount(1)),
                    ks_base_log: Some(DecompositionBaseLog(4)),
                    ks_level: Some(DecompositionLevelCount(4)),
                    lwe_dimension: Some(LweDimension(860)),
                    glwe_dimension: Some(GlweDimension(1)),
                    polynomial_size: Some(PolynomialSize(1 << 12)),
                    glwe_modular_std_dev: Some(StandardDev(0.0000000000000000002168404344971)), //actual value matters only for correctness not for benches
                    lwe_modular_std_dev: Some(StandardDev(0.00000102638652733045)),
                    ..Default::default()
                }),
            ),
            (
                "message_4_carry_4_square_trick".to_string(),
                (CryptoParametersRecord {
                    pbs_base_log: Some(DecompositionBaseLog(15)),
                    pbs_level: Some(DecompositionLevelCount(2)),
                    ks_base_log: Some(DecompositionBaseLog(4)),
                    ks_level: Some(DecompositionLevelCount(5)),
                    lwe_dimension: Some(LweDimension(982)),
                    glwe_dimension: Some(GlweDimension(1)),
                    polynomial_size: Some(PolynomialSize(1 << 14)),
                    glwe_modular_std_dev: Some(StandardDev(0.0000000000000000002168404344971)), //actual value matters only for correctness not for benches
                    lwe_modular_std_dev: Some(StandardDev(0.000000108250060212356)),
                    ..Default::default()
                }),
            ),
        ]
    } else {
        // For now there are no parameters available to test multi bit PBS on 32 bits.
        vec![]
    }
}

fn square_trick_circuit<Scalar: UnsignedTorus + CastInto<usize> + Default + Serialize>(
    c: &mut Criterion,
) {
    //only written for local development benchmarking
    let bench_name = "square_trick_mult";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    //let ciphertext_modulus: tfhe::core_crypto::prelude::CiphertextModulus<Scalar> = tfhe::core_crypto::prelude::CiphertextModulus::new_native();

    for (name, params) in square_trick_benchmark_parameters::<Scalar>().iter() {
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );

        //let glwe_secret_key = GlweSecretKey::new_empty_key(
        //    Scalar::ZERO,
        //    params.glwe_dimension.unwrap(),
        //    params.polynomial_size.unwrap(),
        //);
        //let big_lwe_sk = glwe_secret_key.into_lwe_secret_key();
        //let big_lwe_dimension = big_lwe_sk.lwe_dimension();

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in_lhs: LweCiphertextOwned<Scalar> =
            allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                params.lwe_modular_std_dev.unwrap(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
                &mut encryption_generator,
            );

        let lwe_ciphertext_in_rhs: LweCiphertextOwned<Scalar> =
            allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                params.lwe_modular_std_dev.unwrap(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
                &mut encryption_generator,
            );

        let accumulator1 = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let accumulator2 = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk1 = FourierLweBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
        );

        let fourier_bsk2 = FourierLweBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
        );

        let mut sq_sum = LweCiphertext::new(
            Scalar::ZERO,
            params.lwe_dimension.unwrap().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut sq_subtraction = LweCiphertext::new(
            Scalar::ZERO,
            params.lwe_dimension.unwrap().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        //for benchmarking it does not matter what the input/output key is
        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &input_lwe_secret_key,
            &input_lwe_secret_key,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.lwe_modular_std_dev.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let mut ks_result_mult = LweCiphertext::new(
            Scalar::ZERO,
            params.lwe_dimension.unwrap().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let mut extracted_sample: LweCiphertextOwned<Scalar> =
            allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                Plaintext(Scalar::ZERO),
                params.lwe_modular_std_dev.unwrap(),
                tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
                &mut encryption_generator,
            );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
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

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
        );

        let id = format!("{bench_name}_{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    square_trick(
                        &lwe_ciphertext_in_lhs,
                        &lwe_ciphertext_in_rhs,
                        &accumulator1,
                        &accumulator2,
                        &fourier_bsk1,
                        &fourier_bsk2,
                        &mut sq_sum,
                        &mut sq_subtraction,
                        &ksk,
                        &mut ks_result_mult,
                        &mut extracted_sample,
                        &accumulator,
                        &fourier_bsk,
                        fft,
                        &mut buffers,
                        &mut out_pbs_ct,
                    );
                    black_box(&mut out_pbs_ct);
                })
            });
        }

        let bit_size = (params.message_modulus.unwrap_or(2) as u64).ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "circuit lev mult with square trick",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

// fn mult_through_pbs_benchmark_parameters<Scalar: UnsignedInteger + Default + Serialize>(
// ) -> Vec<(String, CryptoParametersRecord<Scalar>)> {
//     if Scalar::BITS == 64 {
//         vec![
//             (
//                 "2_bits_prec".to_string(),
//                 (
//                     CryptoParametersRecord {
//                         lwe_dimension: Some(LweDimension(642)),
//                         ks_base_log: Some(DecompositionBaseLog(8)),
//                         ks_level: Some(DecompositionLevelCount(4)),
//                         relin_base_log: Some(DecompositionBaseLog(8)),
//                         relin_level: Some(DecompositionLevelCount(4)),
//                         glwe_dimension: Some(GlweDimension(6)),
//                         glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
//                         polynomial_size: Some(PolynomialSize(1 << 8)),
//                         message_modulus: Some(2),
//                         ..Default::default()
//                     }
//                 ),
//             ),
//             ]
//         } else {
//             // For now there are no parameters available to test multi bit PBS on 32 bits.
//             vec![]
//         }
//     }

// fn mult_through_pbs<Scalar: UnsignedTorus + CastInto<usize>>(c: &mut Criterion)
// {
//     //only written for local development benchmarking
//     let bench_name = "mult_through_pbs";
//     let mut bench_group = c.benchmark_group(bench_name);

//     // Create the PRNG
//     let mut seeder = new_seeder();
//     let seeder = seeder.as_mut();
//     let mut encryption_generator =
//         EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
//     let mut secret_generator =
//         SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

//     let ciphertext_modulus: tfhe::core_crypto::prelude::CiphertextModulus<Scalar> = tfhe::core_crypto::prelude::CiphertextModulus::new_native();

//     for (name, params) in mult_through_pbs_benchmark_parameters::<Scalar>().iter()
//     {
//         // Create the GlweSecretKey
//         let glwe_secret_key: GlweSecretKeyOwned<Scalar>  = allocate_and_generate_new_binary_glwe_secret_key(
//             params.glwe_dimension.unwrap(),
//             params.polynomial_size.unwrap(),
//             &mut secret_generator,
//         );

//         // Create the lweSecretKey
//         let lwe_secret_key: LweSecretKeyOwned<Scalar>  = allocate_and_generate_new_binary_lwe_secret_key(
//             params.lwe_dimension.unwrap(),
//             &mut secret_generator,
//         );

//         let ksk_glwe_to_lwe = allocate_and_generate_new_lwe_keyswitch_key(
//             &glwe_secret_key,
//             &lwe_secret_key,
//             params.ks_base_log.unwrap(),
//             params.ks_level.unwrap(),
//             params.lwe_modular_std_dev.unwrap(),
//             ciphertext_modulus,
//             &mut encryption_generator,
//         );

//         let glwe_relin_key = allocate_and_generate_glwe_relinearisation_key(
//             &glwe_secret_key,
//             params.relin_base_log.unwrap(),
//             params.relin_level.unwrap(),
//             params.glwe_modular_std_dev.unwrap(),
//             ciphertext_modulus,
//             &mut encryption_generator,
//         );

//         // Allocate a new GlweCiphertext and encrypt our plaintext
//         let mut glwe_1 = GlweCiphertext::new(Scalar::ZERO,
//             params.glwe_dimension.unwrap().to_glwe_size(),
//             params.polynomial_size.unwrap(),
//             ciphertext_modulus);
//         encrypt_glwe_ciphertext_assign(&glwe_secret_key,
//             & mut glwe_1,params.glwe_modular_std_dev.unwrap(),
//             &mut encryption_generator,);
//         let mut glwe_2 = GlweCiphertext::new(Scalar::ZERO,
//             params.glwe_dimension.unwrap().to_glwe_size(),
//             params.polynomial_size.unwrap(),
//             ciphertext_modulus);
//         encrypt_glwe_ciphertext_assign(&glwe_secret_key,
//             & mut glwe_2,params.glwe_modular_std_dev.unwrap(),
//             &mut encryption_generator,);

//         // Perform the tensor product
//         let scale = Scalar::ONE;
//         //let tensor_output = glwe_tensor_product(&glwe_1, &glwe_2, scale);

//         let mut output_glwe_ciphertext =
//             GlweCiphertext::new(Scalar::ZERO, params.glwe_dimension.unwrap().to_glwe_size(), params.polynomial_size.unwrap(), ciphertext_modulus);

//         //glwe_relinearisation(&tensor_output, &glwe_relin_key, &mut output_glwe_ciphertext);

//         let id = format!("{bench_name}_{name}");
//         {
//             bench_group.bench_function(&id, |b| {
//                 b.iter(|| {
//                     tensor_mult_with_relin(
//                         &glwe_1,
//                         &glwe_2,
//                         scale,
//                         &glwe_relin_key,
//                         & mut output_glwe_ciphertext,
//                     );
//                     black_box(&mut output_glwe_ciphertext);
//                 })
//             });
//         }

//         let bit_size = (params.message_modulus.unwrap_or(2) as u64).ilog2();
//         write_to_json(
//             &id,
//             *params,
//             name,
//             "lev mult",
//             &OperatorType::Atomic,
//             bit_size,
//             vec![bit_size],
//         );
//     }
// }

criterion_group!(
    name = pbs_group;
    config = Criterion::default().sample_size(2000);
    targets = mem_optimized_pbs::<u64>, mem_optimized_pbs::<u32>
);

criterion_group!(
    name = multi_bit_pbs_group;
    config = Criterion::default().sample_size(2000);
    targets =   multi_bit_pbs::<u64>,
                multi_bit_pbs::<u32>,
                multi_bit_deterministic_pbs::<u64>,
                multi_bit_deterministic_pbs::<u32>,
);

criterion_group!(
    name = pbs_throughput_group;
    config = Criterion::default().sample_size(100);
    targets = pbs_throughput::<u64>, pbs_throughput::<u32>
);

criterion_group!(
    name = tensor_prod_with_relin_group;
    config = Criterion::default().sample_size(2000);
    targets = tensor_product_with_relin::<u64>
);

criterion_group!(
    name = clot21_mult_circuit_group;
    config = Criterion::default().sample_size(2000);
    targets = mult_circuit_clot21::<u64>
);

criterion_group!(
    name = square_trick_circuit_group;
    config = Criterion::default().sample_size(2000);
    targets = square_trick_circuit::<u64>
);

// #[cfg(not(feature = "gpu"))]
// criterion_main!(pbs_group, multi_bit_pbs_group, pbs_throughput_group);
// #[cfg(feature = "gpu")]
// criterion_main!(cuda_pbs_group, cuda_multi_bit_pbs_group);
//criterion_main!(tensor_prod_with_relin_group);
criterion_main!(clot21_mult_circuit_group, square_trick_circuit_group);
