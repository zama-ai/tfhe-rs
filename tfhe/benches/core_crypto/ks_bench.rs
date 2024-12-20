#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
use criterion::{black_box, criterion_main, Criterion};
use serde::Serialize;
use tfhe::boolean::prelude::*;
use tfhe::core_crypto::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::{
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
};
#[cfg(feature = "gpu")]
use tfhe::shortint::parameters::{
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
};
#[cfg(not(feature = "gpu"))]
use tfhe::shortint::parameters::{
    V0_11_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
};
use tfhe::shortint::prelude::*;
use tfhe::shortint::{MultiBitPBSParameters, PBSParameters};

#[cfg(not(feature = "gpu"))]
const SHORTINT_BENCH_PARAMS: [ClassicPBSParameters; 5] = [
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
];

#[cfg(feature = "gpu")]
const SHORTINT_BENCH_PARAMS: [ClassicPBSParameters; 4] = [
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
];

#[cfg(not(feature = "gpu"))]
const SHORTINT_MULTI_BIT_BENCH_PARAMS: [MultiBitPBSParameters; 6] = [
    V0_11_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
];

#[cfg(feature = "gpu")]
const SHORTINT_MULTI_BIT_BENCH_PARAMS: [MultiBitPBSParameters; 4] = [
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
];

const BOOLEAN_BENCH_PARAMS: [(&str, BooleanParameters); 2] = [
    ("BOOLEAN_DEFAULT_PARAMS", DEFAULT_PARAMETERS),
    (
        "BOOLEAN_TFHE_LIB_PARAMS",
        PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    ),
];

fn benchmark_parameters_64bits() -> Vec<(String, CryptoParametersRecord<u64>)> {
    let classic = SHORTINT_BENCH_PARAMS
        .iter()
        .map(|params| {
            (
                params.name(),
                <ClassicPBSParameters as Into<PBSParameters>>::into(*params)
                    .to_owned()
                    .into(),
            )
        })
        .collect::<Vec<(String, CryptoParametersRecord<u64>)>>();
    let multi_bit = SHORTINT_MULTI_BIT_BENCH_PARAMS
        .iter()
        .map(|params| {
            (
                params.name(),
                <MultiBitPBSParameters as Into<PBSParameters>>::into(*params)
                    .to_owned()
                    .into(),
            )
        })
        .collect();
    [classic, multi_bit].concat()
}

fn benchmark_parameters_32bits() -> Vec<(String, CryptoParametersRecord<u32>)> {
    BOOLEAN_BENCH_PARAMS
        .iter()
        .map(|(name, params)| (name.to_string(), params.to_owned().into()))
        .collect()
}

fn benchmark_compression_parameters() -> Vec<(String, CryptoParametersRecord<u64>)> {
    vec![(
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64.name(),
        (
            COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
            .into(),
    )]
}

fn keyswitch<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
    criterion: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
) {
    let bench_name = "core_crypto::keyswitch";
    let mut bench_group = criterion.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    for (name, params) in parameters.iter() {
        let lwe_dimension = params.lwe_dimension.unwrap();
        let glwe_dimension = params.glwe_dimension.unwrap();
        let polynomial_size = params.polynomial_size.unwrap();
        let ks_decomp_base_log = params.ks_base_log.unwrap();
        let ks_decomp_level_count = params.ks_level.unwrap();

        let lwe_sk =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
        let big_lwe_sk = glwe_sk.into_lwe_secret_key();
        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_sk,
            &lwe_sk,
            ks_decomp_base_log,
            ks_decomp_level_count,
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            &big_lwe_sk,
            Plaintext(Scalar::ONE),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let mut output_ct = LweCiphertext::new(
            Scalar::ZERO,
            lwe_sk.lwe_dimension().to_lwe_size(),
            params.ciphertext_modulus.unwrap(),
        );

        let id = format!("{bench_name}::{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut output_ct);
                    black_box(&mut output_ct);
                })
            });
        }
        let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "ks",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn packing_keyswitch<Scalar, F>(
    criterion: &mut Criterion,
    bench_name: &str,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
    ks_op: F,
) where
    Scalar: UnsignedTorus + CastInto<usize> + Serialize,
    F: Fn(
        &LwePackingKeyswitchKey<Vec<Scalar>>,
        &LweCiphertextList<Vec<Scalar>>,
        &mut GlweCiphertext<Vec<Scalar>>,
    ),
{
    let bench_name = format!("core_crypto::{bench_name}");
    let mut bench_group = criterion.benchmark_group(&bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    for (name, params) in parameters.iter() {
        let lwe_dimension = params.lwe_dimension.unwrap();
        let packing_glwe_dimension = params.packing_ks_glwe_dimension.unwrap();
        let packing_polynomial_size = params.packing_ks_polynomial_size.unwrap();
        let packing_ks_decomp_base_log = params.packing_ks_base_log.unwrap();
        let packing_ks_decomp_level_count = params.packing_ks_level.unwrap();
        let ciphertext_modulus = params.ciphertext_modulus.unwrap();
        let count = params.lwe_per_glwe.unwrap();

        let lwe_sk =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            packing_glwe_dimension,
            packing_polynomial_size,
            &mut secret_generator,
        );

        let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
            &lwe_sk,
            &glwe_sk,
            packing_ks_decomp_base_log,
            packing_ks_decomp_level_count,
            params.packing_ks_key_noise_distribution.unwrap(),
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut input_lwe_list = LweCiphertextList::new(
            Scalar::ZERO,
            lwe_sk.lwe_dimension().to_lwe_size(),
            count,
            ciphertext_modulus,
        );

        let plaintext_list = PlaintextList::new(
            Scalar::ZERO,
            PlaintextCount(input_lwe_list.lwe_ciphertext_count().0),
        );

        encrypt_lwe_ciphertext_list(
            &lwe_sk,
            &mut input_lwe_list,
            &plaintext_list,
            params.lwe_noise_distribution.unwrap(),
            &mut encryption_generator,
        );

        let mut output_glwe = GlweCiphertext::new(
            Scalar::ZERO,
            glwe_sk.glwe_dimension().to_glwe_size(),
            glwe_sk.polynomial_size(),
            ciphertext_modulus,
        );

        let id = format!("{bench_name}::{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    ks_op(&pksk, &input_lwe_list, &mut output_glwe);
                    black_box(&mut output_glwe);
                })
            });
        }
        let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "packing_ks",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

#[cfg(feature = "gpu")]
mod cuda {
    use crate::benchmark_parameters_64bits;
    use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
    use criterion::{black_box, Criterion};
    use serde::Serialize;
    use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
    use tfhe::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
    use tfhe::core_crypto::gpu::vec::{CudaVec, GpuIndex};
    use tfhe::core_crypto::gpu::{
        cuda_keyswitch_lwe_ciphertext, cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext,
        CudaStreams,
    };
    use tfhe::core_crypto::prelude::*;

    fn cuda_keyswitch<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
        criterion: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>)],
    ) {
        let bench_name = "core_crypto::cuda::keyswitch";
        let mut bench_group = criterion.benchmark_group(bench_name);

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

        for (name, params) in parameters.iter() {
            let lwe_dimension = params.lwe_dimension.unwrap();
            let glwe_dimension = params.glwe_dimension.unwrap();
            let polynomial_size = params.polynomial_size.unwrap();
            let ks_decomp_base_log = params.ks_base_log.unwrap();
            let ks_decomp_level_count = params.ks_level.unwrap();

            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut secret_generator,
            );

            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut secret_generator,
            );
            let big_lwe_sk = glwe_sk.into_lwe_secret_key();
            let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
                &big_lwe_sk,
                &lwe_sk,
                ks_decomp_base_log,
                ks_decomp_level_count,
                params.lwe_noise_distribution.unwrap(),
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            );
            let ksk_big_to_small_gpu =
                CudaLweKeyswitchKey::from_lwe_keyswitch_key(&ksk_big_to_small, &streams);

            let ct = allocate_and_encrypt_new_lwe_ciphertext(
                &big_lwe_sk,
                Plaintext(Scalar::ONE),
                params.lwe_noise_distribution.unwrap(),
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            );
            let mut ct_gpu = CudaLweCiphertextList::from_lwe_ciphertext(&ct, &streams);

            let output_ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_sk.lwe_dimension().to_lwe_size(),
                CiphertextModulus::new_native(),
            );
            let mut output_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&output_ct, &streams);

            let h_indexes = &[Scalar::ZERO];
            let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &streams, 0) };
            let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &streams, 0) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), &streams, 0);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), &streams, 0);
            }
            streams.synchronize();

            let id = format!("{bench_name}::{name}");
            {
                bench_group.bench_function(&id, |b| {
                    b.iter(|| {
                        cuda_keyswitch_lwe_ciphertext(
                            &ksk_big_to_small_gpu,
                            &ct_gpu,
                            &mut output_ct_gpu,
                            &d_input_indexes,
                            &d_output_indexes,
                            &streams,
                        );
                        black_box(&mut ct_gpu);
                    })
                });
            }
            let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
            write_to_json(
                &id,
                *params,
                name,
                "ks",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    fn cuda_packing_keyswitch<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
        criterion: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>)],
    ) {
        let bench_name = "core_crypto::cuda::packing_keyswitch";
        let mut bench_group = criterion.benchmark_group(bench_name);

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let gpu_index = 0;
        let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

        for (name, params) in parameters.iter() {
            let lwe_dimension = params.lwe_dimension.unwrap();
            let glwe_dimension = params.glwe_dimension.unwrap();
            let polynomial_size = params.polynomial_size.unwrap();
            let ks_decomp_base_log = params.ks_base_log.unwrap();
            let ks_decomp_level_count = params.ks_level.unwrap();
            let glwe_noise_distribution = params.glwe_noise_distribution.unwrap();
            let ciphertext_modulus = params.ciphertext_modulus.unwrap();

            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut secret_generator,
            );

            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut secret_generator,
            );

            let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
                &lwe_sk,
                &glwe_sk,
                ks_decomp_base_log,
                ks_decomp_level_count,
                glwe_noise_distribution,
                ciphertext_modulus,
                &mut encryption_generator,
            );

            let cuda_pksk =
                CudaLwePackingKeyswitchKey::from_lwe_packing_keyswitch_key(&pksk, &streams);

            let ct = LweCiphertextList::new(
                Scalar::ZERO,
                lwe_sk.lwe_dimension().to_lwe_size(),
                LweCiphertextCount(glwe_sk.polynomial_size().0),
                ciphertext_modulus,
            );
            let mut d_input_lwe_list =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&ct, &streams);

            let mut d_output_glwe = CudaGlweCiphertextList::new(
                glwe_sk.glwe_dimension(),
                glwe_sk.polynomial_size(),
                GlweCiphertextCount(1),
                ciphertext_modulus,
                &streams,
            );

            streams.synchronize();

            let id = format!("{bench_name}::{name}");
            {
                bench_group.bench_function(&id, |b| {
                    b.iter(|| {
                        cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext(
                            &cuda_pksk,
                            &d_input_lwe_list,
                            &mut d_output_glwe,
                            &streams,
                        );
                        black_box(&mut d_input_lwe_list);
                    })
                });
            }
            let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
            write_to_json(
                &id,
                *params,
                name,
                "packing_ks",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    pub fn cuda_keyswitch_group() {
        let mut criterion: Criterion<_> =
            (Criterion::default().sample_size(2000)).configure_from_args();
        cuda_keyswitch(&mut criterion, &benchmark_parameters_64bits());
        cuda_packing_keyswitch(&mut criterion, &benchmark_parameters_64bits());
    }
}

#[cfg(feature = "gpu")]
use cuda::cuda_keyswitch_group;

pub fn keyswitch_group() {
    let mut criterion: Criterion<_> = (Criterion::default()
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60)))
    .configure_from_args();
    keyswitch(&mut criterion, &benchmark_parameters_64bits());
    keyswitch(&mut criterion, &benchmark_parameters_32bits());
}

pub fn packing_keyswitch_group() {
    let mut criterion: Criterion<_> = (Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30)))
    .configure_from_args();
    packing_keyswitch(
        &mut criterion,
        "packing_keyswitch",
        &benchmark_compression_parameters(),
        keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext,
    );
    packing_keyswitch(
        &mut criterion,
        "par_packing_keyswitch",
        &benchmark_compression_parameters(),
        par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext,
    );
}

#[cfg(not(feature = "gpu"))]
criterion_main!(keyswitch_group, packing_keyswitch_group);
#[cfg(feature = "gpu")]
criterion_main!(cuda_keyswitch_group);
