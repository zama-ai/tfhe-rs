#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde::Serialize;
use tfhe::boolean::prelude::*;
use tfhe::core_crypto::prelude::*;
use tfhe::keycache::NamedParam;
#[cfg(feature = "gpu")]
use tfhe::shortint::parameters::{
    PARAM_GPU_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
    PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
};
#[cfg(not(feature = "gpu"))]
use tfhe::shortint::parameters::{
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
};
use tfhe::shortint::prelude::*;
use tfhe::shortint::{MultiBitPBSParameters, PBSParameters};

const SHORTINT_BENCH_PARAMS: [ClassicPBSParameters; 4] = [
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
];

#[cfg(not(feature = "gpu"))]
const SHORTINT_MULTI_BIT_BENCH_PARAMS: [MultiBitPBSParameters; 6] = [
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
];

#[cfg(feature = "gpu")]
const SHORTINT_MULTI_BIT_BENCH_PARAMS: [MultiBitPBSParameters; 2] = [
    PARAM_GPU_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
    PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
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
            .collect::<Vec<(String, CryptoParametersRecord<Scalar>)>>();
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
    } else if Scalar::BITS == 32 {
        BOOLEAN_BENCH_PARAMS
            .iter()
            .map(|(name, params)| (name.to_string(), params.to_owned().into()))
            .collect()
    } else {
        vec![]
    }
}

fn keyswitch<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(criterion: &mut Criterion) {
    let bench_name = "core_crypto::keyswitch";
    let mut bench_group = criterion.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for (name, params) in benchmark_parameters::<Scalar>().iter() {
        let lwe_dimension = params.lwe_dimension.unwrap();
        let lwe_noise_distribution =
            DynamicDistribution::new_gaussian_from_std_dev(params.lwe_std_dev.unwrap());
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
            lwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            &big_lwe_sk,
            Plaintext(Scalar::ONE),
            lwe_noise_distribution,
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
            &mut encryption_generator,
        );

        let mut output_ct = LweCiphertext::new(
            Scalar::ZERO,
            lwe_sk.lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::CiphertextModulus::new_native(),
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

#[cfg(feature = "gpu")]
mod cuda {
    use crate::benchmark_parameters;
    use crate::utilities::{write_to_json, OperatorType};
    use criterion::{black_box, criterion_group, Criterion};
    use serde::Serialize;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
    use tfhe::core_crypto::gpu::vec::CudaVec;
    use tfhe::core_crypto::gpu::{cuda_keyswitch_lwe_ciphertext, CudaDevice, CudaStream};
    use tfhe::core_crypto::prelude::*;

    fn cuda_keyswitch<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
        criterion: &mut Criterion,
    ) {
        let bench_name = "core_crypto::cuda::keyswitch";
        let mut bench_group = criterion.benchmark_group(bench_name);

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
            let lwe_dimension = params.lwe_dimension.unwrap();
            let lwe_noise_distribution =
                DynamicDistribution::new_gaussian_from_std_dev(params.lwe_std_dev.unwrap());
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
                lwe_noise_distribution,
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            );
            let ksk_big_to_small_gpu =
                CudaLweKeyswitchKey::from_lwe_keyswitch_key(&ksk_big_to_small, &stream);

            let ct = allocate_and_encrypt_new_lwe_ciphertext(
                &big_lwe_sk,
                Plaintext(Scalar::ONE),
                lwe_noise_distribution,
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            );
            let mut ct_gpu = CudaLweCiphertextList::from_lwe_ciphertext(&ct, &stream);

            let output_ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_sk.lwe_dimension().to_lwe_size(),
                CiphertextModulus::new_native(),
            );
            let mut output_ct_gpu = CudaLweCiphertextList::from_lwe_ciphertext(&output_ct, &stream);

            let h_indexes = &[Scalar::ZERO];
            let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream) };
            let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(1, &stream) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
                d_output_indexes.copy_from_cpu_async(h_indexes.as_ref(), &stream);
            }
            stream.synchronize();

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
                            &stream,
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
    criterion_group!(
        name = cuda_keyswitch_group;
        config = Criterion::default().sample_size(2000);
        targets = cuda_keyswitch::<u64>
    );
}

#[cfg(feature = "gpu")]
use cuda::cuda_keyswitch_group;

criterion_group!(
    name = keyswitch_group;
    config = Criterion::default().sample_size(2000);
    targets = keyswitch::<u64>, keyswitch::<u32>
);
#[cfg(not(feature = "gpu"))]
criterion_main!(keyswitch_group);
#[cfg(feature = "gpu")]
criterion_main!(cuda_keyswitch_group);
