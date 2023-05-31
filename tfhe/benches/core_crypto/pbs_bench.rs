#[path = "../utilities.rs"]
mod utilities;
use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe::boolean::parameters::{BooleanParameters, DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::keycache::NamedParam;
use tfhe::shortint::parameters::*;
use tfhe::shortint::PBSParameters;

const SHORTINT_BENCH_PARAMS: [PBSParameters; 15] = [
    PARAM_MESSAGE_1_CARRY_0,
    PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_2_CARRY_0,
    PARAM_MESSAGE_2_CARRY_1,
    PARAM_MESSAGE_2_CARRY_2,
    PARAM_MESSAGE_3_CARRY_0,
    PARAM_MESSAGE_3_CARRY_2,
    PARAM_MESSAGE_3_CARRY_3,
    PARAM_MESSAGE_4_CARRY_0,
    PARAM_MESSAGE_4_CARRY_3,
    PARAM_MESSAGE_4_CARRY_4,
    PARAM_MESSAGE_5_CARRY_0,
    PARAM_MESSAGE_6_CARRY_0,
    PARAM_MESSAGE_7_CARRY_0,
    PARAM_MESSAGE_8_CARRY_0,
];

const BOOLEAN_BENCH_PARAMS: [(&str, BooleanParameters); 2] = [
    ("BOOLEAN_DEFAULT_PARAMS", DEFAULT_PARAMETERS),
    ("BOOLEAN_TFHE_LIB_PARAMS", TFHE_LIB_PARAMETERS),
];

criterion_group!(
    name = pbs_group;
    config = Criterion::default().sample_size(100);
    targets = mem_optimized_pbs::<u64>, mem_optimized_pbs::<u32>
);

criterion_group!(
    name = multi_bit_pbs_group;
    config = Criterion::default().sample_size(2000);
    targets = multi_bit_pbs::<u64>, multi_bit_pbs::<u32>
);

criterion_group!(
    name = tensor_prod_with_relin_group;
    config = Criterion::default().sample_size(100);
    targets = tensor_product_with_relin::<u64>
);

criterion_group!(
    name = public_funct_ks_group;
    config = Criterion::default().sample_size(100);
    targets = public_funct_ks::<u64>
);

criterion_group!(
    name = packed_mult_group;
    config = Criterion::default().sample_size(100);
    targets = packed_mul::<u64>
);

criterion_group!(
    name = sum_of_products_group;
    config = Criterion::default().sample_size(100);
    targets = packed_sum_prod::<u64>
);

criterion_main!(pbs_group, tensor_prod_with_relin_group);

fn benchmark_parameters<Scalar: Numeric>() -> Vec<(String, CryptoParametersRecord)> {
    if Scalar::BITS == 64 {
        SHORTINT_BENCH_PARAMS
            .iter()
            .map(|params| (params.name(), params.to_owned().into()))
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

fn multi_bit_benchmark_parameters<Scalar: Numeric>(
) -> Vec<(String, (CryptoParametersRecord, LweBskGroupingFactor))> {
    if Scalar::BITS == 64 {
        vec![
            (
                "2_bits_multi_bit_group_2".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(764)),
                        lwe_modular_std_dev: Some(StandardDev(0.000006025673585415336)),
                        pbs_base_log: Some(DecompositionBaseLog(18)),
                        pbs_level: Some(DecompositionLevelCount(1)),
                        glwe_dimension: Some(GlweDimension(3)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                        polynomial_size: Some(PolynomialSize(1 << 9)),
                        message_modulus: Some(1),
                        carry_modulus: Some(1),
                        ..Default::default()
                    },
                    LweBskGroupingFactor(2),
                ),
            ),
            (
                "2_bits_multi_bit_group_3".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(765)),
                        lwe_modular_std_dev: Some(StandardDev(0.000005915594083804978)),
                        pbs_base_log: Some(DecompositionBaseLog(18)),
                        pbs_level: Some(DecompositionLevelCount(1)),
                        glwe_dimension: Some(GlweDimension(3)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                        polynomial_size: Some(PolynomialSize(1 << 9)),
                        message_modulus: Some(1),
                        carry_modulus: Some(1),
                        ..Default::default()
                    },
                    LweBskGroupingFactor(3),
                ),
            ),
            (
                "4_bits_multi_bit_group_2".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(818)),
                        lwe_modular_std_dev: Some(StandardDev(0.000002226459789930014)),
                        pbs_base_log: Some(DecompositionBaseLog(22)),
                        pbs_level: Some(DecompositionLevelCount(1)),
                        glwe_dimension: Some(GlweDimension(1)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000000003152931493498455)),
                        polynomial_size: Some(PolynomialSize(1 << 11)),
                        message_modulus: Some(2),
                        carry_modulus: Some(2),
                        ..Default::default()
                    },
                    LweBskGroupingFactor(2),
                ),
            ),
            (
                "4_bits_multi_bit_group_3".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(888)),
                        lwe_modular_std_dev: Some(StandardDev(0.000002226459789930014)),
                        pbs_base_log: Some(DecompositionBaseLog(21)),
                        pbs_level: Some(DecompositionLevelCount(1)),
                        glwe_dimension: Some(GlweDimension(1)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000000003152931493498455)),
                        polynomial_size: Some(PolynomialSize(1 << 11)),
                        message_modulus: Some(2),
                        carry_modulus: Some(2),
                        ..Default::default()
                    },
                    LweBskGroupingFactor(3),
                ),
            ),
            (
                "6_bits_multi_bit_group_2".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(922)),
                        lwe_modular_std_dev: Some(StandardDev(0.0000003272369292345697)),
                        pbs_base_log: Some(DecompositionBaseLog(14)),
                        pbs_level: Some(DecompositionLevelCount(2)),
                        glwe_dimension: Some(GlweDimension(1)),
                        glwe_modular_std_dev: Some(StandardDev(
                            0.0000000000000000002168404344971009,
                        )),
                        polynomial_size: Some(PolynomialSize(1 << 13)),
                        message_modulus: Some(3),
                        carry_modulus: Some(3),
                        ..Default::default()
                    },
                    LweBskGroupingFactor(2),
                ),
            ),
            (
                "6_bits_multi_bit_group_3".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(972)),
                        lwe_modular_std_dev: Some(StandardDev(0.00000013016688349592805)),
                        pbs_base_log: Some(DecompositionBaseLog(14)),
                        pbs_level: Some(DecompositionLevelCount(2)),
                        glwe_dimension: Some(GlweDimension(1)),
                        glwe_modular_std_dev: Some(StandardDev(
                            0.0000000000000000002168404344971009,
                        )),
                        polynomial_size: Some(PolynomialSize(1 << 13)),
                        message_modulus: Some(3),
                        carry_modulus: Some(3),
                        ..Default::default()
                    },
                    LweBskGroupingFactor(3),
                ),
            ),
            (
                "8_bits_multi_bit_group_2".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(1052)),
                        lwe_modular_std_dev: Some(StandardDev(0.000000029779789543501806)),
                        pbs_base_log: Some(DecompositionBaseLog(14)),
                        pbs_level: Some(DecompositionLevelCount(2)),
                        glwe_dimension: Some(GlweDimension(1)),
                        glwe_modular_std_dev: Some(StandardDev(
                            0.0000000000000000002168404344971009,
                        )),
                        polynomial_size: Some(PolynomialSize(1 << 15)),
                        message_modulus: Some(4),
                        carry_modulus: Some(4),
                        ..Default::default()
                    },
                    LweBskGroupingFactor(2),
                ),
            ),
            (
                "8_bits_multi_bit_group_3".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(1098)),
                        lwe_modular_std_dev: Some(StandardDev(0.000000012752307213087621)),
                        pbs_base_log: Some(DecompositionBaseLog(14)),
                        pbs_level: Some(DecompositionLevelCount(2)),
                        glwe_dimension: Some(GlweDimension(1)),
                        glwe_modular_std_dev: Some(StandardDev(
                            0.0000000000000000002168404344971009,
                        )),
                        polynomial_size: Some(PolynomialSize(1 << 15)),
                        message_modulus: Some(4),
                        carry_modulus: Some(4),
                        ..Default::default()
                    },
                    LweBskGroupingFactor(3),
                ),
            ),
        ]
    } else {
        // For now there are no parameters available to test multi bit PBS on 32 bits.
        vec![]
    }
}

fn mem_optimized_pbs<Scalar: UnsignedTorus + CastInto<usize>>(c: &mut Criterion) {
    let bench_name = "PBS_mem-optimized";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for (name, params) in packed_operations_benchmark_parameters::<Scalar>().iter() {
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

fn multi_bit_pbs<Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync>(
    c: &mut Criterion,
) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweBootstrapKey creation

    let bench_name = "multi_bits_PBS";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for (name, (params, grouping_factor)) in multi_bit_benchmark_parameters::<Scalar>().iter() {
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

//TODO check parameters
fn tensor_prod_with_relin_benchmark_parameters<Scalar: Numeric>(
) -> Vec<(String, CryptoParametersRecord)> {
    if Scalar::BITS == 64 {
        vec![
            (
                "1_bits_prec".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(550)),
                        ks_base_log: Some(DecompositionBaseLog(8)),
                        ks_level: Some(DecompositionLevelCount(8)),
                        glwe_dimension: Some(GlweDimension(3)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                        polynomial_size: Some(PolynomialSize(1 << 12)),
                        message_modulus: Some(1),
                        ..Default::default()
                    }
                ),
            ),
            (
                "2_bits_prec".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(550)),
                        ks_base_log: Some(DecompositionBaseLog(5)),
                        ks_level: Some(DecompositionLevelCount(10)),
                        glwe_dimension: Some(GlweDimension(3)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                        polynomial_size: Some(PolynomialSize(1 << 11)),
                        message_modulus: Some(1),
                        ..Default::default()
                    }
                ),
            ),
            (
                "3_bits_prec".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(550)),
                        ks_base_log: Some(DecompositionBaseLog(8)),
                        ks_level: Some(DecompositionLevelCount(8)),
                        glwe_dimension: Some(GlweDimension(3)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                        polynomial_size: Some(PolynomialSize(1 << 12)),
                        message_modulus: Some(1),
                        ..Default::default()
                    }
                ),
            ),
            (
                "4_bits_multi_bit_group_2".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(550)),
                        ks_base_log: Some(DecompositionBaseLog(12)),
                        ks_level: Some(DecompositionLevelCount(4)),
                        glwe_dimension: Some(GlweDimension(3)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000000003152931493498455)),
                        polynomial_size: Some(PolynomialSize(1 << 11)),
                        message_modulus: Some(2),
                        ..Default::default()
                    }
                ),
            ),
        ]
    } else {
        // For now there are no parameters available to test multi bit PBS on 32 bits.
        vec![]
    }
}


fn tensor_product_with_relin<Scalar: UnsignedTorus + CastInto<usize>>(c: &mut Criterion) 
{
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
        
    let ciphertext_modulus: tfhe::core_crypto::prelude::CiphertextModulus<Scalar> = tfhe::core_crypto::prelude::CiphertextModulus::new_native();

    for (name, params) in packed_operations_benchmark_parameters::<Scalar>().iter() 
    {
        // Create the GlweSecretKey
        let glwe_secret_key: GlweSecretKeyOwned<Scalar>  = allocate_and_generate_new_binary_glwe_secret_key(
            params.glwe_dimension.unwrap(),
            params.polynomial_size.unwrap(),
            &mut secret_generator,
        );

        let glwe_relin_key = allocate_and_generate_glwe_relinearisation_key(
            &glwe_secret_key,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.glwe_modular_std_dev.unwrap(),
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let log_delta1 = 59;
        let log_delta2 = 60;
        let log_delta = std::cmp::min(log_delta1, log_delta2);
        //let output_log_delta = log_delta1 + log_delta2 - log_delta;

    
        // Allocate a new GlweCiphertext and encrypt our plaintext
        let mut glwe_1 = GlweCiphertext::new(Scalar::ZERO, 
            params.glwe_dimension.unwrap().to_glwe_size(), 
            params.polynomial_size.unwrap(), 
            ciphertext_modulus);
        encrypt_glwe_ciphertext_assign(&glwe_secret_key,
            & mut glwe_1,params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,);
        let mut glwe_2 = GlweCiphertext::new(Scalar::ZERO, 
            params.glwe_dimension.unwrap().to_glwe_size(), 
            params.polynomial_size.unwrap(), 
            ciphertext_modulus);
        encrypt_glwe_ciphertext_assign(&glwe_secret_key,
            & mut glwe_2,params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,);

        // Perform the tensor product
        let scale =Scalar::ONE << log_delta;
        //let tensor_output = glwe_tensor_product(&glwe_1, &glwe_2, scale);
    
        let mut output_glwe_ciphertext =
            GlweCiphertext::new(Scalar::ZERO, params.glwe_dimension.unwrap().to_glwe_size(), params.polynomial_size.unwrap(), ciphertext_modulus);

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
                        & mut output_glwe_ciphertext,
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

//TODO check parameters
fn packed_operations_benchmark_parameters<Scalar: Numeric>(
) -> Vec<(String, CryptoParametersRecord)> {
    if Scalar::BITS == 64 {
        vec![
            (
                "1_bits_prec".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(12288)),
                        lwe_modular_std_dev: Some(StandardDev(0.000000012752307213087621)),
                        ks_base_log: Some(DecompositionBaseLog(8)),
                        ks_level: Some(DecompositionLevelCount(8)),
                        glwe_dimension: Some(GlweDimension(1)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                        polynomial_size: Some(PolynomialSize(1 << 12)),
                        message_modulus: Some(2),
                        pbs_base_log: Some(DecompositionBaseLog(8)),
                        pbs_level: Some(DecompositionLevelCount(8)),
                        ..Default::default()
                    }
                ),
            ),
            /*(
                "2_bits_prec".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(6144)),
                        ks_base_log: Some(DecompositionBaseLog(5)),
                        ks_level: Some(DecompositionLevelCount(10)),
                        glwe_dimension: Some(GlweDimension(3)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                        polynomial_size: Some(PolynomialSize(1 << 11)),
                        message_modulus: Some(1),
                        ..Default::default()
                    }
                ),
            ),
            (
                "3_bits_prec".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(12288)),
                        ks_base_log: Some(DecompositionBaseLog(8)),
                        ks_level: Some(DecompositionLevelCount(8)),
                        glwe_dimension: Some(GlweDimension(3)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000039666089171633006)),
                        polynomial_size: Some(PolynomialSize(1 << 12)),
                        message_modulus: Some(1),
                        ..Default::default()
                    }
                ),
            ),
            (
                "4_bits_prec".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(6144)),
                        ks_base_log: Some(DecompositionBaseLog(12)),
                        ks_level: Some(DecompositionLevelCount(4)),
                        glwe_dimension: Some(GlweDimension(3)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000000003152931493498455)),
                        polynomial_size: Some(PolynomialSize(1 << 11)),
                        message_modulus: Some(2),
                        ..Default::default()
                    }
                ),
            ),*/
            (
                "8_bits_prec".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(2048)),
                        lwe_modular_std_dev: Some(StandardDev(0.000000012752307213087621)),
                        ks_base_log: Some(DecompositionBaseLog(20)),
                        ks_level: Some(DecompositionLevelCount(2)),
                        glwe_dimension: Some(GlweDimension(1)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000000003152931493498455)),
                        polynomial_size: Some(PolynomialSize(1 << 11)),
                        message_modulus: Some(2^8),
                        pbs_base_log: Some(DecompositionBaseLog(20)),
                        pbs_level: Some(DecompositionLevelCount(2)),
                        ..Default::default()
                    }
                ),
            ),
            (
                "6_bits_prec".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(2048)),
                        lwe_modular_std_dev: Some(StandardDev(0.000000012752307213087621)),
                        ks_base_log: Some(DecompositionBaseLog(8)),
                        ks_level: Some(DecompositionLevelCount(8)),
                        glwe_dimension: Some(GlweDimension(1)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000000003152931493498455)),
                        polynomial_size: Some(PolynomialSize(1 << 12)),
                        message_modulus: Some(2^6),
                        pbs_base_log: Some(DecompositionBaseLog(8)),
                        pbs_level: Some(DecompositionLevelCount(8)),
                        ..Default::default()
                    }
                ),
            ),
            (
                "7_bits_prec".to_string(),
                (
                    CryptoParametersRecord {
                        lwe_dimension: Some(LweDimension(2048)),
                        lwe_modular_std_dev: Some(StandardDev(0.000000012752307213087621)),
                        ks_base_log: Some(DecompositionBaseLog(8)),
                        ks_level: Some(DecompositionLevelCount(8)),
                        glwe_dimension: Some(GlweDimension(1)),
                        glwe_modular_std_dev: Some(StandardDev(0.0000000000000003152931493498455)),
                        polynomial_size: Some(PolynomialSize(1 << 12)),
                        message_modulus: Some(2^7),
                        pbs_base_log: Some(DecompositionBaseLog(8)),
                        pbs_level: Some(DecompositionLevelCount(8)),
                        ..Default::default()
                    }
                ),
            ),
        ]
    } else {
        // For now there are no parameters available to test multi bit PBS on 32 bits.
        vec![]
    }
}

fn public_funct_ks<Scalar: UnsignedTorus + CastInto<usize>>(c: &mut Criterion)
{
    //only written for local development benchmarking
    let bench_name = "public_funct_ks";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        
    let ciphertext_modulus: tfhe::core_crypto::prelude::CiphertextModulus<Scalar> = tfhe::core_crypto::prelude::CiphertextModulus::new_native();

    for (name, params) in packed_operations_benchmark_parameters::<Scalar>().iter() 
    {
        // Create the LweSecretKey
        let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );

        // Create the GlweSecretKey
        let glwe_secret_key: GlweSecretKeyOwned<Scalar>  = allocate_and_generate_new_binary_glwe_secret_key(
            params.glwe_dimension.unwrap(),
            params.polynomial_size.unwrap(),
            &mut secret_generator,
        );
        let mut lwe_pubfpksk = LwePublicFunctionalPackingKeyswitchKey::new(
            Scalar::ZERO,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            ciphertext_modulus,
            );
        generate_lwe_public_functional_packing_keyswitch_key(
            &lwe_secret_key,
            &glwe_secret_key,
            &mut lwe_pubfpksk,
            params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
            );
            let lwe_ciphertext_count = LweCiphertextCount(20);
        let lwe_plaintext_list = PlaintextList::new(Scalar::ONE << 59, PlaintextCount(20));
        let mut lwe_list_1 = LweCiphertextList::new(
            Scalar::ZERO,
            params.lwe_dimension.unwrap().to_lwe_size(),
            lwe_ciphertext_count,
            ciphertext_modulus,
            );
        encrypt_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut lwe_list_1,
            &lwe_plaintext_list,
            params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
            );

        let mut output_glwe_ciphertext =
        GlweCiphertext::new(Scalar::ZERO, params.glwe_dimension.unwrap().to_glwe_size(), params.polynomial_size.unwrap(), ciphertext_modulus);
        
        let id = format!("{bench_name}_{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {

                    public_functional_keyswitch_lwe_ciphertexts_into_glwe_ciphertext(
                        &lwe_pubfpksk,
                        &mut output_glwe_ciphertext,
                        &lwe_list_1,
                        | x: Vec<Scalar>| {
                            let mut packed1: Vec<Scalar> = vec![Scalar::ZERO;lwe_pubfpksk.output_polynomial_size().0];
                            x.iter().enumerate().for_each(|(iter,y)| packed1[iter] = *y);
                            Polynomial::from_container(packed1)
                            }
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
            "packed mult",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn packed_mul<Scalar: UnsignedTorus + CastInto<usize>>(c: &mut Criterion) 
{
    //only written for local development benchmarking
    let bench_name = "packed_multiplication";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        
    let ciphertext_modulus: tfhe::core_crypto::prelude::CiphertextModulus<Scalar> = tfhe::core_crypto::prelude::CiphertextModulus::new_native();

    for (name, params) in packed_operations_benchmark_parameters::<Scalar>().iter() 
    {
        // Create the LweSecretKey
        let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );

        // Create the GlweSecretKey
        let glwe_secret_key: GlweSecretKeyOwned<Scalar>  = allocate_and_generate_new_binary_glwe_secret_key(
            params.glwe_dimension.unwrap(),
            params.polynomial_size.unwrap(),
            &mut secret_generator,
        );

        let glwe_relin_key = allocate_and_generate_glwe_relinearisation_key(
            &glwe_secret_key,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.glwe_modular_std_dev.unwrap(),
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut lwe_pubfpksk = LwePublicFunctionalPackingKeyswitchKey::new(
            Scalar::ZERO,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            ciphertext_modulus,
            );
        generate_lwe_public_functional_packing_keyswitch_key(
            &lwe_secret_key,
            &glwe_secret_key,
            &mut lwe_pubfpksk,
            params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
            );

        let log_delta1 = 59;
        let log_delta2 = 60;
        let log_delta = std::cmp::min(log_delta1, log_delta2);

        let lwe_ciphertext_count = LweCiphertextCount(20);
        let lwe_plaintext_list = PlaintextList::new(Scalar::ONE << 59, PlaintextCount(20));
        let mut lwe_list_1 = LweCiphertextList::new(
            Scalar::ZERO,
            params.lwe_dimension.unwrap().to_lwe_size(),
            lwe_ciphertext_count,
            ciphertext_modulus,
            );
        encrypt_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut lwe_list_1,
            &lwe_plaintext_list,
            params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
            );
        let mut lwe_list_2 = LweCiphertextList::new(
            Scalar::ZERO,
            params.lwe_dimension.unwrap().to_lwe_size(),
            lwe_ciphertext_count,
            ciphertext_modulus,
            );
        encrypt_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut lwe_list_2,
            &lwe_plaintext_list,
            params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
            );

        // Perform the tensor product
        let scale =Scalar::ONE << log_delta;

        let mut output_lwe_list = 
            LweCiphertextList::new(
                Scalar::ZERO,
                //fix this LWE dimension to be k*N
                params.lwe_dimension.unwrap().to_lwe_size(),
                lwe_ciphertext_count,
                ciphertext_modulus,
                );

        let id = format!("{bench_name}_{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {

                    packed_mult(
                        &lwe_list_1,
                        &lwe_list_2,
                        &lwe_pubfpksk,
                        &glwe_relin_key,
                        scale,
                        &mut output_lwe_list,
                    );
                black_box(&mut output_lwe_list);
                })
            });
        }
    
        let bit_size = (params.message_modulus.unwrap_or(2) as u64).ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "packed mult",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn packed_sum_prod<Scalar: UnsignedTorus + CastInto<usize>>(c: &mut Criterion) 
{
    //only written for local development benchmarking
    let bench_name = "sum_of_products";
    let mut bench_group = c.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        
    let ciphertext_modulus: tfhe::core_crypto::prelude::CiphertextModulus<Scalar> = tfhe::core_crypto::prelude::CiphertextModulus::new_native();

    for (name, params) in packed_operations_benchmark_parameters::<Scalar>().iter() 
    {
        // Create the LweSecretKey
        let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );

        // Create the GlweSecretKey
        let glwe_secret_key: GlweSecretKeyOwned<Scalar>  = allocate_and_generate_new_binary_glwe_secret_key(
            params.glwe_dimension.unwrap(),
            params.polynomial_size.unwrap(),
            &mut secret_generator,
        );

        let glwe_relin_key = allocate_and_generate_glwe_relinearisation_key(
            &glwe_secret_key,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.glwe_modular_std_dev.unwrap(),
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut lwe_pubfpksk = LwePublicFunctionalPackingKeyswitchKey::new(
            Scalar::ZERO,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            ciphertext_modulus,
            );
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        generate_lwe_public_functional_packing_keyswitch_key(
            &lwe_secret_key,
            &glwe_secret_key,
            &mut lwe_pubfpksk,
            params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
            );

        let lwe_ciphertext_count= LweCiphertextCount(20);
        let lwe_plaintext_list = PlaintextList::new(Scalar::ONE << 59, PlaintextCount(20));
        let mut lwe_list_1 = LweCiphertextList::new(
            Scalar::ZERO,
            params.lwe_dimension.unwrap().to_lwe_size(),
            lwe_ciphertext_count,
            ciphertext_modulus,
            );
        encrypt_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut lwe_list_1,
            &lwe_plaintext_list,
            params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
            );
        let mut lwe_list_2 = LweCiphertextList::new(
            Scalar::ZERO,
            params.lwe_dimension.unwrap().to_lwe_size(),
            lwe_ciphertext_count,
            ciphertext_modulus,
            );
        encrypt_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut lwe_list_2,
            &lwe_plaintext_list,
            params.glwe_modular_std_dev.unwrap(),
            &mut encryption_generator,
            );


        let log_delta1 = 59;
        let log_delta2 = 60;
        let log_delta = std::cmp::min(log_delta1, log_delta2);

        // Perform the tensor product
        let scale =Scalar::ONE << log_delta;
    
        let mut output_lwe_ciphertext = LweCiphertext::new(
            Scalar::ZERO,
            params.lwe_dimension.unwrap().to_lwe_size(),
            ciphertext_modulus,
            );

        let id = format!("{bench_name}_{name}");
        {
            bench_group.bench_function(&id, |b| {
                b.iter(|| {
                    packed_sum_product(
                        &lwe_list_1,
                        &lwe_list_2,
                        &lwe_pubfpksk,
                        &glwe_relin_key,
                        scale,
                        &mut output_lwe_ciphertext
                    );
                    black_box(&mut output_lwe_ciphertext);
                })
            });
        }
    
        let bit_size = (params.message_modulus.unwrap_or(2) as u64).ilog2();
        write_to_json(
            &id,
            *params,
            name,
            "sum of products",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}