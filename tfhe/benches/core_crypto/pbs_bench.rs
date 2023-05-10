#[path = "../utilities.rs"]
mod utilities;
use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe::boolean::parameters::{BooleanParameters, DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::keycache::NamedParam;
use tfhe::shortint::parameters::*;
use tfhe::shortint::ClassicPBSParameters;

const SHORTINT_BENCH_PARAMS: [ClassicPBSParameters; 15] = [
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
    config = Criterion::default().sample_size(2000);
    targets = mem_optimized_pbs::<u64>, mem_optimized_pbs::<u32>
);

criterion_group!(
    name = multi_bit_pbs_group;
    config = Criterion::default().sample_size(2000);
    targets = multi_bit_pbs::<u64>, multi_bit_pbs::<u32>
);

criterion_main!(pbs_group, multi_bit_pbs_group);

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
                        lwe_modular_std_dev: Some(StandardDev(0.0000006125031601933181)),
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
