use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe::boolean::parameters::{BooleanParameters, DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::keycache::NamedParam;
use tfhe::shortint::parameters::*;
use tfhe::shortint::Parameters;

const SHORTINT_BENCH_PARAMS: [Parameters; 15] = [
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
    ("boolean_default_params", DEFAULT_PARAMETERS),
    ("boolean_tfhe_lib_params", TFHE_LIB_PARAMETERS),
];

const MULTI_BIT_PARAMS: [(&str, (BenchmarkPbsParameters, LweBskGroupingFactor)); 2] = [
    (
        "4_bits_multi_bit_group_2",
        (
            BenchmarkPbsParameters {
                input_lwe_dimension: LweDimension(724),
                lwe_modular_std_dev: StandardDev(1.58705e-10),
                decomp_base_log: DecompositionBaseLog(1),
                decomp_level_count: DecompositionLevelCount(18),
                glwe_dimension: GlweDimension(3),
                polynomial_size: PolynomialSize(512),
            },
            LweBskGroupingFactor(2),
        ),
    ),
    (
        "4_bits_multi_bit_group_3",
        (
            BenchmarkPbsParameters {
                input_lwe_dimension: LweDimension(732),
                lwe_modular_std_dev: StandardDev(1.18161e-10),
                decomp_base_log: DecompositionBaseLog(1),
                decomp_level_count: DecompositionLevelCount(18),
                glwe_dimension: GlweDimension(3),
                polynomial_size: PolynomialSize(512),
            },
            LweBskGroupingFactor(3),
        ),
    ),
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

#[derive(Clone, Copy)]
struct BenchmarkPbsParameters {
    input_lwe_dimension: LweDimension,
    lwe_modular_std_dev: StandardDev,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
}

impl From<BooleanParameters> for BenchmarkPbsParameters {
    fn from(params: BooleanParameters) -> Self {
        BenchmarkPbsParameters {
            input_lwe_dimension: params.lwe_dimension,
            lwe_modular_std_dev: params.lwe_modular_std_dev,
            decomp_base_log: params.pbs_base_log,
            decomp_level_count: params.pbs_level,
            glwe_dimension: params.glwe_dimension,
            polynomial_size: params.polynomial_size,
        }
    }
}

impl From<Parameters> for BenchmarkPbsParameters {
    fn from(params: Parameters) -> Self {
        BenchmarkPbsParameters {
            input_lwe_dimension: params.lwe_dimension,
            lwe_modular_std_dev: params.lwe_modular_std_dev,
            decomp_base_log: params.pbs_base_log,
            decomp_level_count: params.pbs_level,
            glwe_dimension: params.glwe_dimension,
            polynomial_size: params.polynomial_size,
        }
    }
}

fn benchmark_parameters<Scalar: Numeric>() -> Vec<(String, BenchmarkPbsParameters)> {
    if Scalar::BITS == 64 {
        SHORTINT_BENCH_PARAMS
            .iter()
            .map(|params| {
                (
                    format!("shortint_{}", params.name().to_lowercase()),
                    params.to_owned().into(),
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

fn multi_bit_benchmark_parameters<Scalar: Numeric>(
) -> Vec<(String, (BenchmarkPbsParameters, LweBskGroupingFactor))> {
    if Scalar::BITS == 64 {
        MULTI_BIT_PARAMS
            .iter()
            .map(|(name, (params, grouping_factor))| {
                (
                    name.to_string(),
                    (params.to_owned(), grouping_factor.to_owned()),
                )
            })
            .collect()
    } else {
        vec![]
    }
}

fn mem_optimized_pbs<Scalar: UnsignedTorus + CastInto<usize>>(c: &mut Criterion) {
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
            params.input_lwe_dimension,
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
            params.input_lwe_dimension,
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
            params.decomp_base_log,
            params.decomp_level_count,
        );

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_modular_std_dev,
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
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

        let id = format!("PBS_mem-optimized_{name}");
        {
            c.bench_function(&id, |b| {
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
    }
}

fn multi_bit_pbs<Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync>(
    c: &mut Criterion,
) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweBootstrapKey creation

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
            params.input_lwe_dimension,
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut secret_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        let multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
            params.input_lwe_dimension,
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
            params.decomp_base_log,
            params.decomp_level_count,
            *grouping_factor,
        );

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            Plaintext(Scalar::ZERO),
            params.lwe_modular_std_dev,
            &mut encryption_generator,
        );

        let accumulator = GlweCiphertext::new(
            Scalar::ZERO,
            params.glwe_dimension.to_glwe_size(),
            params.polynomial_size,
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut out_pbs_ct = LweCiphertext::new(
            Scalar::ZERO,
            output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        );

        let id = format!("multi-bit-PBS_{name}");
        c.bench_function(&id, |b| {
            b.iter(|| {
                multi_bit_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator.as_view(),
                    &multi_bit_bsk,
                    // Leave one thread to the OS and one for the ext product loop
                    ThreadCount(2.max(num_cpus::get_physical() - 2)),
                );
                black_box(&mut out_pbs_ct);
            })
        });
    }
}
