mod noise_estimation;
mod operators;

use crate::operators::classic_pbs::{
    classic_pbs_external_product, classic_pbs_external_product_u128,
    classic_pbs_external_product_u128_split,
};
use crate::operators::multi_bit_pbs::{
    multi_bit_pbs_external_product, std_multi_bit_pbs_external_product,
};
use clap::Parser;
use concrete_security_curves::gaussian::security::minimal_variance_glwe;
use itertools::iproduct;
use std::fs::OpenOptions;
use std::io::Write;
use tfhe::core_crypto::algorithms::misc::torus_modular_diff;
use tfhe::core_crypto::prelude::*;

pub const DEBUG: bool = false;
pub const EXT_PROD_ALGO: &str = "ext-prod";
pub const MULTI_BIT_EXT_PROD_ALGO: &str = "multi-bit-ext-prod";
pub const STD_MULTI_BIT_EXT_PROD_ALGO: &str = "std-multi-bit-ext-prod";
pub const EXT_PROD_U128_SPLIT_ALGO: &str = "ext-prod-u128-split";
pub const EXT_PROD_U128_ALGO: &str = "ext-prod-u128";

#[derive(Debug)]
pub struct GlweCiphertextGgswCiphertextExternalProductParameters<Scalar: UnsignedInteger> {
    pub ggsw_noise: Variance,
    pub glwe_noise: Variance,
    pub glwe_dimension: GlweDimension,
    pub ggsw_encrypted_value: Scalar,
    pub polynomial_size: PolynomialSize,
    pub decomposition_base_log: DecompositionBaseLog,
    pub decomposition_level_count: DecompositionLevelCount,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Total number of threads.
    #[clap(long, short)]
    tot: usize,
    /// Current Thread ID
    #[clap(long, short)]
    id: usize,
    /// Number of time a test is repeated for a single set of parameter.
    /// This indicates the number of different keys since, at each repetition, we re-sample
    /// everything
    #[clap(long, short, default_value_t = 10)]
    repetitions: usize,
    /// The size of the sample per key
    #[clap(long, short = 'S', default_value_t = 10)]
    sample_size: usize,
    /// Step used for testing levels beyond 20in hypercube.
    /// Example: with a step of 3, tested levels tested would be: 1 through 20 then 21, 24, 27, etc
    #[clap(long, short = 's', default_value_t = 1)]
    steps: usize,
    /// Which algorithm to measure fft noise for
    #[clap(long, short = 'a', value_parser = [
        EXT_PROD_ALGO,
        MULTI_BIT_EXT_PROD_ALGO,
        STD_MULTI_BIT_EXT_PROD_ALGO,
        EXT_PROD_U128_SPLIT_ALGO,
        EXT_PROD_U128_ALGO
    ], default_value = "")]
    algorithm: String,
    multi_bit_grouping_factor: Option<usize>,
    #[clap(long, short = 'q')]
    modulus_log2: Option<u32>,
    #[clap(long, short = 'd', default_value = ".")]
    dir: String,
}

fn variance_to_stddev(var: Variance) -> StandardDev {
    StandardDev::from_standard_dev(var.get_standard_dev())
}

fn get_analysis_output_file(dir: &str, id: usize) -> std::fs::File {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .create(true)
        .open(format!("{dir}/{id}.algo_sample_acquistion"))
    {
        Err(why) => panic!("{why}"),
        Ok(file) => file,
    }
}

fn prepare_output_file_header(dir: &str, id: usize) {
    let mut file = get_analysis_output_file(dir, id);
    let header =
        "polynomial_size, glwe_dimension, decomposition_level_count, decomposition_base_log, \
    ggsw_encrypted_value, input_variance, output_variance, predicted_variance, mean_runtime_ns, \
    prep_time_ns\n";
    let _ = file.write(header.as_bytes()).unwrap();
}

fn write_to_file<Scalar: UnsignedInteger + std::fmt::Display>(
    params: &GlweCiphertextGgswCiphertextExternalProductParameters<Scalar>,
    input_stddev: StandardDev,
    output_stddev: StandardDev,
    pred_stddev: StandardDev,
    mean_runtime_ns: u128,
    mean_prep_time_ns: u128,
    dir: &str,
    id: usize,
) {
    let data_to_save = format!(
        "{}, {}, {}, {}, {}, {}, {}, {}, {}, {}\n",
        params.polynomial_size.0,
        params.glwe_dimension.0,
        params.decomposition_level_count.0,
        params.decomposition_base_log.0,
        params.ggsw_encrypted_value,
        input_stddev.get_variance(),
        output_stddev.get_variance(),
        pred_stddev.get_variance(),
        mean_runtime_ns,
        mean_prep_time_ns,
    );

    let mut file = get_analysis_output_file(dir, id);

    let _ = file.write(data_to_save.as_bytes()).unwrap();
}

fn minimal_variance_for_security(k: GlweDimension, size: PolynomialSize, modulus_log2: u32) -> f64 {
    minimal_variance_glwe(k.0 as u64, size.0 as u64, modulus_log2, 128)
}

fn mean(data: &[f64]) -> Option<f64> {
    // adapted from https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html
    let sum: f64 = data.iter().sum();
    let count = data.len();

    match count {
        positive if positive > 0 => Some(sum / count as f64),
        _ => None,
    }
}

fn std_deviation(data: &[f64]) -> Option<StandardDev> {
    // from https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html
    // replacing the mean by 0. as we theoretically know it
    match (mean(data), data.len()) {
        (Some(_data_mean), count) if count > 0 => {
            let variance = data
                .iter()
                .map(|&value| {
                    let diff = 0. - value;

                    diff * diff
                })
                .sum::<f64>()
                / count as f64;

            Some(StandardDev::from_standard_dev(variance.sqrt()))
        }
        _ => None,
    }
}

fn compute_torus_diff<Scalar: UnsignedInteger>(
    errs: &mut [f64],
    output: Vec<Scalar>,
    input: Vec<Scalar>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    bit: Scalar,
) {
    if bit == Scalar::ONE {
        for (&out, (&inp, err)) in output.iter().zip(input.iter().zip(errs.iter_mut())) {
            *err = torus_modular_diff(out, inp, ciphertext_modulus);
        }
    } else if bit == Scalar::ZERO {
        for (&out, err) in output.iter().zip(errs.iter_mut()) {
            *err = torus_modular_diff(out, Scalar::ZERO, ciphertext_modulus);
        }
    } else {
        panic!("Not a bit: {:?}", bit);
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct BaseLevel {
    base: DecompositionBaseLog,
    level: DecompositionLevelCount,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct HyperCubeParams {
    glwe_dimension: GlweDimension,
    base_level: BaseLevel,
    polynomial_size: PolynomialSize,
}

fn filter_b_l(bases: &[usize], levels: &[usize], preserved_mantissa: usize) -> Vec<BaseLevel> {
    let mut bases_levels = vec![];
    for (b, l) in iproduct!(bases, levels) {
        if b * l <= preserved_mantissa {
            bases_levels.push(BaseLevel {
                base: DecompositionBaseLog(*b),
                level: DecompositionLevelCount(*l),
            });
        }
    }
    bases_levels
}

fn main() {
    let args = Args::parse();
    let tot = args.tot;
    let id = args.id;
    let total_repetitions = args.repetitions;
    let base_sample_size = args.sample_size;
    let algo = args.algorithm;
    let dir = &args.dir;

    if algo.is_empty() {
        panic!("No algorithm provided")
    }

    let grouping_factor = match algo.as_str() {
        MULTI_BIT_EXT_PROD_ALGO | STD_MULTI_BIT_EXT_PROD_ALGO => Some(LweBskGroupingFactor(
            args.multi_bit_grouping_factor
                .expect("Required multi_bit_grouping_factor when sampling multi bit alogrithms"),
        )),
        _ => None,
    };

    let modulus: u128 = match args.modulus_log2 {
        Some(modulus_log2) => {
            if modulus_log2 > 128 {
                panic!("Got modulus_log2 > 128, this is not supported");
            }

            match algo.as_str() {
                EXT_PROD_ALGO | MULTI_BIT_EXT_PROD_ALGO | STD_MULTI_BIT_EXT_PROD_ALGO => {
                    if modulus_log2 > 64 {
                        panic!("Got modulus_log2 > 64, for 64 bits scalars");
                    }

                    1u128 << modulus_log2
                }
                EXT_PROD_U128_SPLIT_ALGO | EXT_PROD_U128_ALGO => {
                    if modulus_log2 == 128 {
                        // native
                        0
                    } else {
                        1u128 << modulus_log2
                    }
                }
                _ => unreachable!(),
            }
        }
        // Native
        None => 0,
    };

    // Parameter Grid
    let polynomial_sizes = vec![
        PolynomialSize(1 << 8),
        PolynomialSize(1 << 9),
        PolynomialSize(1 << 10),
        PolynomialSize(1 << 11),
        PolynomialSize(1 << 12),
        PolynomialSize(1 << 13),
        PolynomialSize(1 << 14),
    ];
    let max_polynomial_size = polynomial_sizes.iter().copied().max().unwrap();
    let glwe_dimensions = vec![
        GlweDimension(1),
        GlweDimension(2),
        GlweDimension(3),
        GlweDimension(4),
        GlweDimension(5),
    ];

    // TODO manage moduli < 2^53
    let (stepped_levels_cutoff, max_base_log_inclusive, preserved_mantissa) = match algo.as_str() {
        EXT_PROD_U128_ALGO | EXT_PROD_U128_SPLIT_ALGO => (41, 128, 106),
        _ => (21, 64, 53),
    };

    let preserved_mantissa = preserved_mantissa.min(modulus.ilog2()) as usize;

    let base_logs: Vec<_> = (1..=max_base_log_inclusive).collect();
    let mut levels = (1..stepped_levels_cutoff).collect::<Vec<_>>();
    let mut stepped_levels = (stepped_levels_cutoff..=max_base_log_inclusive)
        .step_by(args.steps)
        .collect::<Vec<_>>();
    levels.append(&mut stepped_levels);
    let bases_levels = filter_b_l(&base_logs, &levels, preserved_mantissa);

    let hypercube = iproduct!(glwe_dimensions, bases_levels, polynomial_sizes);
    let mut hypercube: Vec<HyperCubeParams> = hypercube
        .map(
            |(glwe_dimension, base_level, polynomial_size)| HyperCubeParams {
                glwe_dimension,
                base_level,
                polynomial_size,
            },
        )
        .collect();

    fn ggsw_scalar_size(k: GlweDimension, l: DecompositionLevelCount, n: PolynomialSize) -> usize {
        let (k, l, n) = (k.0, l.0, n.0);
        (k + 1).pow(2) * l * n
    }

    fn scalar_muls_per_ext_prod(
        k: GlweDimension,
        l: DecompositionLevelCount,
        n: PolynomialSize,
    ) -> usize {
        // Each coefficient of the ggsw is involved once in an fmadd operation
        ggsw_scalar_size(k, l, n)
    }

    fn ext_prod_cost(k: GlweDimension, l: DecompositionLevelCount, n: PolynomialSize) -> usize {
        // Conversions going from integer to float and from float to integer
        let conversion_cost = 2 * k.to_glwe_size().0 * n.0;
        // Fwd and back
        let fft_cost = 2 * k.to_glwe_size().0 * n.0 * n.0.ilog2() as usize;
        scalar_muls_per_ext_prod(k, l, n) + conversion_cost + fft_cost
    }

    hypercube.sort_by(|a, b| {
        let k_a = a.glwe_dimension;
        let l_a = a.base_level.level;
        let n_a = a.polynomial_size;

        let k_b = b.glwe_dimension;
        let l_b = b.base_level.level;
        let n_b = b.polynomial_size;

        let muls_a = ext_prod_cost(k_a, l_a, n_a);
        let muls_b = ext_prod_cost(k_b, l_b, n_b);

        muls_a.cmp(&muls_b)
    });

    // Pick elements of increasing complexity stepping by the number of threads to balance the
    // computation cost among threads
    let chunk: Vec<_> = hypercube.iter().skip(id).step_by(tot).collect();
    let chunk_size = chunk.len();

    println!(
        "-> Thread #{id} computing chunk #{id} of length {chunk_size} \
        (processing elements #{id} + k * {tot})",
    );

    prepare_output_file_header(dir, id);

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();

    let mut secret_random_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_random_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let u64_tool =
        |secret_rng: &mut SecretRandomGenerator<ActivatedRandomGenerator>,
         encrypt_rng: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>| {
            for (
                curr_idx,
                HyperCubeParams {
                    glwe_dimension,
                    base_level:
                        BaseLevel {
                            base: decomposition_base_log,
                            level: decomposition_level_count,
                        },
                    polynomial_size,
                },
            ) in chunk.iter().enumerate()
            {
                let glwe_dimension = *glwe_dimension;
                let decomposition_base_log = *decomposition_base_log;
                let decomposition_level_count = *decomposition_level_count;
                let polynomial_size = *polynomial_size;
                let ciphertext_modulus = CiphertextModulus::try_new(modulus).unwrap();

                let modulus_log2 = if ciphertext_modulus.is_native_modulus() {
                    u64::BITS
                } else if ciphertext_modulus.is_power_of_two() {
                    ciphertext_modulus.get_custom_modulus().ilog2()
                } else {
                    todo!("Non power of 2 moduli are currently not supported")
                };

                println!("Chunk part: {:?}/{chunk_size:?} done", curr_idx + 1);
                let sample_size = base_sample_size * max_polynomial_size.0 / polynomial_size.0;
                let ggsw_noise = Variance::from_variance(minimal_variance_for_security(
                    glwe_dimension,
                    polynomial_size,
                    modulus_log2,
                ));
                // We measure the noise added to a GLWE ciphertext, here we can choose to have no
                // input noise
                // It also avoid potential cases where the noise is so big it gets decomposed
                // during computations, it's an assumption we apparently already make ("small noise
                // regime")
                let glwe_noise = Variance(0.0);
                // Variance::from_variance(minimal_variance_for_security_64(glwe_dimension,
                // poly_size));

                let parameters = GlweCiphertextGgswCiphertextExternalProductParameters::<u64> {
                    ggsw_noise,
                    glwe_noise,
                    glwe_dimension,
                    ggsw_encrypted_value: 1,
                    polynomial_size,
                    decomposition_base_log,
                    decomposition_level_count,
                    ciphertext_modulus,
                };

                println!("params: {parameters:?}");

                let noise_prediction =
        match algo.as_str() {
            EXT_PROD_ALGO => noise_estimation::classic_pbs_estimate_external_product_noise_with_binary_ggsw_and_glwe(
                polynomial_size,
                glwe_dimension,
                ggsw_noise,
                decomposition_base_log,
                decomposition_level_count,
                modulus_log2,
            ),
            MULTI_BIT_EXT_PROD_ALGO => noise_estimation::multi_bit_pbs_estimate_external_product_noise_with_binary_ggsw_and_glwe(
                polynomial_size,
                glwe_dimension,
                ggsw_noise,
                decomposition_base_log,
                decomposition_level_count,
                modulus_log2,
                grouping_factor.unwrap(),
            ),
            STD_MULTI_BIT_EXT_PROD_ALGO => noise_estimation::multi_bit_pbs_estimate_external_product_noise_with_binary_ggsw_and_glwe(
                polynomial_size,
                glwe_dimension,
                ggsw_noise,
                decomposition_base_log,
                decomposition_level_count,
                modulus_log2,
                grouping_factor.unwrap(),
            ),
            _ => unreachable!(),
        };

                let fft = Fft::new(parameters.polynomial_size);
                let mut computation_buffers = ComputationBuffers::new();
                computation_buffers.resize(
                    add_external_product_assign_mem_optimized_requirement::<u64>(
                        parameters.glwe_dimension.to_glwe_size(),
                        parameters.polynomial_size,
                        fft.as_view(),
                    )
                    .unwrap()
                    .unaligned_bytes_required()
                    .max(
                        fft.as_view()
                            .forward_scratch()
                            .unwrap()
                            .unaligned_bytes_required(),
                    ),
                );

                let mut errors = vec![0.; sample_size * polynomial_size.0 * total_repetitions];

                if noise_prediction.get_variance() < 1. / 12. {
                    let mut total_runtime_ns = 0u128;
                    let mut total_prep_time_ns = 0u128;

                    for (_, errs) in (0..total_repetitions)
                        .zip(errors.chunks_mut(sample_size * polynomial_size.0))
                    {
                        let mut raw_inputs = Vec::with_capacity(sample_size);
                        let mut outputs = Vec::with_capacity(sample_size);

                        let (sample_runtime_ns, prep_time_ns) = match algo.as_str() {
                            EXT_PROD_ALGO => classic_pbs_external_product(
                                &parameters,
                                &mut raw_inputs,
                                &mut outputs,
                                sample_size,
                                secret_rng,
                                encrypt_rng,
                                fft.as_view(),
                                &mut computation_buffers,
                            ),
                            MULTI_BIT_EXT_PROD_ALGO => multi_bit_pbs_external_product(
                                &parameters,
                                &mut raw_inputs,
                                &mut outputs,
                                sample_size,
                                secret_rng,
                                encrypt_rng,
                                fft.as_view(),
                                &mut computation_buffers,
                                grouping_factor.unwrap(),
                            ),
                            STD_MULTI_BIT_EXT_PROD_ALGO => std_multi_bit_pbs_external_product(
                                &parameters,
                                &mut raw_inputs,
                                &mut outputs,
                                sample_size,
                                secret_rng,
                                encrypt_rng,
                                fft.as_view(),
                                &mut computation_buffers,
                                grouping_factor.unwrap(),
                            ),
                            _ => unreachable!(),
                        };

                        total_runtime_ns += sample_runtime_ns;
                        total_prep_time_ns += prep_time_ns;

                        let raw_input_plaintext_vector =
                            raw_inputs.into_iter().flatten().collect::<Vec<_>>();
                        let output_plaintext_vector =
                            outputs.into_iter().flatten().collect::<Vec<_>>();

                        compute_torus_diff(
                            errs,
                            output_plaintext_vector,
                            raw_input_plaintext_vector,
                            parameters.ciphertext_modulus,
                            parameters.ggsw_encrypted_value,
                        );
                    }
                    let _mean_err = mean(&errors).unwrap();
                    let std_err = std_deviation(&errors).unwrap();
                    let mean_runtime_ns =
                        total_runtime_ns / ((total_repetitions * sample_size) as u128);
                    // GGSW is prepared only once per sample
                    let mean_prep_time_ns = total_prep_time_ns / (total_repetitions as u128);
                    write_to_file(
                        &parameters,
                        variance_to_stddev(parameters.glwe_noise),
                        std_err,
                        variance_to_stddev(noise_prediction),
                        mean_runtime_ns,
                        mean_prep_time_ns,
                        dir,
                        id,
                    );

                    // TODO output raw data
                } else {
                    write_to_file(
                        &parameters,
                        variance_to_stddev(parameters.glwe_noise),
                        variance_to_stddev(Variance::from_variance(1. / 12.)),
                        variance_to_stddev(Variance::from_variance(1. / 12.)),
                        0,
                        0,
                        dir,
                        id,
                    )
                }
            }
        };

    let u128_tool =
        |secret_rng: &mut SecretRandomGenerator<ActivatedRandomGenerator>,
         encrypt_rng: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>| {
            for (
                curr_idx,
                HyperCubeParams {
                    glwe_dimension,
                    base_level:
                        BaseLevel {
                            base: decomposition_base_log,
                            level: decomposition_level_count,
                        },
                    polynomial_size,
                },
            ) in chunk.iter().enumerate()
            {
                let glwe_dimension = *glwe_dimension;
                let decomposition_base_log = *decomposition_base_log;
                let decomposition_level_count = *decomposition_level_count;
                let polynomial_size = *polynomial_size;
                let ciphertext_modulus = CiphertextModulus::try_new(modulus).unwrap();

                let modulus_log2 = if ciphertext_modulus.is_native_modulus() {
                    u128::BITS
                } else if ciphertext_modulus.is_power_of_two() {
                    ciphertext_modulus.get_custom_modulus().ilog2()
                } else {
                    todo!("Non power of 2 moduli are currently not supported")
                };

                println!("Chunk part: {:?}/{chunk_size:?} done", curr_idx + 1);
                let sample_size = base_sample_size * max_polynomial_size.0 / polynomial_size.0;
                let ggsw_noise = Variance::from_variance(minimal_variance_for_security(
                    glwe_dimension,
                    polynomial_size,
                    modulus_log2,
                ));
                // We measure the noise added to a GLWE ciphertext, here we can choose to have no
                // input noise
                // It also avoid potential cases where the noise is so big it gets decomposed
                // during computations, it's an assumption we apparently already make ("small noise
                // regime")
                let glwe_noise = Variance(0.0);
                // Variance::from_variance(minimal_variance_for_security_64(glwe_dimension,
                // poly_size));

                let parameters = GlweCiphertextGgswCiphertextExternalProductParameters::<u128> {
                    ggsw_noise,
                    glwe_noise,
                    glwe_dimension,
                    ggsw_encrypted_value: 1,
                    polynomial_size,
                    decomposition_base_log,
                    decomposition_level_count,
                    ciphertext_modulus,
                };

                println!("params: {parameters:?}");

                let noise_prediction =
        match algo.as_str() {
            EXT_PROD_U128_SPLIT_ALGO | EXT_PROD_U128_ALGO => noise_estimation::classic_pbs_estimate_external_product_noise_with_binary_ggsw_and_glwe(
                polynomial_size,
                glwe_dimension,
                ggsw_noise,
                decomposition_base_log,
                decomposition_level_count,
                modulus_log2,
            ),
            _ => unreachable!(),
        };

                let fft = Fft128::new(parameters.polynomial_size);
                let mut computation_buffers = ComputationBuffers::new();
                computation_buffers.resize(
                    programmable_bootstrap_f128_lwe_ciphertext_mem_optimized_requirement::<u128>(
                        parameters.glwe_dimension.to_glwe_size(),
                        parameters.polynomial_size,
                        fft.as_view(),
                    )
                    .unwrap()
                    .unaligned_bytes_required()
                    .max(
                        fft.as_view()
                            .backward_scratch()
                            .unwrap()
                            .unaligned_bytes_required(),
                    ),
                );

                let mut errors = vec![0.; sample_size * polynomial_size.0 * total_repetitions];

                if noise_prediction.get_variance() < 1. / 12. {
                    let mut total_runtime_ns = 0u128;
                    let mut total_prep_time_ns = 0u128;

                    for (_, errs) in (0..total_repetitions)
                        .zip(errors.chunks_mut(sample_size * polynomial_size.0))
                    {
                        let mut raw_inputs = Vec::with_capacity(sample_size);
                        let mut outputs = Vec::with_capacity(sample_size);

                        let (sample_runtime_ns, prep_time_ns) = match algo.as_str() {
                            EXT_PROD_U128_SPLIT_ALGO => classic_pbs_external_product_u128_split(
                                &parameters,
                                &mut raw_inputs,
                                &mut outputs,
                                sample_size,
                                secret_rng,
                                encrypt_rng,
                                fft.as_view(),
                                &mut computation_buffers,
                            ),
                            EXT_PROD_U128_ALGO => classic_pbs_external_product_u128(
                                &parameters,
                                &mut raw_inputs,
                                &mut outputs,
                                sample_size,
                                secret_rng,
                                encrypt_rng,
                                fft.as_view(),
                                &mut computation_buffers,
                            ),
                            _ => unreachable!(),
                        };

                        total_runtime_ns += sample_runtime_ns;
                        total_prep_time_ns += prep_time_ns;

                        let raw_input_plaintext_vector =
                            raw_inputs.into_iter().flatten().collect::<Vec<_>>();
                        let output_plaintext_vector =
                            outputs.into_iter().flatten().collect::<Vec<_>>();

                        compute_torus_diff(
                            errs,
                            output_plaintext_vector,
                            raw_input_plaintext_vector,
                            parameters.ciphertext_modulus,
                            parameters.ggsw_encrypted_value,
                        );
                    }
                    let _mean_err = mean(&errors).unwrap();
                    let std_err = std_deviation(&errors).unwrap();
                    let mean_runtime_ns =
                        total_runtime_ns / ((total_repetitions * sample_size) as u128);
                    // GGSW is prepared only once per sample
                    let mean_prep_time_ns = total_prep_time_ns / (total_repetitions as u128);
                    write_to_file(
                        &parameters,
                        variance_to_stddev(parameters.glwe_noise),
                        std_err,
                        variance_to_stddev(noise_prediction),
                        mean_runtime_ns,
                        mean_prep_time_ns,
                        dir,
                        id,
                    );

                    // TODO output raw data
                } else {
                    write_to_file(
                        &parameters,
                        variance_to_stddev(parameters.glwe_noise),
                        variance_to_stddev(Variance::from_variance(1. / 12.)),
                        variance_to_stddev(Variance::from_variance(1. / 12.)),
                        0,
                        0,
                        dir,
                        id,
                    )
                }
            }
        };

    match algo.as_str() {
        EXT_PROD_ALGO | MULTI_BIT_EXT_PROD_ALGO | STD_MULTI_BIT_EXT_PROD_ALGO => u64_tool(
            &mut secret_random_generator,
            &mut encryption_random_generator,
        ),
        EXT_PROD_U128_ALGO | EXT_PROD_U128_SPLIT_ALGO => u128_tool(
            &mut secret_random_generator,
            &mut encryption_random_generator,
        ),
        _ => unreachable!(),
    };
}
