use super::*;

use concrete_cpu_noise_model::gaussian_noise::noise::blind_rotate::variance_blind_rotate;
use concrete_cpu_noise_model::gaussian_noise::noise::keyswitch::variance_keyswitch;
use concrete_cpu_noise_model::gaussian_noise::noise::modulus_switching::estimate_modulus_switching_noise_with_binary_key;
use concrete_security_curves::gaussian::security::{minimal_variance_glwe, minimal_variance_lwe};
use rayon::prelude::*;

pub const SECURITY_LEVEL: u64 = 128;
// Variance of uniform distribution over [0; 1)
pub const UNIFORM_NOISE_VARIANCE: f64 = 1. / 12.;

#[derive(Clone, Copy, Debug)]
struct Params {
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
}

struct NoiseVariances {
    lwe_noise_variance: Variance,
    glwe_noise_variance: Variance,
    estimated_pbs_noise_variance: Variance,
    estimated_ks_noise_variance: Variance,
    br_to_ms_noise_variance: Variance,
}

impl NoiseVariances {
    fn all_noises_are_not_uniformly_random(&self) -> bool {
        self.lwe_noise_variance.0 < UNIFORM_NOISE_VARIANCE
            && self.glwe_noise_variance.0 < UNIFORM_NOISE_VARIANCE
            && self.estimated_ks_noise_variance.0 < UNIFORM_NOISE_VARIANCE
            && self.estimated_pbs_noise_variance.0 < UNIFORM_NOISE_VARIANCE
            && self.br_to_ms_noise_variance.0 < UNIFORM_NOISE_VARIANCE
    }
}

fn lwe_glwe_noise_ap_estimate(
    Params {
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        pbs_base_log,
        pbs_level,
        ks_base_log,
        ks_level,
    }: Params,
    ciphertext_modulus_log: u32,
    preserved_mantissa: usize,
) -> NoiseVariances {
    let lwe_noise_variance = Variance(minimal_variance_lwe(
        lwe_dimension.0.try_into().unwrap(),
        ciphertext_modulus_log,
        SECURITY_LEVEL,
    ));

    let glwe_noise_variance = Variance(minimal_variance_glwe(
        glwe_dimension.0.try_into().unwrap(),
        polynomial_size.0.try_into().unwrap(),
        ciphertext_modulus_log,
        SECURITY_LEVEL,
    ));

    let estimated_pbs_noise_variance = Variance(variance_blind_rotate(
        lwe_dimension.0.try_into().unwrap(),
        glwe_dimension.0.try_into().unwrap(),
        polynomial_size.0.try_into().unwrap(),
        pbs_base_log.0.try_into().unwrap(),
        pbs_level.0.try_into().unwrap(),
        ciphertext_modulus_log,
        preserved_mantissa.try_into().unwrap(),
        glwe_noise_variance.0,
    ));

    let estimated_ks_noise_variance = Variance(variance_keyswitch(
        glwe_dimension
            .to_equivalent_lwe_dimension(polynomial_size)
            .0
            .try_into()
            .unwrap(),
        ks_base_log.0.try_into().unwrap(),
        ks_level.0.try_into().unwrap(),
        ciphertext_modulus_log,
        lwe_noise_variance.0,
    ));

    let ms_noise_variance = Variance(estimate_modulus_switching_noise_with_binary_key(
        lwe_dimension.0.try_into().unwrap(),
        polynomial_size.0.ilog2().try_into().unwrap(),
        ciphertext_modulus_log,
    ));

    let br_to_ms_noise_variance = Variance(
        estimated_pbs_noise_variance.0 + estimated_ks_noise_variance.0 + ms_noise_variance.0,
    );

    NoiseVariances {
        lwe_noise_variance,
        glwe_noise_variance,
        estimated_pbs_noise_variance,
        estimated_ks_noise_variance,
        br_to_ms_noise_variance,
    }
}

// preserved_mantissa = number of bits that are in the mantissa of the floating point numbers used
pub fn timing_experiment(algorithm: &str, preserved_mantissa: usize, modulus: u128) {
    assert_eq!(algorithm, EXT_PROD_ALGO);

    let ciphertext_modulus: CiphertextModulus<u64> = match modulus {
        0 => CiphertextModulus::new_native(),
        _ => CiphertextModulus::try_new(modulus).unwrap(),
    };

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let lwe_dimension_search_space = (512..=1024).step_by(16).map(LweDimension);
    let glwe_dimension_search_space = (1..=5).map(GlweDimension);
    let polynomial_size_search_space = (8..=16).map(|poly_log2| PolynomialSize(1 << poly_log2));

    let modulus_log2 = if ciphertext_modulus.is_native_modulus() {
        64usize
    } else {
        ciphertext_modulus.get_custom_modulus().ilog2() as usize
    };

    let preserved_mantissa = preserved_mantissa.min(modulus_log2) as usize;

    let (potential_base_logs, potential_levels) = (
        (1..=modulus_log2).collect::<Vec<_>>(),
        (1..=modulus_log2).collect::<Vec<_>>(),
    );

    let max_base_log_level_prod = preserved_mantissa.min(modulus_log2);

    let base_log_level_pbs = filter_b_l(
        &potential_base_logs,
        &potential_levels,
        max_base_log_level_prod,
    );
    // Same for KS
    let base_log_level_ks = base_log_level_pbs.clone();

    let hypercube = iproduct!(
        lwe_dimension_search_space,
        glwe_dimension_search_space,
        polynomial_size_search_space,
        base_log_level_pbs,
        base_log_level_ks
    );

    let mut hypercube: Vec<_> = hypercube
        .map(
            |(
                lwe_dimension,
                glwe_dimension,
                polynomial_size,
                pbs_base_log_level,
                ks_base_log_level,
            )| {
                let params = Params {
                    lwe_dimension,
                    glwe_dimension,
                    polynomial_size,
                    pbs_base_log: pbs_base_log_level.base,
                    pbs_level: pbs_base_log_level.level,
                    ks_base_log: ks_base_log_level.base,
                    ks_level: ks_base_log_level.level,
                };
                let variances = lwe_glwe_noise_ap_estimate(
                    params,
                    modulus_log2.try_into().unwrap(),
                    preserved_mantissa,
                );
                (params, variances)
            },
        )
        .filter(|(_, variances)| variances.all_noises_are_not_uniformly_random())
        .collect();

    hypercube.sort_by(|a, b| {
        let a = a.0;
        let b = b.0;
        let cost_a = ks_cost(
            a.lwe_dimension,
            a.glwe_dimension
                .to_equivalent_lwe_dimension(a.polynomial_size),
            a.ks_level,
        ) + pbs_cost(
            a.lwe_dimension,
            a.glwe_dimension,
            a.pbs_level,
            a.polynomial_size,
        );
        let cost_b = ks_cost(
            b.lwe_dimension,
            b.glwe_dimension
                .to_equivalent_lwe_dimension(b.polynomial_size),
            b.ks_level,
        ) + pbs_cost(
            b.lwe_dimension,
            b.glwe_dimension,
            b.pbs_level,
            b.polynomial_size,
        );

        cost_a.cmp(&cost_b)
    });

    // TODO eliminate duplicate levels with different base logs

    for (params, variances) in hypercube {
        run_timing_measurements(params, variances, ciphertext_modulus);
    }
}

pub const THREAD_COUNTS: [usize; 5] = [1, 32, 64, 128, 192];
pub const BATCH_SIZE: usize = 100;

use rand::prelude::*;
use rand::thread_rng;

fn run_timing_measurements(
    params: Params,
    variances: NoiseVariances,
    ciphertext_modulus: CiphertextModulus<u64>,
) {
    println!("{params:?}");

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_random_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_random_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    let lwe_noise_distribution =
        Gaussian::from_dispersion_parameter(variances.lwe_noise_variance, 0.0);
    let glwe_noise_distribution =
        Gaussian::from_dispersion_parameter(variances.glwe_noise_variance, 0.0);

    let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        params.lwe_dimension,
        &mut secret_random_generator,
    );

    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        params.glwe_dimension,
        params.polynomial_size,
        &mut secret_random_generator,
    );

    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &glwe_secret_key.as_lwe_secret_key(),
        &lwe_secret_key,
        params.ks_base_log,
        params.ks_level,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_random_generator,
    );

    let fbsk = {
        let bsk = allocate_and_generate_new_lwe_bootstrap_key(
            &lwe_secret_key,
            &glwe_secret_key,
            params.pbs_base_log,
            params.pbs_level,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_random_generator,
        );

        let mut fbsk = FourierLweBootstrapKey::new(
            bsk.input_lwe_dimension(),
            bsk.glwe_size(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
        );

        par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);

        fbsk
    };

    let inputs: Vec<_> = (0..BATCH_SIZE * THREAD_COUNTS.last().unwrap())
        .map(|_| {
            allocate_and_encrypt_new_lwe_ciphertext(
                &glwe_secret_key.as_lwe_secret_key(),
                Plaintext(0),
                glwe_noise_distribution,
                ciphertext_modulus,
                &mut encryption_random_generator,
            )
        })
        .collect();

    let mut output = inputs.clone();

    let fft = Fft::new(fbsk.polynomial_size());
    let fft = fft.as_view();

    let mut buffers: Vec<_> = (0..*THREAD_COUNTS.last().unwrap())
        .map(|_| {
            let buffer_after_ks =
                LweCiphertext::new(0u64, ksk.output_lwe_size(), ciphertext_modulus);

            let mut computations_buffers = ComputationBuffers::new();
            computations_buffers.resize(
                programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                    fbsk.glwe_size(),
                    fbsk.polynomial_size(),
                    fft,
                )
                .unwrap()
                .try_unaligned_bytes_required()
                .unwrap(),
            );

            (buffer_after_ks, computations_buffers)
        })
        .collect();

    let mut accumulator = GlweCiphertext::new(
        0u64,
        fbsk.glwe_size(),
        fbsk.polynomial_size(),
        ciphertext_modulus,
    );

    let mut rng = thread_rng();

    // Random values in the lut
    accumulator.as_mut().fill_with(|| rng.gen::<u64>());

    let mut timings = vec![];

    for thread_count in THREAD_COUNTS {
        let ciphertext_to_process_count = thread_count * BATCH_SIZE;

        if thread_count == 1 {
            let (after_ks_buffer, fft_buffer) = &mut buffers[0];

            let start = std::time::Instant::now();

            for (input_lwe, output_lwe) in inputs[..ciphertext_to_process_count]
                .iter()
                .zip(output[..ciphertext_to_process_count].iter_mut())
            {
                keyswitch_lwe_ciphertext(&ksk, input_lwe, after_ks_buffer);

                programmable_bootstrap_lwe_ciphertext_mem_optimized(
                    after_ks_buffer,
                    output_lwe,
                    &accumulator,
                    &fbsk,
                    fft,
                    fft_buffer.stack(),
                );
            }

            let elapsed = start.elapsed();
            let elpased_per_sample = elapsed / ciphertext_to_process_count.try_into().unwrap();
            println!("elpased_per_sample={elpased_per_sample:?}");
            let per_sample_nanos = elpased_per_sample.as_nanos();
            timings.push((thread_count, per_sample_nanos));
        } else {
            let start = std::time::Instant::now();

            for (input_lwe_chunk, output_lwe_chunk) in inputs[..ciphertext_to_process_count]
                .chunks_exact(thread_count)
                .zip(output[..ciphertext_to_process_count].chunks_exact_mut(thread_count))
            {
                keyswitch_lwe_ciphertext(&ksk, input_lwe, after_ks_buffer);

                programmable_bootstrap_lwe_ciphertext_mem_optimized(
                    after_ks_buffer,
                    output_lwe,
                    &accumulator,
                    &fbsk,
                    fft,
                    fft_buffer.stack(),
                );
            }

            let elapsed = start.elapsed();
            let elpased_per_sample = elapsed / ciphertext_to_process_count.try_into().unwrap();
            println!("elpased_per_sample={elpased_per_sample:?}");
            let per_sample_nanos = elpased_per_sample.as_nanos();
            timings.push((thread_count, per_sample_nanos));
        }
    }

    println!("{timings:?}");
}
