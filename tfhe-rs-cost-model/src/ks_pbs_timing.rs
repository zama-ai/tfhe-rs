use super::*;

use concrete_cpu_noise_model::gaussian_noise::noise::blind_rotate::variance_blind_rotate;
use concrete_cpu_noise_model::gaussian_noise::noise::keyswitch::variance_keyswitch;
use concrete_cpu_noise_model::gaussian_noise::noise::modulus_switching::estimate_modulus_switching_noise_with_binary_key;
use concrete_security_curves::gaussian::security::minimal_variance_lwe;
use itertools::Itertools;
use rand::prelude::*;
use rayon::prelude::*;
use std::path::{Path, PathBuf};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParamsHash {
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    pbs_level: DecompositionLevelCount,
    ks_level: DecompositionLevelCount,
}

impl std::hash::Hash for ParamsHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.lwe_dimension.0.hash(state);
        self.glwe_dimension.0.hash(state);
        self.polynomial_size.0.hash(state);
        self.pbs_level.0.hash(state);
        self.ks_level.0.hash(state);
    }
}

impl From<Params> for ParamsHash {
    fn from(value: Params) -> Self {
        Self {
            lwe_dimension: value.lwe_dimension,
            glwe_dimension: value.glwe_dimension,
            polynomial_size: value.polynomial_size,
            pbs_level: value.pbs_level,
            ks_level: value.ks_level,
        }
    }
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
        polynomial_size.0.ilog2().into(),
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

fn write_results_to_file(
    params: Params,
    perf_metrics_array: &[(usize, ThreadCount, usize, PerfMetrics)],
    out_dir: &Path,
) {
    let exp_name = format!(
        "n={}_k={}_N={}_brl={}_ksl={}",
        params.lwe_dimension.0,
        params.glwe_dimension.0,
        params.polynomial_size.0,
        params.pbs_level.0,
        params.ks_level.0
    );

    let out_file_name = PathBuf::from(format!("{exp_name}.csv"));

    let out_path = out_dir.join(out_file_name);

    if out_path.exists() {
        std::fs::remove_file(&out_path).unwrap();
    }

    let mut out = std::fs::File::options()
        .create(true)
        .append(true)
        .open(&out_path)
        .unwrap();

    // per_batch_runtime_s: f64,
    // pbs_per_s: f64,
    // pbs_per_s_per_thread: f64,
    // equivalent_monothread_pbs_runtime_s: f64,

    writeln!(
        &mut out,
        "chunk_size,threads_used,batch_count,overall_runtime_s,\
        per_batch_runtime_s,pbs_per_s,pbs_per_s_per_thread,equivalent_monothread_pbs_runtime_s"
    )
    .unwrap();

    for (chunk_size, thread_count, batch_count, perf_metrics) in perf_metrics_array {
        let thread_count = thread_count.0;
        let PerfMetrics {
            overall_runtime_s,
            per_batch_runtime_s,
            pbs_per_s,
            pbs_per_s_per_thread,
            equivalent_monothread_pbs_runtime_s,
        } = perf_metrics;
        writeln!(
            &mut out,
            "{chunk_size},{thread_count},{batch_count},{overall_runtime_s},\
            {per_batch_runtime_s},{pbs_per_s},{pbs_per_s_per_thread},{equivalent_monothread_pbs_runtime_s}"
        ).unwrap();
    }
}

// preserved_mantissa = number of bits that are in the mantissa of the floating point numbers used
pub fn timing_experiment(algorithm: &str, preserved_mantissa: usize, modulus: u128) {
    assert_eq!(algorithm, EXT_PROD_ALGO);

    let out_dir = Path::new("exp");
    if !out_dir.exists() {
        std::fs::create_dir(out_dir).unwrap();
    }

    let ciphertext_modulus: CiphertextModulus<u64> = match modulus {
        0 => CiphertextModulus::new_native(),
        _ => CiphertextModulus::try_new(modulus).unwrap(),
    };

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let lwe_dimension_search_space = (512..=1024).step_by(64).map(LweDimension);
    let glwe_dimension_search_space = (1..=5).map(GlweDimension);
    let polynomial_size_search_space = (8..=16).map(|poly_log2| PolynomialSize(1 << poly_log2));

    let modulus_log2 = if ciphertext_modulus.is_native_modulus() {
        64usize
    } else {
        ciphertext_modulus.get_custom_modulus().ilog2() as usize
    };

    // TODO: as discussed with Sam, limit to 40
    let max_base_level_product = 40;

    let preserved_mantissa = preserved_mantissa.min(modulus_log2);

    let (potential_base_logs, potential_levels) = (
        (1..=modulus_log2).collect::<Vec<_>>(),
        (1..=modulus_log2).collect::<Vec<_>>(),
    );

    let max_base_log_level_prod = preserved_mantissa
        .min(modulus_log2)
        .min(max_base_level_product);

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

    let hypercube: Vec<_> = hypercube
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

    println!("candidates {}", hypercube.len());

    let mut hypercube: Vec<_> = hypercube
        .into_iter()
        .unique_by(|x| ParamsHash::from(x.0))
        .collect();

    println!("candidates {}", hypercube.len());

    // hypercube.sort_by(|a, b| {
    //     let a = a.0;
    //     let b = b.0;
    //     let cost_a = ks_cost(
    //         a.lwe_dimension,
    //         a.glwe_dimension
    //             .to_equivalent_lwe_dimension(a.polynomial_size),
    //         a.ks_level,
    //     ) + pbs_cost(
    //         a.lwe_dimension,
    //         a.glwe_dimension,
    //         a.pbs_level,
    //         a.polynomial_size,
    //     );
    //     let cost_b = ks_cost(
    //         b.lwe_dimension,
    //         b.glwe_dimension
    //             .to_equivalent_lwe_dimension(b.polynomial_size),
    //         b.ks_level,
    //     ) + pbs_cost(
    //         b.lwe_dimension,
    //         b.glwe_dimension,
    //         b.pbs_level,
    //         b.polynomial_size,
    //     );

    //     cost_a.cmp(&cost_b)
    // });

    let seed = [0u8; 8 * 4];
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);
    hypercube.shuffle(&mut rng);

    // {
    //     let mut out = std::fs::File::options()
    //         .create(true)
    //         .write(true)
    //         .open(&out_dir.join(&"params.log"))
    //         .unwrap();

    //     for (param, _) in &hypercube {
    //         writeln!(&mut out, "{param:?}").unwrap();
    //     }
    // }

    let start_time = std::time::Instant::now();

    for (idx, (params, variances)) in hypercube.into_iter().enumerate() {
        let loop_start = std::time::Instant::now();
        println!("#{idx} start");
        println!("{params:#?}");
        let perf_metrics = run_timing_measurements(params, variances, ciphertext_modulus);
        println!("{perf_metrics:#?}");
        write_results_to_file(params, &perf_metrics, out_dir);
        let loop_elapsed = loop_start.elapsed();
        println!("#{idx} done in {loop_elapsed:?}");
        println!("overall runtime {:?}", start_time.elapsed());
    }
}

pub const CHUNK_SIZE: [usize; 5] = [1, 32, 64, 128, 192];
pub const BATCH_COUNT: usize = 100;

#[derive(Clone, Copy, Debug)]
struct PerfMetrics {
    overall_runtime_s: f64,
    per_batch_runtime_s: f64,
    pbs_per_s: f64,
    pbs_per_s_per_thread: f64,
    equivalent_monothread_pbs_runtime_s: f64,
}

fn compute_perf_metrics(
    overall_runtime: std::time::Duration,
    batch_count: usize,
    pbs_per_batch: usize,
    thread_count: usize,
) -> PerfMetrics {
    let per_batch_runtime = overall_runtime / batch_count.try_into().unwrap();
    let per_batch_runtime_s = per_batch_runtime.as_secs_f64();
    let batch_per_s = 1.0 / per_batch_runtime_s;
    let pbs_per_s = batch_per_s * pbs_per_batch as f64;
    let pbs_per_s_per_thread = pbs_per_s / thread_count as f64;
    let equivalent_monothread_pbs_runtime_s = 1.0 / pbs_per_s_per_thread;

    PerfMetrics {
        overall_runtime_s: overall_runtime.as_secs_f64(),
        per_batch_runtime_s,
        pbs_per_s,
        pbs_per_s_per_thread,
        equivalent_monothread_pbs_runtime_s,
    }
}

fn run_timing_measurements(
    params: Params,
    variances: NoiseVariances,
    ciphertext_modulus: CiphertextModulus<u64>,
) -> Vec<(usize, ThreadCount, usize, PerfMetrics)> {
    // let params = Params {
    //     lwe_dimension: LweDimension(742),
    //     glwe_dimension: GlweDimension(1),
    //     polynomial_size: PolynomialSize(2048),
    //     pbs_base_log: DecompositionBaseLog(23),
    //     pbs_level: DecompositionLevelCount(1),
    //     ks_base_log: DecompositionBaseLog(3),
    //     ks_level: DecompositionLevelCount(5),
    // };

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

    let inputs: Vec<_> = (0..BATCH_COUNT * CHUNK_SIZE.last().unwrap())
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

    let mut buffers: Vec<_> = (0..*CHUNK_SIZE.last().unwrap())
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

    let current_thread_count = rayon::current_num_threads();

    for chunk_size in CHUNK_SIZE {
        let effective_thread_count = ThreadCount(chunk_size.min(current_thread_count));

        let ciphertext_to_process_count = chunk_size * BATCH_COUNT;

        if chunk_size == 1 {
            assert_eq!(ciphertext_to_process_count, BATCH_COUNT);

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

            let perf_metrics =
                compute_perf_metrics(elapsed, BATCH_COUNT, chunk_size, effective_thread_count.0);

            timings.push((
                chunk_size,
                effective_thread_count,
                BATCH_COUNT,
                perf_metrics,
            ));
        } else {
            let mut measurement_count = 0;

            let start = std::time::Instant::now();

            for (input_lwe_chunk, output_lwe_chunk) in inputs[..ciphertext_to_process_count]
                .chunks_exact(chunk_size)
                .zip(output[..ciphertext_to_process_count].chunks_exact_mut(chunk_size))
            {
                measurement_count += 1;
                assert_eq!(input_lwe_chunk.len(), chunk_size);
                assert_eq!(output_lwe_chunk.len(), chunk_size);

                input_lwe_chunk
                    .par_iter()
                    .zip(output_lwe_chunk.par_iter_mut())
                    .zip(buffers.par_iter_mut())
                    .for_each(|((input_lwe, output_lwe), (after_ks_buffer, fft_buffer))| {
                        keyswitch_lwe_ciphertext(&ksk, input_lwe, after_ks_buffer);

                        programmable_bootstrap_lwe_ciphertext_mem_optimized(
                            after_ks_buffer,
                            output_lwe,
                            &accumulator,
                            &fbsk,
                            fft,
                            fft_buffer.stack(),
                        );
                    });
            }

            let elapsed = start.elapsed();

            assert_eq!(measurement_count, BATCH_COUNT);

            let perf_metrics =
                compute_perf_metrics(elapsed, BATCH_COUNT, chunk_size, effective_thread_count.0);

            timings.push((
                chunk_size,
                effective_thread_count,
                BATCH_COUNT,
                perf_metrics,
            ));
        }
    }

    timings
}
