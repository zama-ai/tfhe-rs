use benchmark::utilities::{get_bench_type, BenchmarkType};
use criterion::{black_box, Criterion, Throughput};
use rayon::prelude::*;
use tfhe::core_crypto::experimental::prelude::*;
use tfhe::core_crypto::prelude::*;

pub struct ExtendedPBSBenchParameters {
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    extension_factor: LweBootstrapExtensionFactor,
    lwe_noise_distribution: DynamicDistribution<u64>,
    glwe_noise_distribution: DynamicDistribution<u64>,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    message_modulus: CleartextModulus<MessageSpace>,
    carry_modulus: CleartextModulus<CarrySpace>,
    #[allow(dead_code)]
    max_norm2: MaxNorm2,
    #[allow(dead_code)]
    log2_p_fail: f64,
    ciphertext_modulus: CiphertextModulus<u64>,
    encryption_key_choice: EncryptionKeyChoice,
}

// p-fail = 2^-128.147, algorithmic cost ~ 67456140, 2-norm = 5, extension factor = 16,
const BENCH_PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_EF_16_2M128: ExtendedPBSBenchParameters =
    ExtendedPBSBenchParameters {
        lwe_dimension: LweDimension(884),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        extension_factor: LweBootstrapExtensionFactor(16),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.4999005934396873e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: CleartextModulus::new(4),
        carry_modulus: CleartextModulus::new(4),
        max_norm2: MaxNorm2(5f64),
        log2_p_fail: -128.0,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };

const KS_EPBS_BENCH_PARAMS: [(&str, &ExtendedPBSBenchParameters); 1] = [(
    "BENCH_PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_EF_16_2M128",
    &BENCH_PARAM_MESSAGE_2_CARRY_2_PARALLEL_PBS_EF_16_2M128,
)];

fn get_encoding_with_padding<Scalar: UnsignedInteger>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> Scalar {
    if ciphertext_modulus.is_native_modulus() {
        Scalar::ONE << (Scalar::BITS - 1)
    } else {
        Scalar::cast_from(ciphertext_modulus.get_custom_modulus() / 2)
    }
}

fn ks_extended_pbs(criterion: &mut Criterion) {
    let bench_name = "core_crypto::ks_extended_pbs";
    let mut bench_group = criterion.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    for (name, params) in KS_EPBS_BENCH_PARAMS {
        let ExtendedPBSBenchParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            extension_factor,
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            message_modulus,
            carry_modulus,
            max_norm2: _,
            log2_p_fail: _,
            ciphertext_modulus,
            encryption_key_choice,
        } = *params;

        let plaintext_modulus = message_modulus.0 * carry_modulus.0;
        let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
        let delta = encoding_with_padding / plaintext_modulus;

        assert!(matches!(encryption_key_choice, EncryptionKeyChoice::Big));

        let lwe_sk =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
        let big_lwe_sk = glwe_sk.as_lwe_secret_key();
        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_sk,
            &lwe_sk,
            ks_base_log,
            ks_level,
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let bsk = allocate_and_generate_new_lwe_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            pbs_base_log,
            pbs_level,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut fourier_bsk = FourierLweBootstrapKey::new(
            bsk.input_lwe_dimension(),
            bsk.glwe_size(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
        );
        par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);

        let f = |x: u64| x;

        let accumulator = generate_programmable_bootstrap_glwe_lut(
            PolynomialSize(polynomial_size.0 * extension_factor.0),
            glwe_dimension.to_glwe_size(),
            plaintext_modulus.cast_into(),
            ciphertext_modulus,
            delta,
            f,
        );

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        let mut buffers = ComputationBuffers::new();

        // TODO: have req for main thread and for workers ?
        use extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized_requirement as rq;

        let requirement = rq::<u64>(
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            extension_factor,
            fft,
        )
        .unaligned_bytes_required();

        buffers.resize(requirement);

        let mut thread_buffers = Vec::with_capacity(extension_factor.0);
        for _ in 0..extension_factor.0 {
            let mut buffer = ComputationBuffers::new();
            buffer.resize(requirement);
            thread_buffers.push(buffer);
        }

        let mut thread_stacks: Vec<_> = thread_buffers.iter_mut().map(|x| x.stack()).collect();

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let ct = allocate_and_encrypt_new_lwe_ciphertext(
                    &big_lwe_sk,
                    Plaintext(0),
                    lwe_noise_distribution,
                    ciphertext_modulus,
                    &mut encryption_generator,
                );

                let mut ks_buffer =
                    LweCiphertext::new(0, lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);

                let mut output_ct = ct.clone();
                output_ct.as_mut().fill(0);

                bench_id = format!("{bench_name}::{name}");
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut ks_buffer);
                        extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized(
                            &fourier_bsk,
                            &mut output_ct,
                            &ct,
                            &accumulator,
                            extension_factor,
                            fft,
                            buffers.stack(),
                            &mut thread_stacks,
                        );
                        black_box(&mut output_ct);
                    })
                });
            }
            BenchmarkType::Throughput => {
                bench_id = format!("{bench_name}::throughput::{name}");
                let mut setup = |batch_size: usize| {
                    let inputs = (0..batch_size)
                        .map(|_| {
                            let ct = allocate_and_encrypt_new_lwe_ciphertext(
                                &big_lwe_sk,
                                Plaintext(0),
                                lwe_noise_distribution,
                                ciphertext_modulus,
                                &mut encryption_generator,
                            );

                            let ks_buffer = LweCiphertext::new(
                                0,
                                lwe_sk.lwe_dimension().to_lwe_size(),
                                ciphertext_modulus,
                            );

                            let mut output_ct = ct.clone();
                            output_ct.as_mut().fill(0);

                            let accumulator = generate_programmable_bootstrap_glwe_lut(
                                PolynomialSize(polynomial_size.0 * extension_factor.0),
                                glwe_dimension.to_glwe_size(),
                                plaintext_modulus.cast_into(),
                                ciphertext_modulus,
                                delta,
                                f,
                            );

                            let fft = Fft::new(fourier_bsk.polynomial_size());
                            let fft = fft.as_view();

                            let mut main_thread_buffer = ComputationBuffers::new();

                            let requirement = rq::<u64>(
                                glwe_dimension.to_glwe_size(),
                                polynomial_size,
                                extension_factor,
                                fft,
                            )
                            .unaligned_bytes_required();

                            main_thread_buffer.resize(requirement);

                            let mut thread_buffers = Vec::with_capacity(extension_factor.0);
                            for _ in 0..extension_factor.0 {
                                let mut buffer = ComputationBuffers::new();
                                buffer.resize(requirement);
                                thread_buffers.push(buffer);
                            }

                            (
                                ct,
                                ks_buffer,
                                output_ct,
                                accumulator,
                                main_thread_buffer,
                                thread_buffers,
                            )
                        })
                        .collect::<Vec<_>>();
                    inputs
                };
                type Res = Vec<(
                    LweCiphertext<Vec<u64>>,  // Input
                    LweCiphertext<Vec<u64>>,  // KS result
                    LweCiphertext<Vec<u64>>,  // PBS result
                    GlweCiphertext<Vec<u64>>, // Accumulator
                    ComputationBuffers,       // Main thread buffer
                    Vec<ComputationBuffers>,  // Worker thread buffer
                )>;
                let run = |inputs: &mut Res| {
                    inputs.par_iter_mut().for_each(
                        |(
                            ct,
                            ks_buffer,
                            output_ct,
                            accumulator,
                            main_thread_buffer,
                            thread_buffers,
                        )| {
                            let mut thread_stacks: Vec<_> =
                                thread_buffers.iter_mut().map(|x| x.stack()).collect();
                            keyswitch_lwe_ciphertext(&ksk_big_to_small, ct, ks_buffer);
                            extended_programmable_bootstrap_lwe_ciphertext_mem_optimized_parallelized(
                                &fourier_bsk,
                                 output_ct,
                                ct,
                                accumulator,
                                extension_factor,
                                fft,
                                main_thread_buffer.stack(),
                                &mut thread_stacks,
                            );
                            black_box(output_ct);
                        },
                    )
                };
                let elements = {
                    use benchmark::find_optimal_batch::find_optimal_batch;
                    find_optimal_batch(|inputs, _batch_size| run(inputs), &mut setup) as u64
                };
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    b.iter_batched(
                        || setup(elements as usize),
                        |mut inputs| run(&mut inputs),
                        criterion::BatchSize::SmallInput,
                    )
                });
            }
        };
    }
}

pub fn extended_pbs_group() {
    let mut criterion: Criterion<_> = (Criterion::default()
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60)))
    .configure_from_args();
    ks_extended_pbs(&mut criterion);
}

fn go_through_cpu_bench_groups() {
    extended_pbs_group();
}

fn main() {
    go_through_cpu_bench_groups();

    Criterion::default().configure_from_args().final_summary();
}
