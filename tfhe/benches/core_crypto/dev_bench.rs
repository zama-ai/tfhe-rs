use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe::core_crypto::prelude::*;

criterion_group!(
    boolean_like_pbs_group,
    multi_bit_pbs::<u32>,
    pbs::<u32>,
    mem_optimized_pbs::<u32>
);

criterion_group!(
    shortint_like_pbs_group,
    multi_bit_pbs::<u64>,
    pbs::<u64>,
    mem_optimized_pbs::<u64>
);

criterion_main!(boolean_like_pbs_group, shortint_like_pbs_group);

fn get_bench_params<Scalar: Numeric>() -> (
    LweDimension,
    StandardDev,
    DecompositionBaseLog,
    DecompositionLevelCount,
    GlweDimension,
    PolynomialSize,
    LweBskGroupingFactor,
    ThreadCount,
) {
    if Scalar::BITS == 64 {
        (
            LweDimension(742),
            StandardDev(0.000007069849454709433),
            DecompositionBaseLog(3),
            DecompositionLevelCount(5),
            GlweDimension(1),
            PolynomialSize(1024),
            LweBskGroupingFactor(2),
            ThreadCount(5),
        )
    } else if Scalar::BITS == 32 {
        (
            LweDimension(778),
            StandardDev(0.000003725679281679651),
            DecompositionBaseLog(18),
            DecompositionLevelCount(1),
            GlweDimension(3),
            PolynomialSize(512),
            LweBskGroupingFactor(2),
            ThreadCount(5),
        )
    } else {
        unreachable!()
    }
}

fn multi_bit_pbs<Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync>(
    c: &mut Criterion,
) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweBootstrapKey creation

    let (
        mut input_lwe_dimension,
        lwe_std_dev,
        decomp_base_log,
        decomp_level_count,
        glwe_dimension,
        polynomial_size,
        grouping_factor,
        thread_count,
    ) = get_bench_params::<Scalar>();

    let lwe_noise_distribution = Gaussian {
        std: lwe_std_dev.0,
        mean: 0.0,
    };

    let ciphertext_modulus = CiphertextModulus::new_native();

    while input_lwe_dimension.0 % grouping_factor.0 != 0 {
        input_lwe_dimension = LweDimension(input_lwe_dimension.0 + 1);
    }

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // Create the LweSecretKey
    let input_lwe_secret_key =
        allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
    let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
        allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
    let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

    let multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
        input_lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        grouping_factor,
    );

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        Plaintext(Scalar::ZERO),
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let accumulator = GlweCiphertext::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    // Allocate the LweCiphertext to store the result of the PBS
    let mut out_pbs_ct = LweCiphertext::new(
        Scalar::ZERO,
        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    let id = format!("Multi Bit PBS {}", Scalar::BITS);

    {
        c.bench_function(&id, |b| {
            b.iter(|| {
                multi_bit_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator.as_view(),
                    &multi_bit_bsk,
                    thread_count,
                    false,
                );
                black_box(&mut out_pbs_ct);
            })
        });
    }
}

fn pbs<Scalar: UnsignedTorus + CastInto<usize>>(c: &mut Criterion) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweBootstrapKey creation

    let (
        input_lwe_dimension,
        lwe_std_dev,
        decomp_base_log,
        decomp_level_count,
        glwe_dimension,
        polynomial_size,
        _,
        _,
    ) = get_bench_params::<Scalar>();

    let lwe_noise_distribution = Gaussian {
        std: lwe_std_dev.0,
        mean: 0.0,
    };

    let ciphertext_modulus = CiphertextModulus::new_native();

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // Create the LweSecretKey
    let input_lwe_secret_key =
        allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
    let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
        allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
    let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

    // Create the empty bootstrapping key in the Fourier domain
    let fourier_bsk = FourierLweBootstrapKey::new(
        input_lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
    );

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        Plaintext(Scalar::ZERO),
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let accumulator = GlweCiphertext::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    // Allocate the LweCiphertext to store the result of the PBS
    let mut out_pbs_ct = LweCiphertext::new(
        Scalar::ZERO,
        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    let id = format!("PBS {}", Scalar::BITS);
    {
        c.bench_function(&id, |b| {
            b.iter(|| {
                programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator.as_view(),
                    &fourier_bsk,
                );
                black_box(&mut out_pbs_ct);
            })
        });
    }
}

fn mem_optimized_pbs<Scalar: UnsignedTorus + CastInto<usize>>(c: &mut Criterion) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweBootstrapKey creation

    let (
        input_lwe_dimension,
        lwe_std_dev,
        decomp_base_log,
        decomp_level_count,
        glwe_dimension,
        polynomial_size,
        _,
        _,
    ) = get_bench_params::<Scalar>();

    let lwe_noise_distribution = Gaussian {
        std: lwe_std_dev.0,
        mean: 0.0,
    };

    let ciphertext_modulus = CiphertextModulus::new_native();

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // Create the LweSecretKey
    let input_lwe_secret_key =
        allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
    let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
        allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
    let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

    // Create the empty bootstrapping key in the Fourier domain
    let fourier_bsk = FourierLweBootstrapKey::new(
        input_lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
    );

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        Plaintext(Scalar::ZERO),
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let accumulator = GlweCiphertext::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );
    // Allocate the LweCiphertext to store the result of the PBS
    let mut out_pbs_ct = LweCiphertext::new(
        Scalar::ZERO,
        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
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

    let id = format!("PBS mem-optimized {}", Scalar::BITS);
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
