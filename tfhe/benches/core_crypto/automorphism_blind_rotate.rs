use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe::core_crypto::fft_impl::common::automorphism_modulus_switch;
use tfhe::core_crypto::prelude::automorphism_base_blind_rotate::{blind_rotate, TravBsk, Travs};
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, LweDimension, PolynomialSize,
};

fn automorphism(c: &mut Criterion) {
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let lwe_dimension = LweDimension(800);

    let glwe_size = GlweSize(2);
    let polynomial_size = PolynomialSize(2048);

    let lwe_noise_distribution = Gaussian::from_dispersion_parameter(StandardDev(0.0), 0.0);

    let glwe_noise_distribution = Gaussian::from_dispersion_parameter(StandardDev(0.0), 0.0);

    let decomp_base_log = DecompositionBaseLog(30);
    let decomp_level_count = DecompositionLevelCount(1);

    let ciphertext_modulus = CiphertextModulus::new_native();

    let lwe_secret_key: LweSecretKey<Vec<u64>> =
        allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_size.to_glwe_dimension(),
        polynomial_size,
        &mut secret_generator,
    );

    let base = 5;

    let window_size = 4;

    let travs = Travs::new(
        &glwe_secret_key,
        decomp_base_log,
        decomp_level_count,
        glwe_noise_distribution,
        ciphertext_modulus,
        window_size,
        base,
        &mut encryption_generator,
    );

    let bsks = TravBsk::new(
        base as usize,
        &lwe_secret_key,
        &glwe_secret_key,
        5,
        decomp_base_log,
        decomp_level_count,
        ciphertext_modulus,
        glwe_noise_distribution,
        &mut encryption_generator,
    );

    let mut lut = vec![0; polynomial_size.0];

    lut[0] = 1 << 60;

    lut[1] = 2 << 60;

    lut[2] = 3 << 60;

    let lut_glwe = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &PlaintextList::from_container(lut.clone()),
        ciphertext_modulus,
    );

    let bench_name = "core_crypto::automorphism_blind_rotate";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    let params_name = "Custom";

    let id = format!("{bench_name}::{params_name}");
    bench_group.bench_function(&id, |bencher| {
        bencher.iter(|| {
            let lwe = allocate_and_encrypt_new_lwe_ciphertext(
                &lwe_secret_key,
                Plaintext(1 << 60),
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut encryption_generator,
            );

            let (lwe_mask, lwe_body) = lwe.get_mask_and_body();

            let b = automorphism_modulus_switch(*lwe_body.data, polynomial_size) as u64;

            let ais: Vec<u64> = lwe_mask
                .as_ref()
                .iter()
                .map(|a| automorphism_modulus_switch(*a, polynomial_size) as u64)
                .collect();

            let mut acc = lut_glwe.clone();

            blind_rotate(
                b,
                &ais,
                &bsks,
                base,
                &travs,
                acc.as_mut_view(),
                polynomial_size,
                glwe_size,
            );
            black_box(&mut acc);
        });
    });
}

criterion_group!(automorphism_group, automorphism);
criterion_main!(automorphism_group);
