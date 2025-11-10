use criterion::{black_box, criterion_group, criterion_main, Criterion};
use modulus_switch_noise_reduction::improve_lwe_ciphertext_modulus_switch_noise_for_binary_key;
use tfhe::core_crypto::commons::parameters::{NoiseEstimationMeasureBound, RSigmaFactor};
use tfhe::core_crypto::prelude::*;

fn modulus_switch_noise_reduction(c: &mut Criterion) {
    // TODO: use shortint params
    let lwe_dimension = LweDimension(918);
    let noise_distribution = DynamicDistribution::new_t_uniform(46);
    let ciphertext_modulus = CiphertextModulus::new_native();
    let bound = NoiseEstimationMeasureBound((1_u64 << (64 - 1 - 4 - 1)) as f64);
    let r_sigma_factor = RSigmaFactor(14.658999256586121);
    let log_modulus = PolynomialSize(2048).to_blind_rotation_input_modulus_log();
    let input_variance = Variance(0.);

    for count in [10, 50, 100, 1_000, 10_000, 100_000] {
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let sk =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        let clean_lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &sk,
            Plaintext(0),
            noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut encryptions_of_zero = LweCiphertextList::new(
            0,
            lwe_dimension.to_lwe_size(),
            LweCiphertextCount(count),
            ciphertext_modulus,
        );

        let plaintext_list = PlaintextList::new(0, PlaintextCount(count));

        encrypt_lwe_ciphertext_list(
            &sk,
            &mut encryptions_of_zero,
            &plaintext_list,
            noise_distribution,
            &mut encryption_generator,
        );

        let mut lwe =
            LweCiphertext::new(0_u64, sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);

        let bench_name = "modulus_switch_noise_reduction";

        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(5));

        let bench_name = format!("modulus_switch_noise_reduction_{count}");
        println!("{bench_name}");

        bench_group.bench_function(&bench_name, |b| {
            b.iter(|| {
                lwe.as_mut().copy_from_slice(clean_lwe.as_ref());

                improve_lwe_ciphertext_modulus_switch_noise_for_binary_key(
                    &mut lwe,
                    &encryptions_of_zero,
                    r_sigma_factor,
                    bound,
                    input_variance,
                    log_modulus,
                );

                black_box(&lwe);
            });
        });
    }
}

criterion_group!(
    modulus_switch_noise_reduction2,
    modulus_switch_noise_reduction
);
criterion_main!(modulus_switch_noise_reduction2);
