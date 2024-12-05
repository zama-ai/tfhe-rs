use criterion::{black_box, criterion_group, criterion_main, Criterion};
use modulus_switch_noise_reduction::improve_modulus_switch_noise;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

fn modulus_switch_noise_reduction(c: &mut Criterion) {
    for count in [10, 50, 100, 1_000, 10_000, 100_000] {
        let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let ciphertext_modulus = params.ciphertext_modulus;

        let lwe_dim = params.lwe_dimension;

        let noise_distribution = params.lwe_noise_distribution;

        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let bound = 188.2e15_f64;

        let log_modulus = params.polynomial_size.to_blind_rotation_input_modulus_log();

        let sk = allocate_and_generate_new_binary_lwe_secret_key(lwe_dim, &mut secret_generator);

        let clean_lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &sk,
            Plaintext(0),
            noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut encryptions_of_zero = LweCiphertextList::new(
            0,
            lwe_dim.to_lwe_size(),
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

        let mut lwe = LweCiphertext::new(0, sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);

        let bench_name = "modulus_switch_noise_reduction";

        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(5));

        let bench_name = format!("modulus_switch_noise_reduction_{count}");

        bench_group.bench_function(&bench_name, |b| {
            b.iter(|| {
                lwe.as_mut().copy_from_slice(clean_lwe.as_ref());

                improve_modulus_switch_noise(
                    &mut lwe,
                    &encryptions_of_zero,
                    9.16,
                    bound,
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
