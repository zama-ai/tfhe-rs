use criterion::*;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::{
    allocate_and_generate_new_binary_glwe_secret_key,
    par_allocate_and_generate_new_lwe_bootstrap_key, CiphertextModulus, DefaultRandomGenerator,
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use tfhe::core_crypto::seeders::new_seeder;
use tfhe::shortint::prelude::*;
use tfhe_csprng::seeders::Seeder;

fn criterion_bench(c: &mut Criterion) {
    let parameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let mut seeder = new_seeder();
    let mut deterministic_seeder =
        DeterministicSeeder::<DefaultRandomGenerator>::new(seeder.seed());
    let mut secret_generator =
        SecretRandomGenerator::<DefaultRandomGenerator>::new(deterministic_seeder.seed());
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        deterministic_seeder.seed(),
        &mut deterministic_seeder,
    );
    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key::<u64, _>(
        parameters.glwe_dimension,
        parameters.polynomial_size,
        &mut secret_generator,
    );
    let lwe_secret_key_after_ks = glwe_secret_key.clone().into_lwe_secret_key();
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let _ = par_allocate_and_generate_new_lwe_bootstrap_key(
                &lwe_secret_key_after_ks,
                &glwe_secret_key,
                parameters.pbs_base_log,
                parameters.pbs_level,
                parameters.glwe_noise_distribution,
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            );
        });
    });
}

criterion_group!(benches, criterion_bench);
criterion_main!(benches);
