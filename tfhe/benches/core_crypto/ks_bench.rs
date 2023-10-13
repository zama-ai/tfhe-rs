use criterion::{criterion_group, criterion_main, Criterion};
use tfhe::core_crypto::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::shortint::prelude::*;

fn criterion_bench(criterion: &mut Criterion) {
    type Scalar = u64;

    let mut bench_group = criterion.benchmark_group("KS");
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    for params in [
        PARAM_MESSAGE_1_CARRY_1_KS_PBS,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    ]
    .into_iter()
    {
        let lwe_dimension = params.lwe_dimension;
        let lwe_modular_std_dev = params.lwe_modular_std_dev;
        let ciphertext_modulus = params.ciphertext_modulus;
        let encoding_with_padding = if ciphertext_modulus.is_native_modulus() {
            Scalar::ONE << (Scalar::BITS - 1)
        } else {
            Scalar::cast_from(ciphertext_modulus.get_custom_modulus() / 2)
        };
        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        let ks_decomp_base_log = params.ks_base_log;
        let ks_decomp_level_count = params.ks_level;
        let msg_modulus: Scalar = params.message_modulus.0.cast_into();
        let total_modulus: Scalar = (params.message_modulus.0 * params.carry_modulus.0).cast_into();

        let msg = msg_modulus - 1;
        let delta: Scalar = encoding_with_padding / total_modulus;

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        let lwe_sk =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
        let big_lwe_sk = glwe_sk.into_lwe_secret_key();
        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_sk,
            &lwe_sk,
            ks_decomp_base_log,
            ks_decomp_level_count,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let plaintext = Plaintext(msg * delta);
        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            &big_lwe_sk,
            plaintext,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut output_ct = LweCiphertext::new(
            Scalar::ZERO,
            lwe_sk.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        bench_group.bench_function(&params.name(), |bencher| {
            bencher.iter(|| {
                keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut output_ct);
            })
        });
    }
}

criterion_group!(benches, criterion_bench);
criterion_main!(benches);
