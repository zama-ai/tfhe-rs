use criterion::{criterion_group, criterion_main, Criterion};
use dyn_stack::PodStack;

fn sqr(x: f64) -> f64 {
    x * x
}

fn criterion_bench(c: &mut Criterion) {
    {
        use tfhe::core_crypto::fft_impl::fft128::crypto::bootstrap::bootstrap_scratch;
        use tfhe::core_crypto::prelude::*;
        type Scalar = u128;

        let small_lwe_dimension = LweDimension(742);
        let glwe_dimension = GlweDimension(1);
        let polynomial_size = PolynomialSize(2048);
        let lwe_modular_std_dev = StandardDev(sqr(0.000007069849454709433));
        let pbs_base_log = DecompositionBaseLog(23);
        let pbs_level = DecompositionLevelCount(1);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        let small_lwe_sk =
            LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

        let glwe_sk = GlweSecretKey::<Vec<Scalar>>::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );

        let big_lwe_sk = glwe_sk.into_lwe_secret_key();

        let fourier_bsk = Fourier128LweBootstrapKey::new(
            small_lwe_dimension,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            pbs_base_log,
            pbs_level,
        );

        let fft = Fft128::new(polynomial_size);
        let fft = fft.as_view();

        let message_modulus: Scalar = 1 << 4;

        let input_message: Scalar = 3;

        let delta: Scalar = (1 << (Scalar::BITS - 1)) / message_modulus;

        let plaintext = Plaintext(input_message * delta);

        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_sk,
            plaintext,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let accumulator: GlweCiphertextOwned<Scalar> = GlweCiphertextOwned::new(
            Scalar::ONE,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            ciphertext_modulus,
        );

        let mut pbs_out: LweCiphertext<Vec<Scalar>> = LweCiphertext::new(
            0,
            big_lwe_sk.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        let mut buf = vec![
            0u8;
            bootstrap_scratch::<Scalar>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft
            )
            .unwrap()
            .unaligned_bytes_required()
        ];

        c.bench_function("pbs128", |b| {
            b.iter(|| {
                fourier_bsk.bootstrap(
                    &mut pbs_out,
                    &lwe_ciphertext_in,
                    &accumulator,
                    fft,
                    PodStack::new(&mut buf),
                )
            });
        });
    }
}

criterion_group!(benches, criterion_bench);
criterion_main!(benches);
