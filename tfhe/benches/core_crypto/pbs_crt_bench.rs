use criterion::{criterion_group, criterion_main, Criterion};
use dyn_stack::PodStack;

fn criterion_bench(c: &mut Criterion) {
    {
        use tfhe::core_crypto::fft_impl::crt_ntt::crypto::bootstrap::{
            bootstrap_scratch, CrtNttLweBootstrapKey,
        };
        use tfhe::core_crypto::fft_impl::crt_ntt::math::ntt::CrtNtt64;
        use tfhe::core_crypto::prelude::*;
        type Scalar = u64;

        let small_lwe_dimension = LweDimension(742);
        let glwe_dimension = GlweDimension(1);
        let polynomial_size = PolynomialSize(2048);
        let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
        let pbs_base_log = DecompositionBaseLog(23);
        let pbs_level = DecompositionLevelCount(1);

        // Request the best seeder possible, starting with hardware entropy sources and falling back
        // to /dev/random on Unix systems if enabled via cargo features
        let mut boxed_seeder = new_seeder();
        // Get a mutable reference to the seeder as a trait object from the Box returned by
        // new_seeder
        let seeder = boxed_seeder.as_mut();

        // Create a generator which uses a CSPRNG to generate secret keys
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
        // noise
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate an LweSecretKey with binary coefficients
        let small_lwe_sk =
            LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

        // Generate a GlweSecretKey with binary coefficients
        let glwe_sk = GlweSecretKey::<Vec<Scalar>>::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );

        // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
        let big_lwe_sk = glwe_sk.into_lwe_secret_key();

        // Create the empty bootstrapping key in the NTT domain
        let ntt_bsk = CrtNttLweBootstrapKey::new(
            small_lwe_dimension,
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            pbs_base_log,
            pbs_level,
        );

        let fft = CrtNtt64::new(polynomial_size);
        let fft = fft.as_view();

        // We don't need the standard bootstrapping key anymore

        // Our 4 bits message space
        let message_modulus: Scalar = 1 << 4;

        // Our input message
        let input_message: Scalar = 3;

        // Delta used to encode 4 bits of message + a bit of padding on Scalar
        let delta: Scalar = (1 << (Scalar::BITS - 1)) / message_modulus;

        // Apply our encoding
        let plaintext = Plaintext(input_message * delta);

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_sk,
            plaintext,
            lwe_modular_std_dev,
            &mut encryption_generator,
        );

        let accumulator: GlweCiphertextOwned<Scalar> =
            GlweCiphertextOwned::new(Scalar::ONE, glwe_dimension.to_glwe_size(), polynomial_size);

        // Allocate the LweCiphertext to store the result of the PBS
        let mut pbs_multiplication_ct: LweCiphertext<Vec<Scalar>> =
            LweCiphertext::new(0, big_lwe_sk.lwe_dimension().to_lwe_size());

        let mut buf = vec![
            0u8;
            bootstrap_scratch::<u32, 5, Scalar>(
                ntt_bsk.glwe_size(),
                ntt_bsk.polynomial_size(),
            )
            .unwrap()
            .unaligned_bytes_required()
        ];

        c.bench_function("pbs-crt-u64-u32x5", |b| {
            b.iter(|| {
                ntt_bsk.bootstrap(
                    &mut pbs_multiplication_ct,
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
