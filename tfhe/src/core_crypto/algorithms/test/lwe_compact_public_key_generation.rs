use super::*;
use crate::core_crypto::commons::generators::{DeterministicSeeder, MaskRandomGenerator};
use crate::core_crypto::commons::math::random::Uniform;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn test_seeded_lwe_cpk_gen_equivalence<Scalar: UnsignedTorus>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweCompactPublicKey creation
    let lwe_dimension = LweDimension(1024);
    let lwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.00000004990272175010415), 0.0);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mask_seed = seeder.seed();
    let deterministic_seeder_seed = seeder.seed();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    for _ in 0..NB_TESTS {
        // Create the LweSecretKey
        let input_lwe_secret_key =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        let mut cpk = LweCompactPublicKey::new(Scalar::ZERO, lwe_dimension, ciphertext_modulus);

        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed);
        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            mask_seed,
            &mut deterministic_seeder,
        );

        generate_lwe_compact_public_key(
            &input_lwe_secret_key,
            &mut cpk,
            lwe_noise_distribution,
            &mut encryption_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &cpk,
            ciphertext_modulus
        ));

        let mut seeded_cpk = SeededLweCompactPublicKey::new(
            Scalar::ZERO,
            lwe_dimension,
            mask_seed.into(),
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed);

        generate_seeded_lwe_compact_public_key(
            &input_lwe_secret_key,
            &mut seeded_cpk,
            lwe_noise_distribution,
            &mut deterministic_seeder,
        );

        assert!(check_encrypted_content_respects_mod(
            &seeded_cpk,
            ciphertext_modulus
        ));

        let decompressed_cpk = seeded_cpk.decompress_into_lwe_compact_public_key();

        assert_eq!(cpk, decompressed_cpk);
    }
}

#[test]
fn test_seeded_lwe_cpk_gen_equivalence_u32_native_mod() {
    test_seeded_lwe_cpk_gen_equivalence::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_seeded_lwe_cpk_gen_equivalence_u64_naive_mod() {
    test_seeded_lwe_cpk_gen_equivalence::<u64>(CiphertextModulus::new_native());
}

/// Verify a generator forked by `decompression_fork_config` is fully exhausted after the
/// decompression call (its mask budget matches what decompression consumes).
fn test_seeded_lwe_cpk_decompression_fork_config_exhaustion<Scalar: UnsignedTorus>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    // `SeededLweCompactPublicKey` requires a power-of-2 lwe dimension.
    let lwe_dimension = LweDimension(1024);

    let mut seeder = new_seeder();
    let seed = seeder.as_mut().seed();

    // Contents don't affect byte consumption, so a zeroed seeded key suffices.
    let seeded_cpk = SeededLweCompactPublicKey::new(
        Scalar::ZERO,
        lwe_dimension,
        seed.into(),
        ciphertext_modulus,
    );

    let mut output_cpk = LweCompactPublicKey::new(Scalar::ZERO, lwe_dimension, ciphertext_modulus);

    let mut generator =
        MaskRandomGenerator::<DefaultRandomGenerator>::new(seeded_cpk.compression_seed());
    let mut child = generator
        .try_fork_from_config(seeded_cpk.decompression_fork_config(Uniform))
        .expect("failed to fork generator")
        .next()
        .expect("decompression_fork_config must yield exactly one child");

    decompress_seeded_lwe_compact_public_key_with_pre_seeded_generator(
        &mut output_cpk,
        &seeded_cpk,
        &mut child,
    );

    assert_eq!(
        child.remaining_bytes(),
        Some(0),
        "mask generator must be exhausted after compact public key decompression",
    );
}

#[test]
fn test_seeded_lwe_cpk_decompression_fork_config_exhaustion_u64_native_mod() {
    test_seeded_lwe_cpk_decompression_fork_config_exhaustion::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_seeded_lwe_cpk_decompression_fork_config_exhaustion_u64_custom_mod() {
    test_seeded_lwe_cpk_decompression_fork_config_exhaustion::<u64>(
        CiphertextModulus::try_new_power_of_2(63).unwrap(),
    );
}
