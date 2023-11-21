use super::*;

use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::ActivatedRandomGenerator;

#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;

fn test_seeded_lwe_cpk_gen_equivalence<Scalar: UnsignedTorus>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweCompactPublicKey creation
    let lwe_dimension = LweDimension(1024);
    let lwe_modular_std_dev = StandardDev(0.00000004990272175010415);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mask_seed = seeder.seed();
    let deterministic_seeder_seed = seeder.seed();
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for _ in 0..NB_TESTS {
        // Create the LweSecretKey
        let input_lwe_secret_key =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        let mut cpk = LweCompactPublicKey::new(Scalar::ZERO, lwe_dimension, ciphertext_modulus);

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(deterministic_seeder_seed);
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
            mask_seed,
            &mut deterministic_seeder,
        );

        generate_lwe_compact_public_key(
            &input_lwe_secret_key,
            &mut cpk,
            lwe_modular_std_dev,
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
            DeterministicSeeder::<ActivatedRandomGenerator>::new(deterministic_seeder_seed);

        generate_seeded_lwe_compact_public_key(
            &input_lwe_secret_key,
            &mut seeded_cpk,
            lwe_modular_std_dev,
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
