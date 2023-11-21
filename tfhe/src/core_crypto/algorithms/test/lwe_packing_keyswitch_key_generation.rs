use super::*;

use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::ActivatedRandomGenerator;

#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;

fn test_seeded_lwe_pksk_gen_equivalence<Scalar: UnsignedTorus>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweKeyswitchKey creation
    let input_lwe_dimension = LweDimension(742);
    let output_glwe_dimension = GlweDimension(1);
    let output_polynomial_size = PolynomialSize(2048);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let decomp_base_log = DecompositionBaseLog(3);
    let decomp_level_count = DecompositionLevelCount(5);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mask_seed = seeder.seed();
    let deterministic_seeder_seed = seeder.seed();
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for _ in 0..NB_TESTS {
        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            input_lwe_dimension,
            &mut secret_generator,
        );
        let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            output_glwe_dimension,
            output_polynomial_size,
            &mut secret_generator,
        );

        let mut pksk = LwePackingKeyswitchKey::new(
            Scalar::ZERO,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(deterministic_seeder_seed);
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
            mask_seed,
            &mut deterministic_seeder,
        );

        generate_lwe_packing_keyswitch_key(
            &input_lwe_secret_key,
            &output_glwe_secret_key,
            &mut pksk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &pksk,
            ciphertext_modulus
        ));

        let mut seeded_pksk = SeededLwePackingKeyswitchKey::new(
            Scalar::ZERO,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            mask_seed.into(),
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(deterministic_seeder_seed);

        generate_seeded_lwe_packing_keyswitch_key(
            &input_lwe_secret_key,
            &output_glwe_secret_key,
            &mut seeded_pksk,
            glwe_modular_std_dev,
            &mut deterministic_seeder,
        );

        assert!(check_encrypted_content_respects_mod(
            &seeded_pksk,
            ciphertext_modulus
        ));

        let decompressed_ksk = seeded_pksk.decompress_into_lwe_packing_keyswitch_key();

        assert_eq!(pksk, decompressed_ksk);
    }
}

#[test]
fn test_seeded_lwe_pksk_gen_equivalence_u32_native_mod() {
    test_seeded_lwe_pksk_gen_equivalence::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_seeded_lwe_pksk_gen_equivalence_u64_native_mod() {
    test_seeded_lwe_pksk_gen_equivalence::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_seeded_lwe_pksk_gen_equivalence_u32_custom_mod() {
    test_seeded_lwe_pksk_gen_equivalence::<u32>(CiphertextModulus::try_new_power_of_2(31).unwrap());
}

#[test]
fn test_seeded_lwe_pksk_gen_equivalence_u64_custom_mod() {
    test_seeded_lwe_pksk_gen_equivalence::<u64>(CiphertextModulus::try_new_power_of_2(63).unwrap());
}
