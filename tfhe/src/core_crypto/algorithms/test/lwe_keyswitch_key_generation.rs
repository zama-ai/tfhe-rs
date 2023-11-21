use super::*;

use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::ActivatedRandomGenerator;

#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;

fn test_seeded_lwe_ksk_gen_equivalence<Scalar: UnsignedTorus + Send + Sync>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweKeyswitchKey creation
    let input_lwe_dimension = LweDimension(742);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let output_lwe_dimension = LweDimension(2048);
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
        let output_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            output_lwe_dimension,
            &mut secret_generator,
        );

        let mut ksk = LweKeyswitchKey::new(
            Scalar::ZERO,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(deterministic_seeder_seed);
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
            mask_seed,
            &mut deterministic_seeder,
        );

        generate_lwe_keyswitch_key(
            &input_lwe_secret_key,
            &output_lwe_secret_key,
            &mut ksk,
            lwe_modular_std_dev,
            &mut encryption_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &ksk,
            ciphertext_modulus
        ));

        let mut seeded_ksk = SeededLweKeyswitchKey::new(
            Scalar::ZERO,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            mask_seed.into(),
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(deterministic_seeder_seed);

        generate_seeded_lwe_keyswitch_key(
            &input_lwe_secret_key,
            &output_lwe_secret_key,
            &mut seeded_ksk,
            lwe_modular_std_dev,
            &mut deterministic_seeder,
        );

        assert!(check_encrypted_content_respects_mod(
            &seeded_ksk,
            ciphertext_modulus
        ));

        let ser_decompressed_ksk = seeded_ksk.clone().decompress_into_lwe_keyswitch_key();

        assert_eq!(ksk, ser_decompressed_ksk);

        let par_decompressed_ksk = seeded_ksk.par_decompress_into_lwe_keyswitch_key();

        assert_eq!(ser_decompressed_ksk, par_decompressed_ksk);
    }
}

#[test]
fn test_seeded_lwe_ksk_gen_equivalence_u32_native_mod() {
    test_seeded_lwe_ksk_gen_equivalence::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_seeded_lwe_ksk_gen_equivalence_u64_native_mod() {
    test_seeded_lwe_ksk_gen_equivalence::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_seeded_lwe_ksk_gen_equivalence_u32_custom_mod() {
    test_seeded_lwe_ksk_gen_equivalence::<u32>(CiphertextModulus::try_new_power_of_2(31).unwrap());
}

#[test]
fn test_seeded_lwe_ksk_gen_equivalence_u64_custom_mod() {
    test_seeded_lwe_ksk_gen_equivalence::<u64>(CiphertextModulus::try_new_power_of_2(63).unwrap());
}
