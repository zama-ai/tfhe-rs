//! LWE encryption scheme.
mod ciphertext;
mod keyswitch;
mod list;
mod seeded_ciphertext;
mod seeded_keyswitch;
mod seeded_list;

pub use ciphertext::*;
pub use keyswitch::*;
pub use list::*;
pub use seeded_ciphertext::*;
pub use seeded_keyswitch::*;
pub use seeded_list::*;

#[cfg(test)]
mod test {
    use crate::core_crypto::commons::crypto::lwe::{LweKeyswitchKey, LweSeededKeyswitchKey};
    use crate::core_crypto::commons::crypto::secret::generators::{
        DeterministicSeeder, EncryptionRandomGenerator,
    };
    use crate::core_crypto::commons::crypto::secret::LweSecretKey;
    use crate::core_crypto::commons::math::random::CompressionSeed;
    use crate::core_crypto::commons::math::torus::UnsignedTorus;
    use crate::core_crypto::commons::test_tools::new_secret_random_generator;
    use crate::core_crypto::prelude::{
        DecompositionBaseLog, DecompositionLevelCount, LweDimension, StandardDev,
    };
    use concrete_csprng::generators::SoftwareRandomGenerator;
    use concrete_csprng::seeders::Seed;

    fn test_ksk_seeded_gen_equivalence<T: UnsignedTorus>() {
        for _ in 0..10 {
            let input_lwe_dim =
                LweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let output_lwe_dim =
                LweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let level = DecompositionLevelCount(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let base_log = DecompositionBaseLog(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let mask_seed = Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);
            let deterministic_seeder_seed =
                Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);

            let compression_seed = CompressionSeed { seed: mask_seed };

            let mut secret_generator = new_secret_random_generator();

            let input_key = LweSecretKey::generate_binary(input_lwe_dim, &mut secret_generator);
            let output_key = LweSecretKey::generate_binary(output_lwe_dim, &mut secret_generator);

            let mut ksk =
                LweKeyswitchKey::allocate(T::ZERO, level, base_log, input_lwe_dim, output_lwe_dim);

            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    mask_seed,
                    &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(
                        deterministic_seeder_seed,
                    ),
                );

            ksk.fill_with_keyswitch_key(
                &input_key,
                &output_key,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            let mut seeded_ksk = LweSeededKeyswitchKey::allocate(
                level,
                base_log,
                input_lwe_dim,
                output_lwe_dim,
                compression_seed,
            );

            seeded_ksk.fill_with_seeded_keyswitch_key::<_, _, _, _, _, SoftwareRandomGenerator>(
                &input_key,
                &output_key,
                StandardDev::from_standard_dev(10.),
                &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(deterministic_seeder_seed),
            );

            let mut expanded_ksk =
                LweKeyswitchKey::allocate(T::ZERO, level, base_log, input_lwe_dim, output_lwe_dim);

            seeded_ksk.expand_into::<_, _, SoftwareRandomGenerator>(&mut expanded_ksk);

            assert_eq!(ksk, expanded_ksk);
        }
    }

    #[test]
    fn test_ksk_seeded_gen_equivalence_u32() {
        test_ksk_seeded_gen_equivalence::<u32>()
    }

    #[test]
    fn test_ksk_seeded_gen_equivalence_u64() {
        test_ksk_seeded_gen_equivalence::<u64>()
    }
}
