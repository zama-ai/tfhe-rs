use crate::core_crypto::commons::crypto::encoding::PlaintextList;
use crate::core_crypto::commons::crypto::secret::generators::{
    DeterministicSeeder, EncryptionRandomGenerator,
};
use crate::core_crypto::commons::crypto::secret::GlweSecretKey;
use crate::core_crypto::commons::math::random::{CompressionSeed, Seeder};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::test_tools;
use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, LogStandardDev};
use concrete_csprng::generators::SoftwareRandomGenerator;

use super::{StandardGgswCiphertext, StandardGgswSeededCiphertext};

fn test_seeded_ggsw<T: UnsignedTorus>() {
    // random settings
    let nb_ct = test_tools::random_ciphertext_count(10);
    let dimension = test_tools::random_glwe_dimension(5);
    let polynomial_size = test_tools::random_polynomial_size(200);
    let noise_parameters = LogStandardDev::from_log_standard_dev(-50.);
    let decomp_level = DecompositionLevelCount(3);
    let decomp_base_log = DecompositionBaseLog(7);
    let mut secret_generator = test_tools::new_secret_random_generator();

    // generates a secret key
    let sk = GlweSecretKey::generate_binary(dimension, polynomial_size, &mut secret_generator);

    // generates random plaintexts
    let plaintext_vector =
        PlaintextList::from_tensor(secret_generator.random_uniform_tensor(nb_ct.0));

    for plaintext in plaintext_vector.plaintext_iter() {
        let main_seed = test_tools::random_seed();

        // Use a deterministic seeder to get the seeds that will be used during the tests
        let mut deterministic_seeder =
            DeterministicSeeder::<SoftwareRandomGenerator>::new(main_seed);
        let noise_seed = deterministic_seeder.seed();
        let mask_seed = deterministic_seeder.seed();

        // encrypts
        let mut seeded_ggsw = StandardGgswSeededCiphertext::allocate(
            polynomial_size,
            dimension.to_glwe_size(),
            decomp_level,
            decomp_base_log,
            CompressionSeed { seed: mask_seed },
        );

        // Recreate a second deterministic seeder to control the behavior of the seeded encryption
        let mut seeder = DeterministicSeeder::<SoftwareRandomGenerator>::new(main_seed);

        sk.encrypt_constant_seeded_ggsw::<_, _, _, _, SoftwareRandomGenerator>(
            &mut seeded_ggsw,
            plaintext,
            noise_parameters,
            &mut seeder,
        );

        // expands
        let mut ggsw_expanded = StandardGgswCiphertext::allocate(
            T::ZERO,
            polynomial_size,
            dimension.to_glwe_size(),
            decomp_level,
            decomp_base_log,
        );
        seeded_ggsw.expand_into::<_, _, SoftwareRandomGenerator>(&mut ggsw_expanded);

        // control encryption
        let mut ggsw = StandardGgswCiphertext::allocate(
            T::ZERO,
            polynomial_size,
            dimension.to_glwe_size(),
            decomp_level,
            decomp_base_log,
        );

        // Recreate a generator with the known mask seed
        let mut generator = EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
            mask_seed,
            &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(main_seed),
        );
        // And force the noise seed (only available in tests) to the noise seed we know was used
        generator.seed_noise_generator(noise_seed);

        sk.encrypt_constant_ggsw(&mut ggsw, plaintext, noise_parameters, &mut generator);

        assert_eq!(ggsw_expanded, ggsw);
    }
}

#[test]
fn test_seeded_ggsw_u32() {
    test_seeded_ggsw::<u32>()
}

#[test]
fn test_seeded_ggsw_u64() {
    test_seeded_ggsw::<u64>()
}

#[cfg(feature = "__commons_parallel")]
mod parallel {
    use crate::core_crypto::commons::crypto::encoding::PlaintextList;
    use crate::core_crypto::commons::crypto::secret::generators::{
        DeterministicSeeder, EncryptionRandomGenerator,
    };
    use crate::core_crypto::commons::crypto::secret::GlweSecretKey;
    use crate::core_crypto::commons::math::random::{CompressionSeed, Seeder};
    use crate::core_crypto::commons::math::torus::UnsignedTorus;
    use crate::core_crypto::commons::test_tools;
    use crate::core_crypto::prelude::{
        DecompositionBaseLog, DecompositionLevelCount, LogStandardDev,
    };
    use concrete_csprng::generators::SoftwareRandomGenerator;

    use super::{StandardGgswCiphertext, StandardGgswSeededCiphertext};

    fn test_par_seeded_ggsw<T: UnsignedTorus + Send + Sync>() {
        // random settings
        let nb_ct = test_tools::random_ciphertext_count(10);
        let dimension = test_tools::random_glwe_dimension(5);
        let polynomial_size = test_tools::random_polynomial_size(200);
        let noise_parameters = LogStandardDev::from_log_standard_dev(-50.);
        let decomp_level = DecompositionLevelCount(3);
        let decomp_base_log = DecompositionBaseLog(7);
        let mut secret_generator = test_tools::new_secret_random_generator();

        // generates a secret key
        let sk = GlweSecretKey::generate_binary(dimension, polynomial_size, &mut secret_generator);

        // generates random plaintexts
        let plaintext_vector =
            PlaintextList::from_tensor(secret_generator.random_uniform_tensor(nb_ct.0));

        for plaintext in plaintext_vector.plaintext_iter() {
            let main_seed = test_tools::random_seed();

            // Use a deterministic seeder to get the seeds that will be used during the tests
            let mut deterministic_seeder =
                DeterministicSeeder::<SoftwareRandomGenerator>::new(main_seed);
            let noise_seed = deterministic_seeder.seed();
            let mask_seed = deterministic_seeder.seed();

            // encrypts
            let mut seeded_ggsw = StandardGgswSeededCiphertext::allocate(
                polynomial_size,
                dimension.to_glwe_size(),
                decomp_level,
                decomp_base_log,
                CompressionSeed { seed: mask_seed },
            );

            // Recreate a second deterministic seeder to control the behavior of the seeded
            // encryption
            let mut seeder = DeterministicSeeder::<SoftwareRandomGenerator>::new(main_seed);

            sk.par_encrypt_constant_seeded_ggsw::<_, _, _, _, SoftwareRandomGenerator>(
                &mut seeded_ggsw,
                plaintext,
                noise_parameters,
                &mut seeder,
            );

            // expands
            let mut ggsw_expanded = StandardGgswCiphertext::allocate(
                T::ZERO,
                polynomial_size,
                dimension.to_glwe_size(),
                decomp_level,
                decomp_base_log,
            );
            seeded_ggsw.expand_into::<_, _, SoftwareRandomGenerator>(&mut ggsw_expanded);

            // control encryption
            let mut ggsw = StandardGgswCiphertext::allocate(
                T::ZERO,
                polynomial_size,
                dimension.to_glwe_size(),
                decomp_level,
                decomp_base_log,
            );

            // Recreate a generator with the known mask seed
            let mut generator = EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                mask_seed,
                &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(main_seed),
            );
            // And force the noise seed (only available in tests) to the noise seed we know was used
            generator.seed_noise_generator(noise_seed);

            sk.par_encrypt_constant_ggsw(&mut ggsw, plaintext, noise_parameters, &mut generator);

            assert_eq!(ggsw_expanded, ggsw);
        }
    }

    #[test]
    fn test_par_seeded_ggsw_u32() {
        test_par_seeded_ggsw::<u32>()
    }

    #[test]
    fn test_par_seeded_ggsw_u64() {
        test_par_seeded_ggsw::<u64>()
    }
}
