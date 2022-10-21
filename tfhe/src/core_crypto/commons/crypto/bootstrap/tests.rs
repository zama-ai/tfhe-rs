use crate::core_crypto::commons::crypto::bootstrap::{
    StandardBootstrapKey, StandardSeededBootstrapKey,
};
use crate::core_crypto::commons::crypto::secret::generators::{
    DeterministicSeeder, EncryptionRandomGenerator,
};
use crate::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::test_tools::new_secret_random_generator;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    StandardDev,
};
use concrete_csprng::generators::SoftwareRandomGenerator;
use concrete_csprng::seeders::Seed;

fn test_bsk_seeded_gen_equivalence<T: UnsignedTorus + Send + Sync>() {
    for _ in 0..10 {
        let lwe_dim = LweDimension(
            crate::core_crypto::commons::test_tools::random_usize_between(5..10),
        );
        let glwe_dim = GlweDimension(
            crate::core_crypto::commons::test_tools::random_usize_between(5..10),
        );
        let poly_size = PolynomialSize(
            crate::core_crypto::commons::test_tools::random_usize_between(5..10),
        );
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
        let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
        let glwe_sk = GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);

        let mut bsk = StandardBootstrapKey::allocate(
            T::ZERO,
            glwe_dim.to_glwe_size(),
            poly_size,
            level,
            base_log,
            lwe_dim,
        );

        let mut encryption_generator = EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
            mask_seed,
            &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(deterministic_seeder_seed),
        );

        bsk.fill_with_new_key(
            &lwe_sk,
            &glwe_sk,
            StandardDev::from_standard_dev(10.),
            &mut encryption_generator,
        );

        let mut seeded_bsk = StandardSeededBootstrapKey::allocate(
            glwe_dim.to_glwe_size(),
            poly_size,
            level,
            base_log,
            lwe_dim,
            compression_seed,
        );

        seeded_bsk.fill_with_new_key::<_, _, _, _, _, SoftwareRandomGenerator>(
            &lwe_sk,
            &glwe_sk,
            StandardDev::from_standard_dev(10.),
            &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(deterministic_seeder_seed),
        );

        let mut expanded_bsk = StandardBootstrapKey::allocate(
            T::ZERO,
            glwe_dim.to_glwe_size(),
            poly_size,
            level,
            base_log,
            lwe_dim,
        );

        seeded_bsk.expand_into::<_, _, SoftwareRandomGenerator>(&mut expanded_bsk);

        assert_eq!(bsk, expanded_bsk);
    }
}

#[test]
fn test_bsk_seeded_gen_equivalence_u32() {
    test_bsk_seeded_gen_equivalence::<u32>()
}

#[test]
fn test_bsk_seeded_gen_equivalence_u64() {
    test_bsk_seeded_gen_equivalence::<u64>()
}

#[cfg(all(test, feature = "__commons_parallel"))]
mod parallel {
    use crate::core_crypto::commons::crypto::bootstrap::{
        StandardBootstrapKey, StandardSeededBootstrapKey,
    };
    use crate::core_crypto::commons::crypto::secret::generators::{
        DeterministicSeeder, EncryptionRandomGenerator,
    };
    use crate::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    use crate::core_crypto::commons::math::random::CompressionSeed;
    use crate::core_crypto::commons::math::torus::UnsignedTorus;
    use crate::core_crypto::commons::test_tools::{
        new_secret_random_generator, UnsafeRandSeeder,
    };
    use crate::core_crypto::prelude::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
        StandardDev,
    };
    use concrete_csprng::generators::SoftwareRandomGenerator;
    use concrete_csprng::seeders::Seed;

    fn test_bsk_gen_equivalence<T: UnsignedTorus + Send + Sync>() {
        for _ in 0..10 {
            let lwe_dim = LweDimension(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let glwe_dim = GlweDimension(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let poly_size = PolynomialSize(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let level = DecompositionLevelCount(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let base_log = DecompositionBaseLog(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let mask_seed = crate::core_crypto::commons::test_tools::any_usize() as u128;
            let noise_seed = crate::core_crypto::commons::test_tools::any_usize() as u128;

            let mut secret_generator = new_secret_random_generator();
            let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
            let glwe_sk =
                GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);

            let mut mono_bsk = StandardBootstrapKey::allocate(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                level,
                base_log,
                lwe_dim,
            );
            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    Seed(mask_seed),
                    &mut UnsafeRandSeeder,
                );
            encryption_generator.seed_noise_generator(Seed(noise_seed));
            mono_bsk.fill_with_new_key(
                &lwe_sk,
                &glwe_sk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            let mut multi_bsk = StandardBootstrapKey::allocate(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                level,
                base_log,
                lwe_dim,
            );
            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    Seed(mask_seed),
                    &mut UnsafeRandSeeder,
                );
            encryption_generator.seed_noise_generator(Seed(noise_seed));
            multi_bsk.par_fill_with_new_key(
                &lwe_sk,
                &glwe_sk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            assert_eq!(mono_bsk, multi_bsk);
        }
    }

    fn test_bsk_par_seeded_gen_equivalence<T: UnsignedTorus + Send + Sync>() {
        for _ in 0..10 {
            let lwe_dim = LweDimension(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let glwe_dim = GlweDimension(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let poly_size = PolynomialSize(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let level = DecompositionLevelCount(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let base_log = DecompositionBaseLog(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let mask_seed =
                Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);
            let deterministic_seeder_seed =
                Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);

            let compression_seed = CompressionSeed { seed: mask_seed };

            let mut secret_generator = new_secret_random_generator();
            let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
            let glwe_sk =
                GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);

            let mut bsk = StandardBootstrapKey::allocate(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                level,
                base_log,
                lwe_dim,
            );

            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    mask_seed,
                    &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(
                        deterministic_seeder_seed,
                    ),
                );

            // To mitigate current issues with forking SoftwareRandomGenerator generators
            // We know parallel and sequential generation of bsk are the same thanks to the
            // test_bsk_gen_equivalence based tests
            bsk.fill_with_new_key(
                &lwe_sk,
                &glwe_sk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            let mut par_seeded_bsk = StandardSeededBootstrapKey::allocate(
                glwe_dim.to_glwe_size(),
                poly_size,
                level,
                base_log,
                lwe_dim,
                compression_seed,
            );

            par_seeded_bsk.par_fill_with_new_key::<_, _, _, _, _, SoftwareRandomGenerator>(
                &lwe_sk,
                &glwe_sk,
                StandardDev::from_standard_dev(10.),
                &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(deterministic_seeder_seed),
            );

            let mut expanded_bsk = StandardBootstrapKey::allocate(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                level,
                base_log,
                lwe_dim,
            );

            par_seeded_bsk.expand_into::<_, _, SoftwareRandomGenerator>(&mut expanded_bsk);

            assert_eq!(bsk, expanded_bsk);
        }
    }

    #[test]
    fn test_bsk_gen_equivalence_u32() {
        test_bsk_gen_equivalence::<u32>()
    }

    #[test]
    fn test_bsk_gen_equivalence_u64() {
        test_bsk_gen_equivalence::<u64>()
    }

    #[test]
    fn test_bsk_par_seeded_gen_equivalence_u32() {
        test_bsk_par_seeded_gen_equivalence::<u32>()
    }

    #[test]
    fn test_bsk_par_seeded_gen_equivalence_u64() {
        test_bsk_par_seeded_gen_equivalence::<u64>()
    }
}
