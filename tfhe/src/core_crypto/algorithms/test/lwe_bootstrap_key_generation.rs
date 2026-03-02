use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::StandardDev;
use crate::core_crypto::commons::generators::{DeterministicSeeder, EncryptionRandomGenerator};
use crate::core_crypto::commons::math::random::{
    CompressionSeed, DefaultRandomGenerator, DynamicDistribution, Seed,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    ChunkSize, CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GlweDimension,
    LweDimension, PolynomialSize,
};
use crate::core_crypto::commons::test_tools::new_secret_random_generator;
use crate::core_crypto::entities::*;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn test_parallel_and_seeded_and_chunked_bsk_gen_equivalence<T: UnsignedTorus + Sync + Send>(
    ciphertext_modulus: CiphertextModulus<T>,
) {
    for _ in 0..NB_TESTS {
        let lwe_dim =
            LweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
        let glwe_dim =
            GlweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
        let poly_size =
            PolynomialSize(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
        let level = DecompositionLevelCount(
            crate::core_crypto::commons::test_tools::random_usize_between(2..5),
        );
        let base_log = DecompositionBaseLog(
            crate::core_crypto::commons::test_tools::random_usize_between(2..5),
        );
        let mask_seed = Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);
        let deterministic_seeder_seed =
            Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);

        let noise_distribution =
            DynamicDistribution::new_gaussian_from_std_dev(StandardDev::from_standard_dev(10.));

        let mut secret_generator = new_secret_random_generator();
        let lwe_sk =
            allocate_and_generate_new_binary_lwe_secret_key::<T, _>(lwe_dim, &mut secret_generator);
        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dim,
            poly_size,
            &mut secret_generator,
        );

        let mut parallel_bsk = LweBootstrapKeyOwned::new(
            T::ZERO,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            lwe_dim,
            ciphertext_modulus,
        );

        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            mask_seed,
            &mut DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed),
        );

        par_generate_lwe_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            &mut parallel_bsk,
            noise_distribution,
            &mut encryption_generator,
        );

        let mut sequential_bsk = LweBootstrapKeyOwned::new(
            T::ZERO,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            lwe_dim,
            ciphertext_modulus,
        );

        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            mask_seed,
            &mut DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed),
        );

        generate_lwe_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            &mut sequential_bsk,
            noise_distribution,
            &mut encryption_generator,
        );

        assert_eq!(parallel_bsk, sequential_bsk);

        let mut sequential_seeded_bsk = SeededLweBootstrapKey::new(
            T::ZERO,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            lwe_dim,
            mask_seed.into(),
            ciphertext_modulus,
        );

        generate_seeded_lwe_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            &mut sequential_seeded_bsk,
            noise_distribution,
            &mut DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed),
        );

        let mut parallel_seeded_bsk = SeededLweBootstrapKey::new(
            T::ZERO,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            lwe_dim,
            mask_seed.into(),
            ciphertext_modulus,
        );

        par_generate_seeded_lwe_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            &mut parallel_seeded_bsk,
            noise_distribution,
            &mut DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed),
        );

        assert_eq!(sequential_seeded_bsk, parallel_seeded_bsk);

        let ser_decompressed_bsk = sequential_seeded_bsk
            .as_view()
            .decompress_into_lwe_bootstrap_key();

        assert_eq!(ser_decompressed_bsk, sequential_bsk);

        let par_decompressed_bsk = parallel_seeded_bsk.par_decompress_into_lwe_bootstrap_key();

        assert_eq!(ser_decompressed_bsk, par_decompressed_bsk);

        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            mask_seed,
            &mut DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed),
        );

        let chunk_generator = LweBootstrapKeyChunkGenerator::new(
            &mut encryption_generator,
            ChunkSize(crate::core_crypto::commons::test_tools::random_usize_between(1..5)),
            lwe_dim,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            ciphertext_modulus,
            &lwe_sk,
            &glwe_sk,
            noise_distribution,
            false,
        );

        let chunks = chunk_generator.collect::<Vec<_>>();
        let assembled_bsk = allocate_and_assemble_lwe_bootstrap_key_from_chunks(chunks.as_slice());
        assert_eq!(assembled_bsk, sequential_bsk);

        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            mask_seed,
            &mut DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed),
        );

        let par_chunk_generator = LweBootstrapKeyChunkGenerator::new(
            &mut encryption_generator,
            ChunkSize(crate::core_crypto::commons::test_tools::random_usize_between(1..5)),
            lwe_dim,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            ciphertext_modulus,
            &lwe_sk,
            &glwe_sk,
            noise_distribution,
            true,
        );
        let chunks = par_chunk_generator.collect::<Vec<_>>();
        let assembled_bsk = allocate_and_assemble_lwe_bootstrap_key_from_chunks(chunks.as_slice());
        assert_eq!(assembled_bsk, sequential_bsk);

        let mut noise_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed);
        let compression_seed = CompressionSeed::from(mask_seed);
        let seeded_chunk_generator = SeededLweBootstrapKeyChunkGenerator::new(
            ChunkSize(crate::core_crypto::commons::test_tools::random_usize_between(1..5)),
            lwe_dim,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            ciphertext_modulus,
            &lwe_sk,
            &glwe_sk,
            noise_distribution,
            compression_seed.clone(),
            &mut noise_seeder,
            false,
        );

        let seeded_chunks = seeded_chunk_generator.collect::<Vec<_>>();
        let assembled_seeded_bsk =
            allocate_and_assemble_seeded_lwe_bootstrap_key_from_chunks(seeded_chunks.as_slice());
        assert_eq!(assembled_seeded_bsk, sequential_seeded_bsk);
        assert_eq!(
            assembled_seeded_bsk.decompress_into_lwe_bootstrap_key(),
            sequential_bsk
        );

        let mut noise_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed);
        let par_seeded_chunk_generator = SeededLweBootstrapKeyChunkGenerator::new(
            ChunkSize(crate::core_crypto::commons::test_tools::random_usize_between(1..5)),
            lwe_dim,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            ciphertext_modulus,
            &lwe_sk,
            &glwe_sk,
            noise_distribution,
            compression_seed,
            &mut noise_seeder,
            true,
        );

        let seeded_chunks = par_seeded_chunk_generator.collect::<Vec<_>>();
        let assembled_seeded_bsk =
            allocate_and_assemble_seeded_lwe_bootstrap_key_from_chunks(seeded_chunks.as_slice());
        assert_eq!(assembled_seeded_bsk, sequential_seeded_bsk);
        assert_eq!(
            assembled_seeded_bsk.decompress_into_lwe_bootstrap_key(),
            sequential_bsk
        );
    }
}

#[test]
fn test_parallel_and_seeded_and_chunked_bsk_gen_equivalence_u32_native_mod() {
    test_parallel_and_seeded_and_chunked_bsk_gen_equivalence::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_parallel_and_seeded_and_chunked_bsk_gen_equivalence_u32_custom_mod() {
    test_parallel_and_seeded_and_chunked_bsk_gen_equivalence::<u32>(
        CiphertextModulus::try_new_power_of_2(31).unwrap(),
    );
}

#[test]
fn test_parallel_and_seeded_and_chunked_bsk_gen_equivalence_u64_native_mod() {
    test_parallel_and_seeded_and_chunked_bsk_gen_equivalence::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_parallel_and_seeded_and_chunked_bsk_gen_equivalence_u64_custom_mod() {
    test_parallel_and_seeded_and_chunked_bsk_gen_equivalence::<u64>(
        CiphertextModulus::try_new_power_of_2(63).unwrap(),
    );
}
