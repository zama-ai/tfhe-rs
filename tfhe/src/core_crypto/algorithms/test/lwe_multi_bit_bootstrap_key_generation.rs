use crate::core_crypto::algorithms::test::TestResources;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::StandardDev;
use crate::core_crypto::commons::generators::{DeterministicSeeder, EncryptionRandomGenerator};
use crate::core_crypto::commons::math::random::{
    DefaultRandomGenerator, DynamicDistribution, Seed, Uniform,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GgswCiphertextCount,
    GlweDimension, LweBskGroupingFactor, LweDimension, PolynomialSize,
};
use crate::core_crypto::commons::test_tools::new_secret_random_generator;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::CastFrom;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn test_parallel_and_seeded_multi_bit_bsk_gen_equivalence<
    T: UnsignedTorus + CastFrom<usize> + Sync + Send,
>(
    ciphertext_modulus: CiphertextModulus<T>,
) {
    for _ in 0..NB_TESTS {
        let mut lwe_dim =
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
        let grouping_factor = LweBskGroupingFactor(
            crate::core_crypto::commons::test_tools::random_usize_between(2..4),
        );
        let mask_seed = Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);
        let deterministic_seeder_seed =
            Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);

        let noise_distribution =
            DynamicDistribution::new_gaussian_from_std_dev(StandardDev::from_standard_dev(10.));

        while !lwe_dim.0.is_multiple_of(grouping_factor.0) {
            lwe_dim = LweDimension(lwe_dim.0 + 1);
        }

        let mut secret_generator = new_secret_random_generator();
        let lwe_sk =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dim, &mut secret_generator);
        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dim,
            poly_size,
            &mut secret_generator,
        );

        let mut parallel_multi_bit_bsk = LweMultiBitBootstrapKeyOwned::new(
            T::ZERO,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            lwe_dim,
            grouping_factor,
            ciphertext_modulus,
        );

        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            mask_seed,
            &mut DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed),
        );

        par_generate_lwe_multi_bit_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            &mut parallel_multi_bit_bsk,
            noise_distribution,
            &mut encryption_generator,
        );

        let mut sequential_multi_bit_bsk = LweMultiBitBootstrapKeyOwned::new(
            T::ZERO,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            lwe_dim,
            grouping_factor,
            ciphertext_modulus,
        );

        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            mask_seed,
            &mut DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed),
        );

        generate_lwe_multi_bit_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            &mut sequential_multi_bit_bsk,
            noise_distribution,
            &mut encryption_generator,
        );

        assert_eq!(parallel_multi_bit_bsk, sequential_multi_bit_bsk);

        let mut sequential_seeded_multi_bit_bsk = SeededLweMultiBitBootstrapKey::new(
            T::ZERO,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            lwe_dim,
            grouping_factor,
            mask_seed.into(),
            ciphertext_modulus,
        );

        generate_seeded_lwe_multi_bit_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            &mut sequential_seeded_multi_bit_bsk,
            noise_distribution,
            &mut DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed),
        );

        let mut parallel_seeded_multi_bit_bsk = SeededLweMultiBitBootstrapKey::new(
            T::ZERO,
            glwe_dim.to_glwe_size(),
            poly_size,
            base_log,
            level,
            lwe_dim,
            grouping_factor,
            mask_seed.into(),
            ciphertext_modulus,
        );

        par_generate_seeded_lwe_multi_bit_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            &mut parallel_seeded_multi_bit_bsk,
            noise_distribution,
            &mut DeterministicSeeder::<DefaultRandomGenerator>::new(deterministic_seeder_seed),
        );

        assert_eq!(
            sequential_seeded_multi_bit_bsk,
            parallel_seeded_multi_bit_bsk
        );

        let ser_decompressed_multi_bit_bsk =
            sequential_seeded_multi_bit_bsk.decompress_into_lwe_multi_bit_bootstrap_key();

        assert_eq!(ser_decompressed_multi_bit_bsk, sequential_multi_bit_bsk);

        let par_decompressed_multi_bit_bsk =
            parallel_seeded_multi_bit_bsk.par_decompress_into_lwe_multi_bit_bootstrap_key();

        assert_eq!(
            ser_decompressed_multi_bit_bsk,
            par_decompressed_multi_bit_bsk
        );
    }
}

#[test]
fn test_parallel_and_seeded_multi_bit_bsk_gen_equivalence_u32_native_mod() {
    test_parallel_and_seeded_multi_bit_bsk_gen_equivalence::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_parallel_and_seeded_multi_bit_bsk_gen_equivalence_u32_custom_mod() {
    test_parallel_and_seeded_multi_bit_bsk_gen_equivalence::<u32>(
        CiphertextModulus::try_new_power_of_2(31).unwrap(),
    );
}

#[test]
fn test_parallel_and_seeded_multi_bit_bsk_gen_equivalence_u64_native_mod() {
    test_parallel_and_seeded_multi_bit_bsk_gen_equivalence::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_parallel_and_seeded_multi_bit_bsk_gen_equivalence_u64_custom_mod() {
    test_parallel_and_seeded_multi_bit_bsk_gen_equivalence::<u64>(
        CiphertextModulus::try_new_power_of_2(63).unwrap(),
    );
}

/// Verify that a generator forked for one LWE key-bit group via
/// [`lwe_multi_bit_bootstrap_key_fork_config`] is fully exhausted after the key generation call.
///
/// Uses `LweDimension(600)` and a random `LweBskGroupingFactor` so the fork produces
/// `input_lwe_dimension / grouping_factor` children (one per key-bit group); each child is passed
/// to [`encrypt_lwe_multi_bit_ggsw_group`], which directly consumes one key-bit group's
/// randomness.
///
/// Uses a TUniform noise distribution which has `single_sample_success_probability == 1.0`,
/// making byte consumption deterministic and exhaustion guaranteed.
#[test]
fn lwe_multi_bit_bootstrap_key_fork_config_exhaustion() {
    let glwe_noise_distribution = DynamicDistribution::new_t_uniform(30);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(512);
    let decomp_base_log = DecompositionBaseLog(8);
    let decomp_level_count = DecompositionLevelCount(2);
    let grouping_factor =
        LweBskGroupingFactor(crate::core_crypto::commons::test_tools::random_usize_between(2..5));
    let input_lwe_dimension = LweDimension(10 * grouping_factor.0);

    println!(
        "grouping_factor = {}, input_lwe_dimension = {}",
        grouping_factor.0, input_lwe_dimension.0
    );

    let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element();

    let mut secret_generator = new_secret_random_generator();

    let input_lwe_secret_key =
        allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);

    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut secret_generator,
    );

    let mut rsc = TestResources::new();

    let glwe_size = glwe_dimension.to_glwe_size();

    let mut ggsw_group = GgswCiphertextList::new(
        0u64,
        glwe_size,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        GgswCiphertextCount(ggsw_per_multi_bit_element.0),
        ciphertext_modulus,
    );

    let fork_config = lwe_multi_bit_bootstrap_key_fork_config(
        input_lwe_dimension,
        glwe_size,
        polynomial_size,
        decomp_level_count,
        grouping_factor,
        Uniform,
        glwe_noise_distribution,
        ciphertext_modulus,
    );

    let input_key_elements = input_lwe_secret_key.as_ref();
    let children_iterator = rsc
        .encryption_random_generator
        .try_fork_from_config(fork_config)
        .expect("Failed to fork generator");

    for (child_index, (mut child, key_chunk)) in children_iterator
        .zip(input_key_elements.chunks_exact(grouping_factor.0))
        .enumerate()
    {
        encrypt_lwe_multi_bit_ggsw_group(
            &output_glwe_secret_key,
            &mut ggsw_group,
            key_chunk,
            glwe_noise_distribution,
            &mut child,
        );

        assert_eq!(
            child.remaining_bytes(),
            Some(0),
            "Child {child_index}: mask generator should be exhausted after multi-bit BSK generation"
        );
        assert_eq!(
            child.noise_generator_mut().remaining_bytes(),
            Some(0),
            "Child {child_index}: noise generator should be exhausted after multi-bit BSK generation"
        );
    }
}
