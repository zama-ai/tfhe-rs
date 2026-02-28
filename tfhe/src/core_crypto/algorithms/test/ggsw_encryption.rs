use super::*;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::commons::test_tools;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn test_parallel_and_seeded_ggsw_encryption_equivalence<Scalar>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) where
    Scalar: UnsignedTorus + Sync + Send,
{
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for GgswCiphertext creation
    let glwe_size = GlweSize(2);
    let polynomial_size = PolynomialSize(1024);
    let decomp_base_log = DecompositionBaseLog(8);
    let decomp_level_count = DecompositionLevelCount(3);
    let glwe_noise_distribution = DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    ));

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let main_seed = seeder.seed();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    for _ in 0..NB_TESTS {
        // Create the GlweSecretKey
        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_size.to_glwe_dimension(),
            polynomial_size,
            &mut secret_generator,
        );

        // Create the cleartext
        let encoded_msg: Scalar = test_tools::random_uint_between(Scalar::ZERO..Scalar::TWO.shl(2));
        let cleartext = Cleartext(encoded_msg);

        let compression_seed: CompressionSeed = seeder.seed().into();

        let mut ser_ggsw = GgswCiphertext::new(
            Scalar::ZERO,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(main_seed);

        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            compression_seed.clone(),
            &mut deterministic_seeder,
        );

        encrypt_constant_ggsw_ciphertext(
            &glwe_secret_key,
            &mut ser_ggsw,
            cleartext,
            glwe_noise_distribution,
            &mut encryption_generator,
        );

        let mut par_ggsw = GgswCiphertext::new(
            Scalar::ZERO,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(main_seed);

        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            compression_seed.clone(),
            &mut deterministic_seeder,
        );

        par_encrypt_constant_ggsw_ciphertext(
            &glwe_secret_key,
            &mut par_ggsw,
            cleartext,
            glwe_noise_distribution,
            &mut encryption_generator,
        );

        assert_eq!(ser_ggsw, par_ggsw);

        // Create a new GgswCiphertext
        let mut ser_seeded_ggsw = SeededGgswCiphertext::new(
            Scalar::ZERO,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            compression_seed.clone(),
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(main_seed);

        encrypt_constant_seeded_ggsw_ciphertext(
            &glwe_secret_key,
            &mut ser_seeded_ggsw,
            cleartext,
            glwe_noise_distribution,
            &mut deterministic_seeder,
        );

        let mut par_seeded_ggsw = SeededGgswCiphertext::new(
            Scalar::ZERO,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            compression_seed,
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(main_seed);

        par_encrypt_constant_seeded_ggsw_ciphertext(
            &glwe_secret_key,
            &mut par_seeded_ggsw,
            cleartext,
            glwe_noise_distribution,
            &mut deterministic_seeder,
        );

        assert_eq!(ser_seeded_ggsw, par_seeded_ggsw);

        let ser_decompressed_ggsw = ser_seeded_ggsw.decompress_into_ggsw_ciphertext();

        assert_eq!(ser_ggsw, ser_decompressed_ggsw);

        let par_decompressed_ggsw = par_seeded_ggsw.par_decompress_into_ggsw_ciphertext();

        assert_eq!(ser_decompressed_ggsw, par_decompressed_ggsw);
    }
}

#[test]
fn test_parallel_and_seeded_ggsw_encryption_equivalence_u32_native_mod() {
    test_parallel_and_seeded_ggsw_encryption_equivalence::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_parallel_and_seeded_ggsw_encryption_equivalence_u32_custom_mod() {
    test_parallel_and_seeded_ggsw_encryption_equivalence::<u32>(
        CiphertextModulus::try_new_power_of_2(31).unwrap(),
    );
}

#[test]
fn test_parallel_and_seeded_ggsw_encryption_equivalence_u64_native_mod() {
    test_parallel_and_seeded_ggsw_encryption_equivalence::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_parallel_and_seeded_ggsw_encryption_equivalence_u64_custom_mod() {
    test_parallel_and_seeded_ggsw_encryption_equivalence::<u64>(
        CiphertextModulus::try_new_power_of_2(63).unwrap(),
    );
}

fn ggsw_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let decomposition_base_log = params.pbs_base_log;
    let decomposition_level_count = params.pbs_level;

    let mut rsc = TestResources::new();

    let mut msg = Scalar::ONE << decomposition_base_log.0;

    while msg != Scalar::ZERO {
        // We are going to go faster if the base log is big
        if msg > (Scalar::ONE << 4) {
            msg /= Scalar::TWO;
        } else {
            // Then we can scan all values
            msg = msg.wrapping_sub(Scalar::ONE);
        }
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut ggsw = GgswCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
                ciphertext_modulus,
            );

            // GGSW constants are seen as cleartext, the encoding is done by the encryption itself
            let cleartext = Cleartext(msg);

            encrypt_constant_ggsw_ciphertext(
                &glwe_sk,
                &mut ggsw,
                cleartext,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ggsw,
                ciphertext_modulus
            ));

            let decoded = decrypt_constant_ggsw_ciphertext(&glwe_sk, &ggsw);

            assert_eq!(decoded.0, msg);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(ggsw_encrypt_decrypt_custom_mod);

fn ggsw_par_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus + Send + Sync>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let decomposition_base_log = params.pbs_base_log;
    let decomposition_level_count = params.pbs_level;

    let mut rsc = TestResources::new();

    let mut msg = Scalar::ONE << decomposition_base_log.0;

    while msg != Scalar::ZERO {
        // We are going to go faster if the base log is big
        if msg > (Scalar::ONE << 4) {
            msg /= Scalar::TWO;
        } else {
            // Then we can scan all values
            msg = msg.wrapping_sub(Scalar::ONE);
        }
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut ggsw = GgswCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
                ciphertext_modulus,
            );

            // GGSW constants are seen as cleartext, the encoding is done by the encryption itself
            let cleartext = Cleartext(msg);

            par_encrypt_constant_ggsw_ciphertext(
                &glwe_sk,
                &mut ggsw,
                cleartext,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ggsw,
                ciphertext_modulus
            ));

            let decoded = decrypt_constant_ggsw_ciphertext(&glwe_sk, &ggsw);

            assert_eq!(decoded.0, msg);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(ggsw_par_encrypt_decrypt_custom_mod);

fn ggsw_seeded_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let decomposition_base_log = params.pbs_base_log;
    let decomposition_level_count = params.pbs_level;

    let mut rsc = TestResources::new();

    let mut msg = Scalar::ONE << decomposition_base_log.0;

    while msg != Scalar::ZERO {
        // We are going to go faster if the base log is big
        if msg > (Scalar::ONE << 4) {
            msg /= Scalar::TWO;
        } else {
            // Then we can scan all values
            msg = msg.wrapping_sub(Scalar::ONE);
        }
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut seeded_ggsw = SeededGgswCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
                rsc.seeder.seed().into(),
                ciphertext_modulus,
            );

            // GGSW constants are seen as cleartext, the encoding is done by the encryption itself
            let cleartext = Cleartext(msg);

            encrypt_constant_seeded_ggsw_ciphertext(
                &glwe_sk,
                &mut seeded_ggsw,
                cleartext,
                glwe_noise_distribution,
                rsc.seeder.as_mut(),
            );

            let ggsw = seeded_ggsw.decompress_into_ggsw_ciphertext();

            assert!(check_encrypted_content_respects_mod(
                &ggsw,
                ciphertext_modulus
            ));

            let decoded = decrypt_constant_ggsw_ciphertext(&glwe_sk, &ggsw);

            assert_eq!(decoded.0, msg);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(ggsw_seeded_encrypt_decrypt_custom_mod);

fn ggsw_seeded_par_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus + Sync + Send>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let decomposition_base_log = params.pbs_base_log;
    let decomposition_level_count = params.pbs_level;

    let mut rsc = TestResources::new();

    let mut msg = Scalar::ONE << decomposition_base_log.0;

    while msg != Scalar::ZERO {
        // We are going to go faster if the base log is big
        if msg > (Scalar::ONE << 4) {
            msg /= Scalar::TWO;
        } else {
            // Then we can scan all values
            msg = msg.wrapping_sub(Scalar::ONE);
        }
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut seeded_ggsw = SeededGgswCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
                rsc.seeder.seed().into(),
                ciphertext_modulus,
            );

            // GGSW constants are seen as cleartext, the encoding is done by the encryption itself
            let cleartext = Cleartext(msg);

            par_encrypt_constant_seeded_ggsw_ciphertext(
                &glwe_sk,
                &mut seeded_ggsw,
                cleartext,
                glwe_noise_distribution,
                rsc.seeder.as_mut(),
            );

            let ggsw = seeded_ggsw.decompress_into_ggsw_ciphertext();

            assert!(check_encrypted_content_respects_mod(
                &ggsw,
                ciphertext_modulus
            ));

            let decoded = decrypt_constant_ggsw_ciphertext(&glwe_sk, &ggsw);

            assert_eq!(decoded.0, msg);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(ggsw_seeded_par_encrypt_decrypt_custom_mod);
