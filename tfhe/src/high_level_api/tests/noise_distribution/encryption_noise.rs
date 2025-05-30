use shortint::parameters::test_params::{
    TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use shortint::parameters::{
    AtomicPatternParameters, CompactPublicKeyEncryptionParameters, ShortintKeySwitchingParameters,
};
use shortint::ClassicPBSParameters;

use crate::core_crypto::algorithms::lwe_encryption::decrypt_lwe_ciphertext;
use crate::core_crypto::algorithms::test::noise_distribution::lwe_encryption_noise::lwe_compact_public_key_encryption_expected_variance;
use crate::core_crypto::commons::math::random::DynamicDistribution;
use crate::core_crypto::commons::test_tools::{variance, variance_confidence_interval};
use crate::prelude::*;
use crate::shortint::parameters::compact_public_key_only::CompactCiphertextListExpansionKind;
use crate::*;

use rayon::prelude::*;

#[test]
fn test_noise_check_secret_key_encryption_noise_tuniform() {
    let params: AtomicPatternParameters = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

    let modulus_as_f64 = if params.ciphertext_modulus().is_native_modulus() {
        2.0f64.powi(u64::BITS as i32)
    } else {
        params.ciphertext_modulus().get_custom_modulus() as f64
    };

    let encryption_noise = params.encryption_noise_distribution();

    let (inclusive_min_val, inclusive_max_val, expected_variance) = match encryption_noise {
        DynamicDistribution::Gaussian(_gaussian) => {
            panic!("This test is written for TUniform, wrong parameter set used")
        }
        DynamicDistribution::TUniform(tuniform) => (
            tuniform.min_value_inclusive(),
            tuniform.max_value_inclusive(),
            tuniform.variance(modulus_as_f64),
        ),
    };

    let config = ConfigBuilder::with_custom_parameters(params).build();

    // Limit seems to be 775030 to have results despite f64 approximations
    const NB_TEST: usize = 500_000;

    let noise_samples: Vec<_> = (0..NB_TEST)
        .into_par_iter()
        .map(|_| {
            let cks = ClientKey::generate(config);
            let encrypted = FheUint2::encrypt(0u32, &cks);

            // Drop to lower level APIs to get to the noise
            let integer_key = cks.into_raw_parts().0;
            let shortint_key: &crate::shortint::ClientKey = integer_key.as_ref();

            let radix = encrypted.into_raw_parts().0;
            assert!(radix.blocks.len() == 1);
            let shortint_block = radix.blocks.into_iter().next().unwrap();

            let noise = shortint_key.decrypt_no_decode(&shortint_block);
            let signed_noise: i64 = noise.0 as i64;

            assert!(
                signed_noise >= inclusive_min_val,
                "{signed_noise} is not >= {inclusive_min_val}"
            );

            assert!(
                signed_noise <= inclusive_max_val,
                "{signed_noise} is not <= {inclusive_max_val}"
            );

            // Rescale
            signed_noise as f64 / modulus_as_f64
        })
        .collect();

    let measured_variance = variance(&noise_samples);
    let measured_confidence_interval =
        variance_confidence_interval(noise_samples.len() as f64, measured_variance, 0.99);

    // For --no-capture inspection
    println!("measured_variance={measured_variance:?}");
    println!("expected_variance={expected_variance:?}");
    println!(
        "lower_bound={:?}",
        measured_confidence_interval.lower_bound()
    );
    println!(
        "upper_bound={:?}",
        measured_confidence_interval.upper_bound()
    );

    assert!(measured_confidence_interval.variance_is_in_interval(expected_variance));
}

#[test]
fn test_noise_check_compact_public_key_to_small_encryption_noise_tuniform() {
    noise_check_compact_public_key_encryption_noise_tuniform(
        TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_compact_public_key_to_big_encryption_noise_tuniform() {
    noise_check_compact_public_key_encryption_noise_tuniform(
        TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn noise_check_compact_public_key_encryption_noise_tuniform(
    mut cpke_params: CompactPublicKeyEncryptionParameters,
    ksk_params: ShortintKeySwitchingParameters,
    block_params: ClassicPBSParameters,
) {
    // Hack to avoid server key needs and get the ciphertext directly
    cpke_params.expansion_kind =
        CompactCiphertextListExpansionKind::NoCasting(block_params.encryption_key_choice.into());

    let modulus_as_f64 = if cpke_params.ciphertext_modulus.is_native_modulus() {
        2.0f64.powi(u64::BITS as i32)
    } else {
        cpke_params.ciphertext_modulus.get_custom_modulus() as f64
    };

    let encryption_noise = cpke_params.encryption_noise_distribution;
    let encryption_variance = match encryption_noise {
        DynamicDistribution::Gaussian(_gaussian) => {
            panic!("This test is written for TUniform, wrong parameter set used")
        }
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(modulus_as_f64),
    };

    let expected_variance = lwe_compact_public_key_encryption_expected_variance(
        encryption_variance,
        cpke_params.encryption_lwe_dimension,
    );

    let config = ConfigBuilder::with_custom_parameters(block_params)
        .use_dedicated_compact_public_key_parameters((cpke_params, ksk_params))
        .build();

    // Limit seems to be 775030 to have results despite f64 approximations
    const NB_TEST: usize = 500_000;

    let thread_pools: Vec<_> = (0..rayon::current_num_threads())
        .map(|_| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .unwrap()
        })
        .collect();

    let pool_count = thread_pools.len();

    let noise_samples: Vec<_> = thread_pools
        .into_par_iter()
        .flat_map(|pool| {
            pool.install(|| {
                (0..NB_TEST.div_ceil(pool_count))
                    .map(|_| {
                        let cks = ClientKey::generate(config);
                        let cpk = CompactPublicKey::new(&cks);

                        let mut builder = CompactCiphertextList::builder(&cpk);
                        builder
                            .push_with_num_bits(
                                0u32,
                                cpke_params.message_modulus.0.ilog2() as usize,
                            )
                            .unwrap();
                        let list = builder.build();
                        let expanded = list.expand().unwrap();
                        let encrypted: FheUint2 = expanded.get(0).unwrap().unwrap();

                        // Drop to lower level APIs to get to the noise
                        let integer_key = cks.into_raw_parts().1.unwrap().0;
                        let shortint_key = integer_key.into_raw_parts();
                        let core_key = shortint_key.into_raw_parts().0;

                        let radix = encrypted.into_raw_parts().0;
                        assert!(radix.blocks.len() == 1);
                        let shortint_block = radix.blocks.into_iter().next().unwrap();
                        let lwe_ct = shortint_block.ct;

                        // This is directly the noise as we encrypted a 0
                        let noise = decrypt_lwe_ciphertext(&core_key, &lwe_ct).0;
                        let signed_noise: i64 = noise as i64;

                        // Rescale
                        signed_noise as f64 / modulus_as_f64
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();

    let measured_variance = variance(&noise_samples);
    let measured_confidence_interval =
        variance_confidence_interval(noise_samples.len() as f64, measured_variance, 0.99);

    // For --no-capture inspection
    println!("measured_variance={measured_variance:?}");
    println!("expected_variance={expected_variance:?}");
    println!(
        "lower_bound={:?}",
        measured_confidence_interval.lower_bound()
    );
    println!(
        "upper_bound={:?}",
        measured_confidence_interval.upper_bound()
    );

    assert!(measured_confidence_interval.variance_is_in_interval(expected_variance));
}
