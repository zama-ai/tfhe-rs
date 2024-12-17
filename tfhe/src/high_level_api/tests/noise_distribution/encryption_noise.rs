use crate::core_crypto::algorithms::lwe_encryption::decrypt_lwe_ciphertext;
use crate::core_crypto::algorithms::test::noise_distribution::lwe_encryption_noise::lwe_compact_public_key_encryption_expected_variance;
use crate::core_crypto::commons::math::random::DynamicDistribution;
use crate::core_crypto::commons::test_tools::{variance, variance_confidence_interval};
use crate::prelude::*;
use crate::shortint::parameters::classic::tuniform::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::parameters::compact_public_key_only::CompactCiphertextListExpansionKind;
use crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::parameters::ShortintParameterSet;
use crate::*;

#[test]
fn test_noise_check_secret_key_encryption_noise_tuniform() {
    let params_as_shortint_parameter_set = ShortintParameterSet::new_pbs_param_set(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64.into(),
    );

    let modulus_as_f64 = if params_as_shortint_parameter_set
        .ciphertext_modulus()
        .is_native_modulus()
    {
        2.0f64.powi(u64::BITS as i32)
    } else {
        params_as_shortint_parameter_set
            .ciphertext_modulus()
            .get_custom_modulus() as f64
    };

    let encryption_noise = params_as_shortint_parameter_set.encryption_noise_distribution();
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

    let expected_encryption_noise = match params_as_shortint_parameter_set.encryption_key_choice() {
        shortint::EncryptionKeyChoice::Big => {
            params_as_shortint_parameter_set.glwe_noise_distribution()
        }
        shortint::EncryptionKeyChoice::Small => {
            params_as_shortint_parameter_set.lwe_noise_distribution()
        }
    };

    assert_eq!(encryption_noise, expected_encryption_noise);

    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64).build();

    const NB_TEST: usize = 16000;

    let mut noise_samples = Vec::with_capacity(NB_TEST);
    for _ in 0..NB_TEST {
        let cks = ClientKey::generate(config);
        let encrypted = FheUint2::encrypt(0u32, &cks);

        // Drop to lower level APIs to get to the noise
        let integer_key = cks.into_raw_parts().0;
        let shortint_key: &crate::shortint::ClientKey = integer_key.as_ref();

        let radix = encrypted.into_raw_parts().0;
        assert!(radix.blocks.len() == 1);
        let shortint_block = radix.blocks.into_iter().next().unwrap();

        let noise = shortint_key.decrypt_no_decode(&shortint_block);
        let signed_noise: i64 = noise as i64;

        assert!(
            signed_noise >= inclusive_min_val,
            "{signed_noise} is not >= {inclusive_min_val}"
        );

        assert!(
            signed_noise <= inclusive_max_val,
            "{signed_noise} is not <= {inclusive_max_val}"
        );

        // Rescale
        noise_samples.push(signed_noise as f64 / modulus_as_f64);
    }

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
fn test_noise_check_compact_public_key_encryption_noise_tuniform() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let mut cpk_params = V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    // Hack to avoid server key needs and get the ciphertext directly
    cpk_params.expansion_kind =
        CompactCiphertextListExpansionKind::NoCasting(block_params.encryption_key_choice.into());
    let ksk_params = V0_11_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

    let modulus_as_f64 = if cpk_params.ciphertext_modulus.is_native_modulus() {
        2.0f64.powi(u64::BITS as i32)
    } else {
        cpk_params.ciphertext_modulus.get_custom_modulus() as f64
    };

    let encryption_noise = cpk_params.encryption_noise_distribution;
    let encryption_variance = match encryption_noise {
        DynamicDistribution::Gaussian(_gaussian) => {
            panic!("This test is written for TUniform, wrong parameter set used")
        }
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(modulus_as_f64),
    };

    let expected_variance = lwe_compact_public_key_encryption_expected_variance(
        encryption_variance,
        cpk_params.encryption_lwe_dimension,
    );

    let config = ConfigBuilder::with_custom_parameters(block_params)
        .use_dedicated_compact_public_key_parameters((cpk_params, ksk_params))
        .build();

    const NB_TEST: usize = 16000;

    let mut noise_samples = Vec::with_capacity(NB_TEST);
    for _ in 0..NB_TEST {
        let cks = ClientKey::generate(config);
        let cpk = CompactPublicKey::new(&cks);

        let mut builder = CompactCiphertextList::builder(&cpk);
        builder
            .push_with_num_bits(0u32, cpk_params.message_modulus.0.ilog2() as usize)
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
        noise_samples.push(signed_noise as f64 / modulus_as_f64);
    }

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
