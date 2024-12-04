use crate::core_crypto::commons::math::random::DynamicDistribution;
use crate::core_crypto::commons::test_tools::{variance, variance_confidence_interval};
use crate::prelude::*;
use crate::shortint::parameters::classic::tuniform::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::parameters::ShortintParameterSet;
use crate::*;

#[test]
fn test_noise_check_encryption_noise_tuniform() {
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
