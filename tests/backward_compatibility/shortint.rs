use std::path::Path;
use tfhe::core_crypto::prelude::{
    LweCiphertextCount, NoiseEstimationMeasureBound, RSigmaFactor, TUniform, Variance,
};
use tfhe::shortint::parameters::ModulusSwitchNoiseReductionParams;
use tfhe_backward_compat_data::load::{
    load_versioned_auxiliary, DataFormat, TestFailure, TestResult, TestSuccess,
};
use tfhe_backward_compat_data::{
    ShortintCiphertextTest, ShortintClientKeyTest, TestDistribution, TestMetadata,
    TestModulusSwitchNoiseReductionParams, TestParameterSet, TestType, Testcase,
};

use tfhe::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize, StandardDev,
};
use tfhe::shortint::{
    CarryModulus, Ciphertext, CiphertextModulus, ClassicPBSParameters, ClientKey,
    EncryptionKeyChoice, MaxNoiseLevel, MessageModulus, PBSParameters, ShortintParameterSet,
};
use tfhe_versionable::Unversionize;

use crate::{load_and_unversionize, TestedModule};

/// Converts test parameters metadata that are independent of any tfhe-rs version and use only
/// built-in types into parameters suitable for the currently tested version.
pub fn load_params(test_params: &TestParameterSet) -> ClassicPBSParameters {
    let TestParameterSet {
        lwe_dimension,
        glwe_dimension,
        polynomial_size,
        lwe_noise_distribution,
        glwe_noise_distribution,
        pbs_base_log,
        pbs_level,
        ks_base_log,
        ks_level,
        message_modulus,
        ciphertext_modulus,
        carry_modulus,
        max_noise_level,
        log2_p_fail,
        encryption_key_choice,
        modulus_switch_noise_reduction_params,
    } = test_params;

    let modulus_switch_noise_reduction_params = modulus_switch_noise_reduction_params.as_ref().map(
        |TestModulusSwitchNoiseReductionParams {
             modulus_switch_zeros_count,
             ms_bound,
             ms_r_sigma_factor,
             ms_input_variance,
         }| {
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(*modulus_switch_zeros_count),
                ms_bound: NoiseEstimationMeasureBound(*ms_bound),
                ms_r_sigma_factor: RSigmaFactor(*ms_r_sigma_factor),
                ms_input_variance: Variance(*ms_input_variance),
            }
        },
    );

    ClassicPBSParameters {
        lwe_dimension: LweDimension(*lwe_dimension),
        glwe_dimension: GlweDimension(*glwe_dimension),
        polynomial_size: PolynomialSize(*polynomial_size),
        lwe_noise_distribution: convert_distribution(lwe_noise_distribution),
        glwe_noise_distribution: convert_distribution(glwe_noise_distribution),
        pbs_base_log: DecompositionBaseLog(*pbs_base_log),
        pbs_level: DecompositionLevelCount(*pbs_level),
        ks_base_log: DecompositionBaseLog(*ks_base_log),
        ks_level: DecompositionLevelCount(*ks_level),
        message_modulus: MessageModulus(*message_modulus as u64),
        carry_modulus: CarryModulus(*carry_modulus as u64),
        max_noise_level: MaxNoiseLevel::new(*max_noise_level as u64),
        log2_p_fail: *log2_p_fail,
        ciphertext_modulus: CiphertextModulus::try_new(*ciphertext_modulus).unwrap(),
        encryption_key_choice: {
            match encryption_key_choice.as_ref() {
                "big" => EncryptionKeyChoice::Big,
                "small" => EncryptionKeyChoice::Small,
                _ => panic!("Invalid encryption key choice"),
            }
        },
        modulus_switch_noise_reduction_params,
    }
}

fn convert_distribution(value: &TestDistribution) -> DynamicDistribution<u64> {
    match value {
        TestDistribution::Gaussian { stddev } => {
            DynamicDistribution::new_gaussian_from_std_dev(StandardDev(*stddev))
        }
        TestDistribution::TUniform { bound_log2 } => {
            DynamicDistribution::TUniform(TUniform::new(*bound_log2))
        }
    }
}

fn load_shortint_params(test_params: &TestParameterSet) -> ShortintParameterSet {
    ShortintParameterSet::new_pbs_param_set(PBSParameters::PBS(load_params(test_params)))
}

pub fn test_shortint_ciphertext(
    dir: &Path,
    test: &ShortintCiphertextTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let key_file = dir.join(&*test.key_filename);
    let key = ClientKey::unversionize(
        load_versioned_auxiliary(key_file).map_err(|e| test.failure(e, format))?,
    )
    .map_err(|e| test.failure(e, format))?;

    let ct: Ciphertext = load_and_unversionize(dir, test, format)?;

    let clear = key.decrypt(&ct);
    if clear != test.clear_value {
        Err(test.failure(
            format!(
                "Invalid {} decrypted cleartext:\n Expected :\n{:?}\nGot:\n{:?}",
                format, clear, test.clear_value
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

pub fn test_shortint_clientkey(
    dir: &Path,
    test: &ShortintClientKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let test_params = load_shortint_params(&test.parameters);

    let key: ClientKey = load_and_unversionize(dir, test, format)?;

    if test_params != key.parameters {
        Err(test.failure(
            format!(
                "Invalid {} parameters:\n Expected :\n{:?}\nGot:\n{:?}",
                format, test_params, key.parameters
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

pub struct Shortint;

impl TestedModule for Shortint {
    const METADATA_FILE: &'static str = "shortint.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase,
        format: DataFormat,
    ) -> TestResult {
        #[allow(unreachable_patterns)]
        match &testcase.metadata {
            TestMetadata::ShortintCiphertext(test) => {
                test_shortint_ciphertext(test_dir.as_ref(), test, format).into()
            }
            TestMetadata::ShortintClientKey(test) => {
                test_shortint_clientkey(test_dir.as_ref(), test, format).into()
            }

            _ => {
                println!("WARNING: missing test: {:?}", testcase.metadata);
                TestResult::Skipped(testcase.skip())
            }
        }
    }
}
