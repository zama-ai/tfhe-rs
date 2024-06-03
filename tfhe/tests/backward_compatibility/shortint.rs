use std::path::Path;

use tfhe::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize, StandardDev,
};
use tfhe_backward_compat_data::load::{load_tests_metadata, load_versioned_auxiliary, DataFormat};
use tfhe_backward_compat_data::{
    ShortintCiphertextTest, ShortintClientKeyTest, TestFailure, TestParameterSet, TestSuccess,
    TestType,
};

use tfhe::shortint::{
    CarryModulus, Ciphertext, CiphertextModulus, ClassicPBSParameters, ClientKey,
    EncryptionKeyChoice, MaxNoiseLevel, MessageModulus, PBSParameters, ShortintParameterSet,
};
use tfhe_versionable::Unversionize;

use crate::run_test;

/// Converts test parameters metadata that are independant of any tfhe-rs version and use only
/// built-in types into parameters suitable for the currently tested version.
fn load_params(test_params: &TestParameterSet) -> ShortintParameterSet {
    ShortintParameterSet::new_pbs_param_set(PBSParameters::PBS(ClassicPBSParameters {
        lwe_dimension: LweDimension(test_params.lwe_dimension),
        glwe_dimension: GlweDimension(test_params.glwe_dimension),
        polynomial_size: PolynomialSize(test_params.polynomial_size),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            test_params.lwe_noise_gaussian_stddev,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            test_params.glwe_noise_gaussian_stddev,
        )),
        pbs_base_log: DecompositionBaseLog(test_params.pbs_base_log),
        pbs_level: DecompositionLevelCount(test_params.pbs_level),
        ks_base_log: DecompositionBaseLog(test_params.ks_base_log),
        ks_level: DecompositionLevelCount(test_params.ks_level),
        message_modulus: MessageModulus(test_params.message_modulus),
        carry_modulus: CarryModulus(test_params.carry_modulus),
        max_noise_level: MaxNoiseLevel::new(test_params.max_noise_level),
        log2_p_fail: test_params.log2_p_fail,
        ciphertext_modulus: CiphertextModulus::try_new(test_params.ciphertext_modulus).unwrap(),
        encryption_key_choice: {
            match &*test_params.encryption_key_choice {
                "big" => EncryptionKeyChoice::Big,
                "small" => EncryptionKeyChoice::Small,
                _ => panic!("Invalid encryption key choice"),
            }
        },
    }))
}

pub fn test_shortint_ciphertext(
    test: &ShortintCiphertextTest,
    format: DataFormat,
    dir: &Path,
) -> Result<TestSuccess, TestFailure> {
    let key_file = dir.join(&*test.key_filename);
    let key =
        ClientKey::unversionize(load_versioned_auxiliary(key_file).map_err(|e| test.failure(e))?)
            .map_err(|e| test.failure(e))?;

    let ct = Ciphertext::unversionize(
        format
            .load_versioned_test(dir, &test.test_filename)
            .map_err(|e| test.failure(e))?,
    )
    .map_err(|e| test.failure(e))?;

    let clear = key.decrypt(&ct);
    if clear != test.clear_value {
        Err(test.failure(format!(
            "Invalid {} decrypted cleartext:\n Expected :\n{:?}\nGot:\n{:?}",
            format, clear, test.clear_value
        )))
    } else {
        Ok(test.success())
    }
}

pub fn test_shortint_clientkey(
    test: &ShortintClientKeyTest,
    format: DataFormat,
    dir: &Path,
) -> Result<TestSuccess, TestFailure> {
    let test_params = load_params(&test.parameters);

    let versioned_key = format
        .load_versioned_test(dir, &test.test_filename)
        .map_err(|e| test.failure(e))?;

    let key = ClientKey::unversionize(versioned_key).map_err(|e| test.failure(e))?;

    if test_params != key.parameters {
        Err(test.failure(format!(
            "Invalid {} parameters:\n Expected :\n{:?}\nGot:\n{:?}",
            format, test_params, key.parameters
        )))
    } else {
        Ok(test.success())
    }
}

pub fn test_shortint<P: AsRef<Path>>(base_dir: P) -> Vec<Result<TestSuccess, TestFailure>> {
    let meta = load_tests_metadata(base_dir.as_ref().join("shortint.ron")).unwrap();

    let mut results = Vec::new();

    for testcase in meta {
        if testcase.is_valid_for_version(env!("CARGO_PKG_VERSION")) {
            let test_result = run_test(&base_dir, &testcase, DataFormat::Cbor);
            results.push(test_result);
            let test_result = run_test(&base_dir, &testcase, DataFormat::Bincode);
            results.push(test_result)
        }
    }

    results
}
