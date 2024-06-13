use std::path::Path;

use tfhe::prelude::FheDecrypt;
use tfhe::shortint::PBSParameters;
use tfhe::{ClientKey, CompressedFheUint8, FheUint8};
use tfhe_backward_compat_data::load::{load_versioned_auxiliary, DataFormat};
use tfhe_backward_compat_data::{
    HlCiphertextTest, HlClientKeyTest, TestFailure, TestMetadata, TestParameterSet, TestSuccess,
    TestType, Testcase,
};
use tfhe_versionable::Unversionize;

use crate::TestedModule;

use super::shortint::load_params;

fn load_hl_params(test_params: &TestParameterSet) -> PBSParameters {
    let pbs_params = load_params(test_params);

    PBSParameters::PBS(pbs_params)
}

pub fn test_hl_ciphertext(
    dir: &Path,
    test: &HlCiphertextTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let key_file = dir.join(&*test.key_filename);
    let key =
        ClientKey::unversionize(load_versioned_auxiliary(key_file).map_err(|e| test.failure(e))?)
            .map_err(|e| test.failure(e))?;

    let ct = if test.compressed {
        CompressedFheUint8::unversionize(
            format
                .load_versioned_test(dir, &test.test_filename)
                .map_err(|e| test.failure(e))?,
        )
        .map_err(|e| test.failure(e))?
        .decompress()
    } else {
        FheUint8::unversionize(
            format
                .load_versioned_test(dir, &test.test_filename)
                .map_err(|e| test.failure(e))?,
        )
        .map_err(|e| test.failure(e))?
    };

    let clear: u8 = ct.decrypt(&key);

    if clear != (test.clear_value as u8) {
        Err(test.failure(format!(
            "Invalid {} decrypted cleartext:\n Expected :\n{:?}\nGot:\n{:?}",
            format, clear, test.clear_value
        )))
    } else {
        Ok(test.success())
    }
}

pub fn test_hl_clientkey(
    dir: &Path,
    test: &HlClientKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let test_params = load_hl_params(&test.parameters);

    let versioned_key = format
        .load_versioned_test(dir, &test.test_filename)
        .map_err(|e| test.failure(e))?;

    let key = ClientKey::unversionize(versioned_key).map_err(|e| test.failure(e))?;
    let (integer_key, _) = key.into_raw_parts();
    let key_params = integer_key.parameters();

    if test_params != key_params {
        Err(test.failure(format!(
            "Invalid {} parameters:\n Expected :\n{:?}\nGot:\n{:?}",
            format, test_params, key_params
        )))
    } else {
        Ok(test.success())
    }
}

pub struct Hl;

impl TestedModule for Hl {
    const METADATA_FILE: &'static str = "high_level_api.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase,
        format: DataFormat,
    ) -> Result<TestSuccess, TestFailure> {
        #[allow(unreachable_patterns)]
        match &testcase.metadata {
            TestMetadata::HlCiphertext(test) => test_hl_ciphertext(test_dir.as_ref(), test, format),
            TestMetadata::HlClientKey(test) => test_hl_clientkey(test_dir.as_ref(), test, format),
            _ => {
                panic!("missing feature, could not run test")
            }
        }
    }
}
