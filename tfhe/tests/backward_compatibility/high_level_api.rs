use std::path::Path;

use tfhe::backward_compatibility::integers::CompactFheUint8;
use tfhe::prelude::FheDecrypt;
use tfhe::shortint::PBSParameters;
use tfhe::{set_server_key, ClientKey, CompressedFheUint8};
use tfhe_backward_compat_data::load::{
    load_versioned_auxiliary, DataFormat, TestFailure, TestResult, TestSuccess,
};
use tfhe_backward_compat_data::{
    HlCiphertextTest, HlClientKeyTest, TestMetadata, TestParameterSet, TestType, Testcase,
};
use tfhe_versionable::Unversionize;

use crate::{load_and_unversionize, TestedModule};

use super::shortint::load_params;

fn load_hl_params(test_params: &TestParameterSet) -> PBSParameters {
    let pbs_params = load_params(test_params);

    PBSParameters::PBS(pbs_params)
}

/// Test HL ciphertext: loads the ciphertext and compare the decrypted value to the one in the
/// metadata.
pub fn test_hl_ciphertext(
    dir: &Path,
    test: &HlCiphertextTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let key_file = dir.join(&*test.key_filename);
    let key = ClientKey::unversionize(
        load_versioned_auxiliary(key_file).map_err(|e| test.failure(e, format))?,
    )
    .map_err(|e| test.failure(e, format))?;

    let server_key = key.generate_server_key();
    set_server_key(server_key);

    let ct = if test.compressed {
        let compressed: CompressedFheUint8 = load_and_unversionize(dir, test, format)?;
        compressed.decompress()
    } else if test.compact {
        let compact: CompactFheUint8 = load_and_unversionize(dir, test, format)?;
        compact.expand().unwrap()
    } else {
        load_and_unversionize(dir, test, format)?
    };

    let clear: u8 = ct.decrypt(&key);

    if clear != (test.clear_value as u8) {
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

/// Test HL client key: loads the key and checks the parameters using the values stored in
/// the test metadata.
pub fn test_hl_clientkey(
    dir: &Path,
    test: &HlClientKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let test_params = load_hl_params(&test.parameters);

    let key: ClientKey = load_and_unversionize(dir, test, format)?;
    let (integer_key, _, _, _) = key.into_raw_parts();
    let key_params = integer_key.parameters();

    if test_params != key_params {
        Err(test.failure(
            format!(
                "Invalid {} parameters:\n Expected :\n{:?}\nGot:\n{:?}",
                format, test_params, key_params
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

pub struct Hl;

impl TestedModule for Hl {
    const METADATA_FILE: &'static str = "high_level_api.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase,
        format: DataFormat,
    ) -> TestResult {
        #[allow(unreachable_patterns)]
        match &testcase.metadata {
            TestMetadata::HlCiphertext(test) => {
                test_hl_ciphertext(test_dir.as_ref(), test, format).into()
            }
            TestMetadata::HlClientKey(test) => {
                test_hl_clientkey(test_dir.as_ref(), test, format).into()
            }
            _ => {
                println!("WARNING: missing test: {:?}", testcase.metadata);
                TestResult::Skipped(testcase.skip())
            }
        }
    }
}
