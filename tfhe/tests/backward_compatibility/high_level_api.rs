#![allow(deprecated)]
use std::path::Path;

use tfhe::backward_compatibility::booleans::{CompactFheBool, CompactFheBoolList};
use tfhe::backward_compatibility::integers::{
    CompactFheInt8, CompactFheInt8List, CompactFheUint8, CompactFheUint8List,
};
use tfhe::prelude::{FheDecrypt, FheEncrypt};
use tfhe::shortint::PBSParameters;
use tfhe::{
    set_server_key, ClientKey, CompactCiphertextList, CompressedCompactPublicKey,
    CompressedFheBool, CompressedFheInt8, CompressedFheUint8, CompressedPublicKey,
    CompressedServerKey, FheUint8,
};
use tfhe_backward_compat_data::load::{
    load_versioned_auxiliary, DataFormat, TestFailure, TestResult, TestSuccess,
};
use tfhe_backward_compat_data::{
    HlBoolCiphertextListTest, HlBoolCiphertextTest, HlCiphertextListTest, HlCiphertextTest,
    HlClientKeyTest, HlPublicKeyTest, HlServerKeyTest, HlSignedCiphertextListTest,
    HlSignedCiphertextTest, TestMetadata, TestParameterSet, TestType, Testcase,
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

/// Test HL signed ciphertext: loads the ciphertext and compare the decrypted value to the one in
/// the metadata.
pub fn test_hl_signed_ciphertext(
    dir: &Path,
    test: &HlSignedCiphertextTest,
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
        let compressed: CompressedFheInt8 = load_and_unversionize(dir, test, format)?;
        compressed.decompress()
    } else if test.compact {
        let compact: CompactFheInt8 = load_and_unversionize(dir, test, format)?;
        compact.expand().unwrap()
    } else {
        load_and_unversionize(dir, test, format)?
    };

    let clear: i8 = ct.decrypt(&key);

    if clear != (test.clear_value as i8) {
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

/// Test HL bool ciphertext: loads the ciphertext and compare the decrypted value to the one in the
/// metadata.
pub fn test_hl_bool_ciphertext(
    dir: &Path,
    test: &HlBoolCiphertextTest,
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
        let compressed: CompressedFheBool = load_and_unversionize(dir, test, format)?;
        compressed.decompress()
    } else if test.compact {
        let compact: CompactFheBool = load_and_unversionize(dir, test, format)?;
        compact.expand().unwrap()
    } else {
        load_and_unversionize(dir, test, format)?
    };

    let clear = ct.decrypt(&key);

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

/// Test HL ciphertext list: loads the ciphertext list and compare the decrypted values to the ones
///  in the metadata.
pub fn test_hl_ciphertext_list(
    dir: &Path,
    test: &HlCiphertextListTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let key_file = dir.join(&*test.key_filename);
    let key = ClientKey::unversionize(
        load_versioned_auxiliary(key_file).map_err(|e| test.failure(e, format))?,
    )
    .map_err(|e| test.failure(e, format))?;

    let server_key = key.generate_server_key();
    set_server_key(server_key);

    let compact: CompactFheUint8List = load_and_unversionize(dir, test, format)?;
    let ct_list = compact.expand().unwrap();

    let clear_list: Vec<u8> = ct_list.into_iter().map(|ct| ct.decrypt(&key)).collect();
    let ref_values: Vec<u8> = test.clear_values.iter().map(|v| *v as u8).collect();
    if clear_list != ref_values {
        Err(test.failure(
            format!(
                "Invalid {} decrypted cleartext:\n Expected :\n{:?}\nGot:\n{:?}",
                format, clear_list, ref_values
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

/// Test HL signed ciphertext list: loads the ciphertext list and compare the decrypted values to
/// the ones  in the metadata.
pub fn test_hl_signed_ciphertext_list(
    dir: &Path,
    test: &HlSignedCiphertextListTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let key_file = dir.join(&*test.key_filename);
    let key = ClientKey::unversionize(
        load_versioned_auxiliary(key_file).map_err(|e| test.failure(e, format))?,
    )
    .map_err(|e| test.failure(e, format))?;

    let server_key = key.generate_server_key();
    set_server_key(server_key);

    let compact: CompactFheInt8List = load_and_unversionize(dir, test, format)?;
    let ct_list = compact.expand().unwrap();

    let clear_list: Vec<i8> = ct_list.into_iter().map(|ct| ct.decrypt(&key)).collect();
    let ref_values: Vec<i8> = test.clear_values.iter().map(|v| *v as i8).collect();
    if clear_list != ref_values {
        Err(test.failure(
            format!(
                "Invalid {} decrypted cleartext:\n Expected :\n{:?}\nGot:\n{:?}",
                format, clear_list, ref_values
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

/// Test HL bool ciphertext list: loads the ciphertext list and compare the decrypted values to the
/// ones  in the metadata.
pub fn test_hl_bool_ciphertext_list(
    dir: &Path,
    test: &HlBoolCiphertextListTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let key_file = dir.join(&*test.key_filename);
    let key = ClientKey::unversionize(
        load_versioned_auxiliary(key_file).map_err(|e| test.failure(e, format))?,
    )
    .map_err(|e| test.failure(e, format))?;

    let server_key = key.generate_server_key();
    set_server_key(server_key);

    let compact: CompactFheBoolList = load_and_unversionize(dir, test, format)?;
    let ct_list = compact.expand().unwrap();

    let clear_list: Vec<bool> = ct_list.into_iter().map(|ct| ct.decrypt(&key)).collect();
    let ref_values: Vec<bool> = test.clear_values.iter().copied().collect();
    if clear_list != ref_values {
        Err(test.failure(
            format!(
                "Invalid {} decrypted cleartext:\n Expected :\n{:?}\nGot:\n{:?}",
                format, clear_list, ref_values
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
    let (integer_key, _, _) = key.into_raw_parts();
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

/// Test HL public key: encrypt a number with the pubkey and tries to decrypt it using
/// the associated client key.
pub fn test_hl_pubkey(
    dir: &Path,
    test: &HlPublicKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let client_key_file = dir.join(&*test.client_key_filename);
    let client_key = ClientKey::unversionize(
        load_versioned_auxiliary(client_key_file).map_err(|e| test.failure(e, format))?,
    )
    .map_err(|e| test.failure(e, format))?;

    let value = 113u8;

    let encrypted = if test.compact {
        let public_key = if test.compressed {
            let compressed: CompressedCompactPublicKey = load_and_unversionize(dir, test, format)?;
            compressed.decompress()
        } else {
            load_and_unversionize(dir, test, format)?
        };
        let ct_list = CompactCiphertextList::builder(&public_key)
            .push(value)
            .build();
        ct_list.expand().unwrap().get(0).unwrap().unwrap()
    } else {
        let public_key = if test.compressed {
            let compressed: CompressedPublicKey = load_and_unversionize(dir, test, format)?;
            compressed.decompress()
        } else {
            load_and_unversionize(dir, test, format)?
        };
        FheUint8::encrypt(value, &public_key)
    };
    let decrypted: u8 = encrypted.decrypt(&client_key);

    if decrypted != value {
        Err(test.failure(
            format!(
                "Failed to decrypt value encrypted with public key, got {} expected {}",
                decrypted, value
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

/// Test HL server key: encrypt to values with a client key, add them using the server key and check
/// that the decrypted sum is valid.
pub fn test_hl_serverkey(
    dir: &Path,
    test: &HlServerKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let client_key_file = dir.join(&*test.client_key_filename);
    let client_key = ClientKey::unversionize(
        load_versioned_auxiliary(client_key_file).map_err(|e| test.failure(e, format))?,
    )
    .map_err(|e| test.failure(e, format))?;

    let v1 = 73u8;
    let ct1 = FheUint8::encrypt(v1, &client_key);
    let v2 = 102u8;
    let ct2 = FheUint8::encrypt(v2, &client_key);

    let key = if test.compressed {
        let compressed: CompressedServerKey = load_and_unversionize(dir, test, format)?;
        compressed.decompress()
    } else {
        load_and_unversionize(dir, test, format)?
    };
    set_server_key(key);

    let ct_sum = ct1 + ct2;
    let sum: u8 = ct_sum.decrypt(&client_key);

    if sum != v1 + v2 {
        Err(test.failure(
            format!(
                "Invalid result for addition using loaded server key, expected {} got {}",
                v1 + v2,
                sum,
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
            TestMetadata::HlSignedCiphertext(test) => {
                test_hl_signed_ciphertext(test_dir.as_ref(), test, format).into()
            }
            TestMetadata::HlBoolCiphertext(test) => {
                test_hl_bool_ciphertext(test_dir.as_ref(), test, format).into()
            }
            TestMetadata::HlBoolCiphertextList(test) => {
                test_hl_bool_ciphertext_list(test_dir.as_ref(), test, format).into()
            }
            TestMetadata::HlCiphertextList(test) => {
                test_hl_ciphertext_list(test_dir.as_ref(), test, format).into()
            }
            TestMetadata::HlSignedCiphertextList(test) => {
                test_hl_signed_ciphertext_list(test_dir.as_ref(), test, format).into()
            }
            TestMetadata::HlClientKey(test) => {
                test_hl_clientkey(test_dir.as_ref(), test, format).into()
            }
            TestMetadata::HlPublicKey(test) => {
                test_hl_pubkey(test_dir.as_ref(), test, format).into()
            }
            TestMetadata::HlServerKey(test) => {
                test_hl_serverkey(test_dir.as_ref(), test, format).into()
            }
            _ => {
                println!("WARNING: missing test: {:?}", testcase.metadata);
                TestResult::Skipped(testcase.skip())
            }
        }
    }
}
