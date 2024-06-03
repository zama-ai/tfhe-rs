//! Tests breaking change in serialized data by trying to load historical data stored in https://github.com/zama-ai/tfhe-backward-compat-data.
//! For each tfhe-rs module, there is a folder with some serialized messages and a [ron](https://github.com/ron-rs/ron)
//! file. The ron file stores some metadata that are parsed in this test. These metadata tell us
//! what to test for each message.

mod backward_compatibility;

use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[cfg(feature = "shortint")]
use backward_compatibility::shortint::{test_shortint_ciphertext, test_shortint_clientkey};
use tfhe_backward_compat_data::load::DataFormat;
use tfhe_backward_compat_data::{
    data_dir, dir_for_version, TestFailure, TestMetadata, TestSuccess, Testcase,
};

#[cfg(feature = "shortint")]
use backward_compatibility::shortint;

fn test_data_dir() -> PathBuf {
    // Try to load the test data from the user provided environment variable or default to a
    // hardcoded path
    let root_dir = if let Ok(dir_str) = env::var("TFHE_BACKWARD_COMPAT_DATA_DIR") {
        PathBuf::from_str(&dir_str).unwrap()
    } else {
        PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))
            .unwrap()
            .join("tfhe-backward-compat-data")
    };

    if !root_dir.exists() {
        panic!("Missing backward compatibility test data. Clone them using `make clone_backward_compat_data`")
    }

    data_dir(root_dir)
}

/// Run a specific testcase. The testcase should be valid for the current version.
fn run_test<P: AsRef<Path>>(
    base_dir: P,
    testcase: &Testcase,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let version = &testcase.tfhe_version_min;
    let module = &testcase.tfhe_module;

    let mut test_dir = dir_for_version(base_dir, version);
    test_dir.push(module);

    #[allow(unreachable_patterns)]
    let test_result = match &testcase.metadata {
        #[cfg(feature = "shortint")]
        TestMetadata::ShortintCiphertext(test) => test_shortint_ciphertext(test, format, &test_dir),
        #[cfg(feature = "shortint")]
        TestMetadata::ShortintClientKey(test) => test_shortint_clientkey(test, format, &test_dir),
        _ => {
            panic!("missing feature, could not run test")
        }
    };

    match &test_result {
        Ok(r) => println!("{}", r),
        Err(r) => println!("{}", r),
    }

    test_result
}

#[test]
#[cfg(feature = "shortint")]
fn test_backward_compatibility_shortint() {
    let base_dir = test_data_dir();

    let results = shortint::test_shortint(base_dir);

    if results.iter().any(|r| r.is_err()) {
        panic!("Backward compatibility test failed")
    }
}
