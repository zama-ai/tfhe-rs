#![cfg(feature = "shortint")]

//! Tests breaking change in serialized data by trying to load historical data stored with git LFS
//! inside `utils/tfhe-backward-compat-data`. For each tfhe-rs module, there is a folder with some serialized messages and a [ron](https://github.com/ron-rs/ron)
//! file. The ron file stores some metadata that are parsed in this test. These metadata tell us
//! what to test for each message.

mod backward_compatibility;

use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use cargo_toml::Manifest;
use tfhe_backward_compat_data::load::{load_tests_metadata, DataFormat, TestFailure, TestResult};
use tfhe_backward_compat_data::{dir_for_version, TestType, Testcase};
use tfhe_versionable::Unversionize;

fn test_data_dir() -> PathBuf {
    // Try to load the test data from the user provided environment variable or default to a
    // hardcoded path
    let mut root_dir = if let Ok(dir_str) = env::var("TFHE_BACKWARD_COMPAT_DATA_DIR") {
        PathBuf::from_str(&dir_str).unwrap()
    } else {
        PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))
            .unwrap()
            .join("..")
            .join("utils")
            .join("tfhe-backward-compat-data")
    };

    if !root_dir.exists() {
        panic!("Wrong backward compat data folder: {}", root_dir.display())
    }

    root_dir.push("data");
    root_dir
}

fn tfhe_manifest_dir() -> PathBuf {
    PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))
        .unwrap()
        .join("..")
        .join("tfhe")
        .join("Cargo.toml")
}

fn load_and_unversionize<Data: Unversionize, P: AsRef<Path>, T: TestType>(
    dir: P,
    test: &T,
    format: DataFormat,
) -> Result<Data, TestFailure> {
    let versioned = format.load_versioned_test(dir, test)?;

    Data::unversionize(versioned).map_err(|e| test.failure(e, format))
}

trait TestedModule {
    /// The name of the `.ron` file where the metadata for this module are stored
    const METADATA_FILE: &'static str;

    /// Run a testcase for this module
    fn run_test<P: AsRef<Path>>(base_dir: P, testcase: &Testcase, format: DataFormat)
        -> TestResult;
}

/// Run a specific testcase. The testcase should be valid for the current version.
fn run_test<M: TestedModule>(
    base_dir: &Path,
    testcase: &Testcase,
    format: DataFormat,
) -> TestResult {
    let version = &testcase.tfhe_version_min;
    let module = &testcase.tfhe_module;

    let mut test_dir = dir_for_version(base_dir, version);
    test_dir.push(module);

    let test_result = M::run_test(test_dir, testcase, format);

    match &test_result {
        TestResult::Success(r) => println!("{r}"),
        TestResult::Failure(r) => println!("{r}"),
        TestResult::Skipped(r) => println!("{r}"),
    }

    test_result
}

fn run_all_tests<M: TestedModule>(base_dir: &Path) -> Vec<TestResult> {
    let meta = load_tests_metadata(base_dir.join(M::METADATA_FILE)).unwrap();

    let mut results = Vec::new();

    let tfhe_manifest = Manifest::from_path(tfhe_manifest_dir()).unwrap();
    let tfhe_version = tfhe_manifest.package().version();

    for testcase in meta {
        if testcase.is_valid_for_version(tfhe_version) {
            let test_result = run_test::<M>(base_dir, &testcase, DataFormat::Cbor);
            results.push(test_result);
            let test_result = run_test::<M>(base_dir, &testcase, DataFormat::Bincode);
            results.push(test_result)
        }
    }

    println!("Executed {} tests", results.len());
    // If we ran 0 test, it is likely that something wrong happened
    assert!(!results.is_empty());

    if results.iter().all(|res| res.is_failure()) {
        println!(
            "\nAll tests failed. Maybe the backward compatibility data files are missing. \
Pull them using `make pull_backward_compat_data`"
        )
    }

    results
}

#[test]
#[cfg(feature = "shortint")]
fn test_backward_compatibility_shortint() {
    use backward_compatibility::shortint::Shortint;

    let base_dir = test_data_dir();

    let results = run_all_tests::<Shortint>(&base_dir);

    if results.iter().any(|r| r.is_failure()) {
        panic!("Backward compatibility test failed")
    }
}

#[test]
#[cfg(feature = "integer")]
fn test_backward_compatibility_hl() {
    use backward_compatibility::high_level_api::Hl;

    let base_dir = test_data_dir();

    let results = run_all_tests::<Hl>(&base_dir);

    if results.iter().any(|r| r.is_failure()) {
        panic!("Backward compatibility test failed")
    }
}
