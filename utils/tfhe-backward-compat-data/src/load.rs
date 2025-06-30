use std::fmt::Display;
use std::fs::{self, File};
use std::path::Path;

use bincode::{DefaultOptions, Options};
use serde::de::DeserializeOwned;

use crate::{TestType, Testcase};

/// Loads auxiliary data that might be needed for a test (eg: a key to test a ciphertext)
/// If the path has an extension the file is loaded as is, if not it adds the .cbor extension
pub fn load_versioned_auxiliary<Data: DeserializeOwned, P: AsRef<Path>>(
    path: P,
) -> Result<Data, String> {
    let path = path.as_ref();
    let path = match path.extension() {
        Some(_) => path.to_path_buf(),
        None => path.with_extension("cbor"),
    };

    let path = path.as_path();

    let file = File::open(path)
        .map_err(|e| format!("Failed to read auxiliary file {}: {}", path.display(), e))?;
    ciborium::de::from_reader(file)
        .map_err(|e| format!("Failed to parse auxiliary file {}: {}", path.display(), e))
}

#[derive(Copy, Clone, Debug)]
pub enum DataFormat {
    Cbor,
    Bincode,
}

impl Display for DataFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl DataFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            DataFormat::Cbor => "cbor",
            DataFormat::Bincode => "bcode",
        }
    }

    /// Loads the file that should be tested
    pub fn load_versioned_test<Data: DeserializeOwned, P: AsRef<Path>, T: TestType>(
        self,
        dir: P,
        test: &T,
    ) -> Result<Data, TestFailure> {
        let filename = format!("{}.{}", test.test_filename(), self.extension());
        let file = File::open(dir.as_ref().join(filename))
            .map_err(|e| test.failure(format!("Failed to read testcase: {}", e), self))?;

        match self {
            Self::Cbor => ciborium::de::from_reader(file).map_err(|e| test.failure(e, self)),
            Self::Bincode => {
                let options = DefaultOptions::new().with_fixint_encoding();
                options
                    .deserialize_from(file)
                    .map_err(|e| test.failure(e, self))
            }
        }
    }
}

pub enum TestResult {
    Success(TestSuccess),
    Failure(TestFailure),
    Skipped(TestSkipped),
}

impl From<Result<TestSuccess, TestFailure>> for TestResult {
    fn from(value: Result<TestSuccess, TestFailure>) -> Self {
        match value {
            Ok(success) => Self::Success(success),
            Err(failure) => Self::Failure(failure),
        }
    }
}

impl TestResult {
    pub fn is_failure(&self) -> bool {
        match self {
            TestResult::Failure(_) => true,
            TestResult::Success(_) | TestResult::Skipped(_) => false,
        }
    }
}

pub struct TestFailure {
    pub(crate) module: String,
    pub(crate) target_type: String,
    pub(crate) test_filename: String,
    pub(crate) source_error: String,
    pub(crate) format: DataFormat,
}

impl Display for TestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Test: {}::{} in file {}.{}: FAILED: {}",
            self.module,
            self.target_type,
            self.test_filename,
            self.format.extension(),
            self.source_error
        )
    }
}

pub struct TestSuccess {
    pub(crate) module: String,
    pub(crate) target_type: String,
    pub(crate) test_filename: String,
    pub(crate) format: DataFormat,
}

impl Display for TestSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Test: {}::{} using file {}.{}: SUCCESS",
            self.module,
            self.target_type,
            self.test_filename,
            self.format.extension(),
        )
    }
}

pub struct TestSkipped {
    pub(crate) module: String,
    pub(crate) test_name: String,
}

impl Display for TestSkipped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Test: {}::{}: SKIPPED", self.module, self.test_name)
    }
}

pub fn load_tests_metadata<P: AsRef<Path>>(path: P) -> Result<Vec<Testcase>, String> {
    let serialized =
        fs::read_to_string(path).map_err(|e| format!("Failed to load test metadata: {}", e))?;
    ron::from_str(&serialized).map_err(|e| format!("Invalid test metadata: {}", e))
}
