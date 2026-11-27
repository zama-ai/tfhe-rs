mod tests;
mod types;

pub use types::*;

use crate::shortint::parameters::MetaParameters;
use std::fs;
use std::path::PathBuf;

/// Returns the name of the function from which it is called.
#[macro_export]
macro_rules! this_function_name {
    () => {{
        struct Local;
        let name = std::any::type_name::<Local>();
        let first = name.split("::").nth(1).unwrap_or(name);
        let before_last = name.rsplit("::").nth(1).unwrap_or(name);
        format!("{}::{}", first, before_last)
    }};
}

pub struct TestJsonGuard<'a> {
    meta_param: &'a MetaParameters,
    param_name: &'a str,
    function_name: &'a str,
    kind: TestKind,
    backend: Backend,
    run: Option<RunContext>,
}

impl<'a> TestJsonGuard<'a> {
    pub fn new_cpu(
        meta_param: &'a MetaParameters,
        param_name: &'a str,
        function_name: &'a str,
        kind: TestKind,
    ) -> Self {
        Self::new(meta_param, param_name, function_name, kind, Backend::Cpu)
    }

    #[cfg(feature = "gpu")]
    pub fn new_gpu(
        meta_param: &'a MetaParameters,
        param_name: &'a str,
        function_name: &'a str,
        kind: TestKind,
    ) -> Self {
        Self::new(meta_param, param_name, function_name, kind, Backend::Gpu)
    }

    fn new(
        meta_param: &'a MetaParameters,
        param_name: &'a str,
        function_name: &'a str,
        kind: TestKind,
        backend: Backend,
    ) -> Self {
        let guard = Self {
            meta_param,
            param_name,
            function_name,
            kind,
            backend,
            run: run_context_from_env(),
        };
        guard.write_results(false, None, TestResult::Empty {});
        guard
    }

    pub fn write_results(
        &self,
        pass: bool,
        warning: Option<String>,
        results: impl Into<TestResult>,
    ) {
        let mut path = PathBuf::from("tests_results");
        fs::create_dir_all(&path).expect("failed to create the test results directory");
        path.push(format!("{}.json", self.file_name()));
        let (layer, name) = self.layer_and_name();
        let output_data = TestJsonOutput {
            name: name.to_string(),
            kind: self.kind,
            layer: layer.to_string(),
            backend: self.backend,
            param_name: self.param_name.to_string(),
            pass,
            warning,
            run: self.run.clone(),
            parameters: self.meta_param,
            results: results.into(),
        };
        let serialized_output =
            serde_json::to_string_pretty(&output_data).expect("failed to serialize test results");
        fs::write(&path, serialized_output)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
    }

    fn test_id(&self) -> String {
        format!("{}::{}", self.function_name, self.param_name).to_lowercase()
    }

    fn file_name(&self) -> String {
        self.test_id().replace("::", "-")
    }

    fn layer_and_name(&self) -> (&str, &str) {
        self.function_name
            .split_once("::")
            .expect("function name should be `layer::name`, as built by this_function_name!")
    }
}

/// Only read when `TFHE_RS_TEST_RECORD_RESULTS=1`, set by the workflow that sends the results
/// to the database. GitHub sets the `GITHUB_*` variables, the workflow exports the
/// `TFHE_RS_TEST_*` ones.
fn run_context_from_env() -> Option<RunContext> {
    if !std::env::var("TFHE_RS_TEST_RECORD_RESULTS").is_ok_and(|v| v == "1") {
        return None;
    }

    let var = |name: &str| {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} must be set when TFHE_RS_TEST_RECORD_RESULTS=1"))
    };
    Some(RunContext {
        commit_sha: var("GITHUB_SHA"),
        commit_date: var("TFHE_RS_TEST_COMMIT_DATE"),
        branch: var("GITHUB_REF_NAME"),
        gh_run_id: var("GITHUB_RUN_ID"),
        gh_run_attempt: var("GITHUB_RUN_ATTEMPT"),
        machine: var("TFHE_RS_TEST_MACHINE"),
    })
}
