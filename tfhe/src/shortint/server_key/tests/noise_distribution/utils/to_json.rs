use crate::shortint::parameters::MetaParameters;
use std::fs;
use std::path::PathBuf;
pub use tfhe_test_results::*;

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
}

impl<'a> TestJsonGuard<'a> {
    pub fn new(
        meta_param: &'a MetaParameters,
        param_name: &'a str,
        function_name: &'a str,
        kind: TestKind,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let guard = Self {
            meta_param,
            param_name,
            function_name,
            kind,
        };
        guard.write_results(false, None, TestResult::Empty {})?;
        Ok(guard)
    }

    pub fn write_results(
        &self,
        pass: bool,
        warning: Option<String>,
        results: TestResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut path = PathBuf::new();
        path.push("tests_results");
        fs::create_dir_all(&path)?;
        path.push(format!("{}.json", self.file_name()));
        let (layer, name) = self.layer_and_name();
        let output_data = TestJsonOutput {
            test: self.test_id(),
            name: name.to_string(),
            kind: self.kind,
            layer: layer.to_string(),
            param_name: self.param_name.to_string(),
            pass,
            warning,
            parameters: self.meta_param,
            results,
        };
        let serialized_output = serde_json::to_string_pretty(&output_data)?;
        fs::write(&path, serialized_output)?;
        Ok(())
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
            .unwrap_or(("", self.function_name))
    }
}
