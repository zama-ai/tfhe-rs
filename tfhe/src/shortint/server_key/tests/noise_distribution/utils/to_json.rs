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
    test_name: &'a str,
    test_module_path: &'a str,
}

impl<'a> TestJsonGuard<'a> {
    pub fn new(
        meta_param: &'a MetaParameters,
        test_name: &'a str,
        test_module_path: &'a str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::write_json_file(
            meta_param,
            test_name,
            test_module_path,
            false,
            None,
            TestResult::Empty {},
        )?;
        Ok(TestJsonGuard {
            meta_param,
            test_name,
            test_module_path,
        })
    }

    pub fn write_results(
        &self,
        pass: bool,
        warning: Option<String>,
        results: TestResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Self::write_json_file(
            self.meta_param,
            self.test_name,
            self.test_module_path,
            pass,
            warning,
            results,
        )
    }

    fn write_json_file(
        meta_param: &MetaParameters,
        test_name: &str,
        test_module_path: &str,
        pass: bool,
        warning: Option<String>,
        results: TestResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_id = format!("{test_module_path}::{test_name}").to_lowercase();
        let short_name = test_module_path
            .rsplit_once("::")
            .map_or(test_module_path, |(_, p)| p);
        let output_data =
            TestJsonOutput::new(&test_id, short_name, pass, warning, meta_param, results);
        let serialized_output = serde_json::to_string_pretty(&output_data)?;
        let mut path = PathBuf::new();
        path.push("tests_results");
        fs::create_dir_all(&path)?;
        path.push(format!("{test_id}.json"));
        fs::write(&path, serialized_output)?;
        Ok(())
    }
}
