use anyhow::{Context, Result, anyhow};
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// Directories where parameter records can be stored.
const BENCHMARK_DIRS: [&str; 2] = ["tfhe-benchmark", "tfhe-zk-pok"];

/// Locate and read the `parameters.json` file produced by `write_to_json_unchecked` for a given
/// `bench_id`. Tries each candidate in [`BENCHMARK_DIRS`] in turn.
///
/// Returns `(params, display_name, operator_type)` where `params` is the remaining top-level JSON
/// object after `display_name` and `operator_type` have been extracted.
pub(super) fn get_parameters(bench_id: &str) -> Result<(Map<String, Value>, String, String)> {
    for dirname in BENCHMARK_DIRS {
        let path = PathBuf::from(dirname)
            .join("benchmarks_parameters")
            .join(bench_id)
            .join("parameters.json");
        if !path.exists() {
            continue;
        }

        let content =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let mut map: Map<String, Value> = serde_json::from_str(&content)
            .with_context(|| format!("parsing {}", path.display()))?;

        let display_name = take_string(&mut map, "display_name", &path)?;
        let operator = take_string(&mut map, "operator_type", &path)?;

        return Ok((map, display_name, operator));
    }
    Err(anyhow!(
        "file not found: '[...]/benchmarks_parameters/{bench_id}/parameters.json'"
    ))
}

fn take_string(map: &mut Map<String, Value>, key: &str, path: &Path) -> Result<String> {
    match map.remove(key) {
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(anyhow!(
            "field '{key}' is not a string in {}",
            path.display()
        )),
        None => Err(anyhow!("missing field '{key}' in {}", path.display())),
    }
}
