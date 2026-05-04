use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::fs;
use std::path::PathBuf;

/// Directories where crypto parameters records can be stored.
const BENCHMARK_DIRS: &[&str] = &["tfhe-benchmark", "tfhe-zk-pok"];

/// Subset of the `parameters.json` shape we care about.
///
/// The fields we surface separately at the `Point` level are deserialized into named fields, the
/// nested `crypto_parameters` object is captured as-is, and `#[serde(flatten)]` collects every
/// other top-level field into `rest`. The dynamic shape of crypto parameters across benchmarks
/// makes a fully-typed mirror of `BenchmarkParametersRecord` unhelpful here.
#[derive(Deserialize)]
struct ParametersHeader {
    display_name: String,
    operator_type: String,
    crypto_parameters: Map<String, Value>,
    #[serde(flatten)]
    rest: Map<String, Value>,
}

/// Locate and read the `parameters.json` file produced by `write_to_json_unchecked` for a given
/// `bench_id`. Tries each candidate in [`BENCHMARK_DIRS`] in turn.
///
/// Returns `(flat_params, display_name, operator_type)` where `flat_params` is the top-level JSON
/// object with `crypto_parameters` merged in (crypto entries win on key collisions), and the two
/// scalar fields hoisted out for use at the `Point` level.
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
        let header: ParametersHeader = serde_json::from_str(&content)
            .with_context(|| format!("parsing {}", path.display()))?;

        let mut map = header.rest;
        map.extend(header.crypto_parameters);
        return Ok((map, header.display_name, header.operator_type));
    }
    Err(anyhow!(
        "file not found: '[...]/benchmarks_parameters/{bench_id}/parameters.json'"
    ))
}
