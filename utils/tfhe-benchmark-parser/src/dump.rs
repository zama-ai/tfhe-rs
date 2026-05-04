use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use tfhe_benchmark_parser::model::{Point, Series};

/// Serialize `series` to JSON and write it to `output`, creating the parent directory if needed.
pub fn write_series(series: &Series, output: &Path) -> Result<()> {
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    let serialized = serde_json::to_string(series)?;
    fs::write(output, serialized).with_context(|| format!("writing {}", output.display()))
}

/// Append `points` to the series already stored in `output`, then rewrite the file.
pub fn append_points(points: Vec<Point>, output: &Path) -> Result<()> {
    let existing =
        fs::read_to_string(output).with_context(|| format!("reading {}", output.display()))?;
    let mut series: Series = serde_json::from_str(&existing)
        .with_context(|| format!("parsing existing series in {}", output.display()))?;

    series.points.extend(points);

    write_series(&series, output)
}
