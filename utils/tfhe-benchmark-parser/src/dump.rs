use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use tfhe_benchmark_parser::model::{Point, Series};

pub fn write_series(series: &Series, output: &Path) -> Result<()> {
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let serialized = serde_json::to_string(series)?;
    fs::write(output, serialized).with_context(|| format!("writing {}", output.display()))?;
    Ok(())
}

pub fn append_points(points: Vec<Point>, output: &Path) -> Result<()> {
    let existing =
        fs::read_to_string(output).with_context(|| format!("reading {}", output.display()))?;
    let mut series: Series = serde_json::from_str(&existing)
        .with_context(|| format!("parsing existing series in {}", output.display()))?;
    series.points.extend(points);
    let serialized = serde_json::to_string(&series)?;
    fs::write(output, serialized).with_context(|| format!("writing {}", output.display()))?;
    Ok(())
}
