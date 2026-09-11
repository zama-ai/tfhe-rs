//! RFC 4180 CSV.

use super::{MISSING, write_record};
use crate::format::Grid;

pub fn table(grid: &Grid) -> String {
    let mut out = String::new();
    write_record(
        &mut out,
        std::iter::once(grid.row_header.as_str()).chain(grid.columns.iter().map(String::as_str)),
    );
    for row in &grid.rows {
        write_record(
            &mut out,
            std::iter::once(row.label.as_str())
                .chain(row.cells.iter().map(|c| c.as_deref().unwrap_or(MISSING))),
        );
    }
    out
}
