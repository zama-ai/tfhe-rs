//! GitHub-flavoured markdown table.

use super::MISSING;
use crate::format::Grid;

pub fn table(grid: &Grid) -> String {
    let mut out = format!("| {} |", escape(&grid.row_header));
    let mut separator = String::from("\n|---|");
    for column in &grid.columns {
        out.push_str(&format!(" {} |", escape(column)));
        separator.push_str("---|");
    }
    out.push_str(&separator);
    out.push('\n');

    for row in &grid.rows {
        out.push_str(&format!("| {} |", escape(&row.label)));
        for cell in &row.cells {
            out.push_str(&format!(
                " {} |",
                escape(cell.as_deref().unwrap_or(MISSING))
            ));
        }
        out.push('\n');
    }
    out
}

/// A `|` would end the cell.
fn escape(s: &str) -> String {
    s.replace('|', "\\|")
}
