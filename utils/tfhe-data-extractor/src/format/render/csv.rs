//! RFC 4180 CSV. Quoting is not optional here: row labels contain commas
//! (`Comparisons (ge, gt, le, lt)`).

use super::MISSING;
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

fn write_record<'a>(out: &mut String, fields: impl Iterator<Item = &'a str>) {
    for (index, field) in fields.enumerate() {
        if index > 0 {
            out.push(',');
        }
        if field.contains([',', '"', '\n']) {
            out.push('"');
            out.push_str(&field.replace('"', "\"\""));
            out.push('"');
        } else {
            out.push_str(field);
        }
    }
    out.push('\n');
}
