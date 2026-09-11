//! Serializers for a `Grid`, one module per output format. Each owns its own
//! escaping.

pub mod csv;
pub mod markdown;
pub mod svg;

/// Cell shown when a column was not measured for a row that has data.
const MISSING: &str = "N/A";

/// One RFC 4180 record. Quoting is not optional: row labels hold commas
/// (`Comparisons (ge, gt, le, lt)`), and so does the archive's `note` column.
///
/// Lives here rather than in [`csv`] because the archive writes records without
/// ever building a [`Grid`](crate::format::Grid).
pub(crate) fn write_record<'a>(out: &mut String, fields: impl Iterator<Item = &'a str>) {
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

#[cfg(test)]
mod tests {
    use crate::format::{Grid, Row};

    fn grid() -> Grid {
        Grid {
            row_header: r"Operation \ Size".to_string(),
            columns: vec!["FheUint8".to_string()],
            rows: vec![Row {
                label: "Comparisons (ge, gt)".to_string(),
                cells: vec![None],
            }],
        }
    }

    #[test]
    fn csv_quotes_labels_containing_commas() {
        assert_eq!(
            super::csv::table(&grid()),
            "Operation \\ Size,FheUint8\n\"Comparisons (ge, gt)\",N/A\n"
        );
    }

    #[test]
    fn markdown_fills_missing_cells() {
        assert!(super::markdown::table(&grid()).ends_with("| Comparisons (ge, gt) | N/A |\n"));
    }

    /// The pipe lives unescaped in the grid; each format escapes its own way.
    #[test]
    fn each_format_escapes_its_own_pipe() {
        let mut g = grid();
        g.rows[0].label = "Bitwise (&, |, ^)".to_string();

        assert!(super::markdown::table(&g).contains(r"Bitwise (&, \|, ^)"));
        assert!(super::csv::table(&g).contains("\"Bitwise (&, |, ^)\""));
        assert!(super::svg::table(&g).contains("Bitwise (&#38;, &#124;, ^)"));
    }
}
