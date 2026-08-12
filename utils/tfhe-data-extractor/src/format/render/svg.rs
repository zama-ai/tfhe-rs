//! SVG table, as published in the documentation: fixed geometry, a black header
//! row, a yellow first column and a grey body, separated by white rules.

use super::MISSING;
use crate::format::Grid;

const BLACK: &str = "black";
const WHITE: &str = "white";
const LIGHT_GREY: &str = "#f3f3f3";
const YELLOW: &str = "#fbbc04";
/// Arial first, for the metrics the fixed geometry below was sized against.
/// Liberation Sans, the usual Linux substitute, is metric-compatible.
const FONT_FAMILY: &str = "Arial, Helvetica, sans-serif";
const FONT_SIZE: u32 = 14;
const BORDER_WIDTH: u32 = 2;
/// Left inset of the row labels and of the row header.
const LABEL_INSET: f64 = 6.0;

/// Dimensions of the published tables. The label column is sized to hold the
/// longest row label at [`FONT_SIZE`], with little to spare.
const OVERALL_WIDTH: f64 = 720.0;
const ROW_HEIGHT: f64 = 40.0;
const LABEL_COL_WIDTH: f64 = 300.0;

pub fn table(grid: &Grid) -> String {
    let col_count = grid.columns.len().max(1) as f64;
    let col_width = (OVERALL_WIDTH - LABEL_COL_WIDTH) / col_count;
    let height = (1 + grid.rows.len()) as f64 * ROW_HEIGHT;

    // The accessible name of the image. The row header is the closest thing to a
    // caption a `Grid` carries.
    let mut elements = vec![format!("  <title>{}</title>", escape(&grid.row_header))];

    // Header row: black band, then the column labels.
    elements.push(rect(0.0, 0.0, OVERALL_WIDTH, ROW_HEIGHT, BLACK));
    elements.push(text(
        LABEL_INSET,
        ROW_HEIGHT / 2.0,
        &grid.row_header,
        "start",
        WHITE,
        true,
    ));
    for (index, column) in grid.columns.iter().enumerate() {
        let centre = LABEL_COL_WIDTH + index as f64 * col_width + col_width / 2.0;
        // Rust type headers are split over two lines so the size stands out;
        // anything else is a single centred label.
        match column.strip_prefix("FheUint") {
            Some(size) => {
                elements.push(text(
                    centre,
                    ROW_HEIGHT / 3.0,
                    "FheUint",
                    "middle",
                    WHITE,
                    true,
                ));
                elements.push(text(
                    centre,
                    2.0 * ROW_HEIGHT / 3.0 + 3.0,
                    size,
                    "middle",
                    WHITE,
                    true,
                ));
            }
            None => elements.push(text(
                centre,
                ROW_HEIGHT / 2.0,
                column,
                "middle",
                WHITE,
                true,
            )),
        }
    }

    // Body background: labels on yellow, values on grey.
    elements.push(rect(
        0.0,
        ROW_HEIGHT,
        LABEL_COL_WIDTH,
        height - ROW_HEIGHT,
        YELLOW,
    ));
    elements.push(rect(
        LABEL_COL_WIDTH,
        ROW_HEIGHT,
        OVERALL_WIDTH - LABEL_COL_WIDTH,
        height - ROW_HEIGHT,
        LIGHT_GREY,
    ));

    for (index, row) in grid.rows.iter().enumerate() {
        let baseline = (index + 1) as f64 * ROW_HEIGHT + ROW_HEIGHT / 2.0;
        elements.push(text(
            LABEL_INSET,
            baseline,
            &row.label,
            "start",
            BLACK,
            false,
        ));
        for (column, cell) in row.cells.iter().enumerate() {
            let centre = LABEL_COL_WIDTH + column as f64 * col_width + col_width / 2.0;
            let value = cell.as_deref().unwrap_or(MISSING);
            elements.push(text(centre, baseline, value, "middle", BLACK, false));
        }
    }

    // One rule per row boundary, the bottom edge included.
    //
    // The four outer rules sit half a stroke inside the box, otherwise the
    // viewBox clips them to half their width while the inner ones keep theirs.
    let inset = f64::from(BORDER_WIDTH) / 2.0;
    for index in 0..=grid.rows.len() + 1 {
        let y = (index as f64 * ROW_HEIGHT).clamp(inset, height - inset);
        elements.push(line(0.0, y, OVERALL_WIDTH, y));
    }
    elements.push(line(inset, 0.0, inset, height));
    for index in 0..=grid.columns.len() {
        let x = (LABEL_COL_WIDTH + index as f64 * col_width).clamp(inset, OVERALL_WIDTH - inset);
        elements.push(line(x, 0.0, x, height));
    }

    // A percentage width with the content height keeps the table at 1:1 and
    // centred in its container, which is how the published tables read. Below
    // `OVERALL_WIDTH` of available width it shrinks and leaves vertical padding,
    // the trade-off that comes with the centring.
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" \
         width=\"100%\" height=\"{height}\" \
         viewBox=\"0 0 {OVERALL_WIDTH} {height}\" \
         preserveAspectRatio=\"xMidYMid meet\">\n{}\n</svg>\n",
        elements.join("\n")
    )
}

fn rect(x: f64, y: f64, width: f64, height: f64, fill: &str) -> String {
    format!("  <rect x=\"{x}\" y=\"{y}\" width=\"{width}\" height=\"{height}\" fill=\"{fill}\"/>")
}

fn line(x1: f64, y1: f64, x2: f64, y2: f64) -> String {
    format!(
        "  <line x1=\"{x1}\" y1=\"{y1}\" x2=\"{x2}\" y2=\"{y2}\" \
         stroke=\"{WHITE}\" stroke-width=\"{BORDER_WIDTH}\"/>"
    )
}

fn text(x: f64, y: f64, content: &str, anchor: &str, fill: &str, bold: bool) -> String {
    let weight = if bold { "bold" } else { "normal" };
    format!(
        "  <text x=\"{x}\" y=\"{y}\" dominant-baseline=\"middle\" text-anchor=\"{anchor}\" \
         font-family=\"{FONT_FAMILY}\" font-size=\"{FONT_SIZE}\" fill=\"{fill}\" \
         font-weight=\"{weight}\">{}</text>",
        escape(content)
    )
}

/// `&` first, or it would escape the ampersands of the other entities.
fn escape(s: &str) -> String {
    s.replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('|', "&#124;")
}
