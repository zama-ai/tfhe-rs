//! One plot box: where everything goes, once, for both the window and the
//! exported file.
//!
//! Hand-drawn rather than pulled from a plotting crate because what this needs
//! is not what they are good at: an axis that switches between log and linear,
//! ticks that come from the data, and a legend that lives outside the box.

mod canvas;
mod format;
mod scale;
mod screen;
mod svg;

pub use canvas::{Anchor, Canvas};
pub use screen::show;
pub use svg::render;

use eframe::egui::{Color32, Pos2, Rect, Vec2};

use benchmark_spec::BenchmarkMetric;

use crate::series::Sample;
use scale::Scale;

/// The reference categorical palette, `(light, dark)` per slot, in fixed order.
/// Validated as a set for both surfaces; re-ordering it invalidates that.
const PALETTE: [(u32, u32); 8] = [
    (0x2a78d6, 0x3987e5),
    (0xeb6834, 0xd95926),
    (0x1baf7a, 0x199e70),
    (0xeda100, 0xc98500),
    (0xe87ba4, 0xd55181),
    (0x008300, 0x008300),
    (0x4a3aa7, 0x9085e9),
    (0xe34948, 0xe66767),
];

/// Past eight, a categorical palette stops being readable. The answer is
/// faceting, not a ninth generated hue, so the app caps instead of cycling.
pub const MAX_SERIES: usize = PALETTE.len();

/// Room for the title above and the Y labels to the left of the plot, then for
/// the dates below it.
const TOP_LEFT_GUTTER: Vec2 = Vec2 { x: 94.0, y: 34.0 };
const BOTTOM_RIGHT_MARGIN: Vec2 = Vec2 { x: 16.0, y: 28.0 };

pub fn series_color(slot: usize, dark: bool) -> Color32 {
    let (light, night) = PALETTE[slot % PALETTE.len()];
    let hex = if dark { night } else { light };
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

/// A drawable series: what it is called, what colour it wears, and its points.
pub struct Curve {
    /// Several lines, for the tooltip.
    pub label: String,
    /// One line, for the exported legend.
    pub legend: String,
    pub color_slot: usize,
    pub metric: BenchmarkMetric,
    pub samples: Vec<Sample>,
}

/// The four colours a plot needs. Taken from the window on screen, fixed for an
/// export: a shared file has to read on someone else's background.
pub struct Theme {
    pub surface: Color32,
    pub grid: Color32,
    pub ink: Color32,
    pub muted: Color32,
    pub dark: bool,
}

impl Theme {
    pub fn light() -> Self {
        Self {
            surface: Color32::from_rgb(0xfc, 0xfc, 0xfb),
            grid: Color32::from_rgb(0xdd, 0xdd, 0xda),
            ink: Color32::from_rgb(0x0b, 0x0b, 0x0b),
            muted: Color32::from_rgb(0x52, 0x51, 0x4e),
            dark: false,
        }
    }
}

/// A drawn point, kept so the caller can match a pointer to it.
pub struct Marker {
    pub at: Pos2,
    pub curve: usize,
    pub sample: usize,
}

/// Lays the plot out and draws it. The only place that knows where anything
/// goes, on screen and in an export alike.
pub fn draw(
    canvas: &mut dyn Canvas,
    frame: Rect,
    title: &str,
    metric: BenchmarkMetric,
    curves: &[&Curve],
    theme: &Theme,
    log_scale: bool,
) -> Vec<Marker> {
    canvas.rect(frame, theme.surface);
    canvas.text(
        frame.min + Vec2::new(10.0, 14.0),
        Anchor::LeftCenter,
        title,
        14.0,
        theme.ink,
    );

    let plot = Rect::from_min_max(frame.min + TOP_LEFT_GUTTER, frame.max - BOTTOM_RIGHT_MARGIN);
    let mut markers = Vec::new();
    if plot.width() < 40.0 || plot.height() < 40.0 {
        return markers;
    }

    let (Some(time), Some(value)) = (
        Scale::span(curves.iter().flat_map(|c| c.samples.iter().map(|s| s.at))),
        Scale::over(
            curves
                .iter()
                .flat_map(|c| c.samples.iter().map(|s| s.value)),
            log_scale,
        ),
    ) else {
        canvas.text(
            frame.center(),
            Anchor::CenterTop,
            "nothing to plot here",
            13.0,
            theme.muted,
        );
        return markers;
    };

    let x_at = |at: f64| plot.left() + time.fraction(at) * plot.width();
    let y_at = |v: f64| plot.bottom() - value.fraction(v) * plot.height();

    // Grid and axes stay recessive: they are a reading aid, not data.
    for tick in value.ticks() {
        let y = y_at(tick);
        canvas.line(
            Pos2::new(plot.left(), y),
            Pos2::new(plot.right(), y),
            1.0,
            theme.grid,
        );
        canvas.text(
            Pos2::new(plot.left() - 8.0, y),
            Anchor::RightCenter,
            &format::value(tick, metric),
            11.0,
            theme.muted,
        );
    }
    canvas.line(plot.left_top(), plot.left_bottom(), 1.0, theme.grid);
    canvas.line(plot.left_bottom(), plot.right_bottom(), 1.0, theme.grid);

    let span_days = (time.high - time.low) / 86_400.0;
    for tick in time.even_ticks(4) {
        let x = x_at(tick);
        canvas.line(
            Pos2::new(x, plot.top()),
            Pos2::new(x, plot.bottom()),
            1.0,
            theme.grid,
        );
        canvas.text(
            Pos2::new(x, plot.bottom() + 6.0),
            Anchor::CenterTop,
            &format::date(tick, span_days > 3.0),
            11.0,
            theme.muted,
        );
    }

    for (index, curve) in curves.iter().enumerate() {
        let color = series_color(curve.color_slot, theme.dark);
        let drawn: Vec<(Pos2, usize)> = curve
            .samples
            .iter()
            .enumerate()
            .filter(|(_, sample)| !log_scale || sample.value > 0.0)
            .map(|(at, sample)| (Pos2::new(x_at(sample.at), y_at(sample.value)), at))
            .collect();

        let points: Vec<Pos2> = drawn.iter().map(|(position, _)| *position).collect();
        canvas.polyline(&points, 2.0, color);

        for (position, sample) in drawn {
            canvas.marker(position, 4.0, color, theme.surface);
            markers.push(Marker {
                at: position,
                curve: index,
                sample,
            });
        }
    }

    markers
}

/// The legend an exported plot carries on its own, since the table it reads
/// from on screen does not travel with it.
pub fn draw_legend(
    canvas: &mut dyn Canvas,
    at: Pos2,
    width: f32,
    curves: &[&Curve],
    theme: &Theme,
) {
    for (row, curve) in curves.iter().enumerate() {
        let y = at.y + row as f32 * 20.0;
        let swatch = Rect::from_min_size(Pos2::new(at.x, y - 5.0), Vec2::new(18.0, 10.0));
        canvas.rect(swatch, series_color(curve.color_slot, theme.dark));
        canvas.text(
            Pos2::new(at.x + 26.0, y),
            Anchor::LeftCenter,
            &elide(&curve.legend, width),
            12.0,
            theme.ink,
        );
    }
}

/// Rough character budget for a width. Good enough for a legend line, and it
/// keeps the export free of a font metrics dependency.
fn elide(text: &str, width: f32) -> String {
    let budget = (width / 6.5) as usize;
    if text.chars().count() <= budget {
        return text.to_string();
    }
    text.chars()
        .take(budget.saturating_sub(1))
        .collect::<String>()
        + "…"
}
