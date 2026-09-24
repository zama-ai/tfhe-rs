//! The same plot, as a file someone else can open.
//!
//! Goes through the same [`Canvas`], so the export cannot drift from the
//! window: there is one layout, and this is a second way of writing it down.

use eframe::egui::{Color32, Pos2, Rect, Vec2};

use benchmark_spec::BenchmarkMetric;

use super::{Anchor, Canvas, Curve, Theme, draw, draw_legend};

const WIDTH: f32 = 980.0;
const PLOT_HEIGHT: f32 = 400.0;
const LEGEND_ROW: f32 = 20.0;

/// `None` when the metric has nothing on screen: an empty plot is not a file
/// worth writing, and a reader who got one would have to guess why.
pub fn render(
    title: &str,
    metric: BenchmarkMetric,
    curves: &[&Curve],
    log_scale: bool,
) -> Option<String> {
    if curves.is_empty() {
        return None;
    }

    // A shared file lands on someone else's background, so it carries its own,
    // and the light steps of the palette with it.
    let theme = Theme::light();
    let height = PLOT_HEIGHT + 16.0 + curves.len() as f32 * LEGEND_ROW;
    let frame = Rect::from_min_size(Pos2::ZERO, Vec2::new(WIDTH, PLOT_HEIGHT));

    let mut canvas = SvgCanvas {
        body: String::new(),
    };
    canvas.rect(
        Rect::from_min_size(Pos2::ZERO, Vec2::new(WIDTH, height)),
        theme.surface,
    );
    draw(&mut canvas, frame, title, metric, curves, &theme, log_scale);
    // Under the plot: a legend over the data would cover the very thing it
    // names, and this one has as many rows as there are series.
    draw_legend(
        &mut canvas,
        Pos2::new(16.0, PLOT_HEIGHT + 16.0),
        WIDTH - 32.0,
        curves,
        &theme,
    );

    Some(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{WIDTH}\" height=\"{height}\" \
         viewBox=\"0 0 {WIDTH} {height}\" font-family=\"Arial, Helvetica, sans-serif\">\n{}</svg>\n",
        canvas.body,
    ))
}

struct SvgCanvas {
    body: String,
}

impl Canvas for SvgCanvas {
    fn rect(&mut self, rect: Rect, color: Color32) {
        self.body.push_str(&format!(
            "  <rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"{}\"/>\n",
            rect.left(),
            rect.top(),
            rect.width(),
            rect.height(),
            hex(color),
        ));
    }

    fn line(&mut self, from: Pos2, to: Pos2, width: f32, color: Color32) {
        self.body.push_str(&format!(
            "  <line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"{}\" \
             stroke-width=\"{width}\"/>\n",
            from.x,
            from.y,
            to.x,
            to.y,
            hex(color),
        ));
    }

    fn polyline(&mut self, points: &[Pos2], width: f32, color: Color32) {
        if points.len() < 2 {
            return;
        }
        let path: Vec<String> = points
            .iter()
            .map(|point| format!("{:.1},{:.1}", point.x, point.y))
            .collect();
        self.body.push_str(&format!(
            "  <polyline points=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{width}\" \
             stroke-linejoin=\"round\"/>\n",
            path.join(" "),
            hex(color),
        ));
    }

    fn marker(&mut self, at: Pos2, radius: f32, fill: Color32, ring: Color32) {
        self.body.push_str(&format!(
            "  <circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"{radius}\" fill=\"{}\" stroke=\"{}\" \
             stroke-width=\"2\"/>\n",
            at.x,
            at.y,
            hex(fill),
            hex(ring),
        ));
    }

    fn text(&mut self, at: Pos2, anchor: Anchor, text: &str, size: f32, color: Color32) {
        let (align, baseline, dy) = match anchor {
            Anchor::LeftCenter => ("start", "middle", 0.0),
            Anchor::RightCenter => ("end", "middle", 0.0),
            // egui anchors the top of the line, SVG the baseline.
            Anchor::CenterTop => ("middle", "hanging", size * 0.1),
        };
        self.body.push_str(&format!(
            "  <text x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"{align}\" \
             dominant-baseline=\"{baseline}\" font-size=\"{size}\" fill=\"{}\">{}</text>\n",
            at.x,
            at.y + dy,
            hex(color),
            escape(text),
        ));
    }
}

fn hex(color: Color32) -> String {
    format!("#{:02x}{:02x}{:02x}", color.r(), color.g(), color.b())
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
