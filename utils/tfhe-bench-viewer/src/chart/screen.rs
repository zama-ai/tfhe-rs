//! The plot on screen: the egui half of the canvas, and the hover the file
//! export has no use for.

use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, Vec2};

use benchmark_spec::BenchmarkMetric;

use super::{Anchor, Canvas, Curve, Theme, draw, format};

pub fn show(
    ui: &mut egui::Ui,
    title: &str,
    metric: BenchmarkMetric,
    curves: &[Curve],
    loaded: bool,
    log_scale: bool,
    height: f32,
) {
    let theme = theme_of(ui.visuals());
    let drawn: Vec<&Curve> = curves.iter().filter(|c| c.metric == metric).collect();

    let (response, painter) =
        ui.allocate_painter(Vec2::new(ui.available_width(), height), Sense::hover());

    if drawn.is_empty() {
        painter.rect_filled(response.rect, 0.0, theme.surface);
        painter.text(
            response.rect.center(),
            Align2::CENTER_CENTER,
            if loaded {
                format!("{title}: nothing to plot here")
            } else {
                format!("{title}: load the results to start")
            },
            FontId::proportional(13.0),
            theme.muted,
        );
        return;
    }

    let markers = draw(
        &mut EguiCanvas { painter: &painter },
        response.rect,
        title,
        metric,
        &drawn,
        &theme,
        log_scale,
    );

    let Some(pointer) = response.hover_pos() else {
        return;
    };
    let nearest = markers
        .iter()
        .map(|marker| (marker.at.distance(pointer), marker))
        .filter(|(distance, _)| *distance < 16.0)
        .min_by(|a, b| a.0.total_cmp(&b.0));

    if let Some((_, marker)) = nearest {
        let curve = drawn[marker.curve];
        let sample = &curve.samples[marker.sample];
        painter.circle_stroke(marker.at, 7.0, Stroke::new(1.0, theme.muted));
        response.on_hover_text(format!(
            "{}\n{}\n{}",
            curve.label,
            format::date(sample.at, false),
            format::value(sample.value, metric),
        ));
    }
}

fn theme_of(visuals: &egui::Visuals) -> Theme {
    Theme {
        surface: visuals.extreme_bg_color,
        grid: visuals.widgets.noninteractive.bg_stroke.color,
        ink: visuals.text_color(),
        muted: visuals.weak_text_color(),
        dark: visuals.dark_mode,
    }
}

struct EguiCanvas<'a> {
    painter: &'a egui::Painter,
}

impl Canvas for EguiCanvas<'_> {
    fn rect(&mut self, rect: Rect, color: Color32) {
        self.painter.rect_filled(rect, 0.0, color);
    }

    fn line(&mut self, from: Pos2, to: Pos2, width: f32, color: Color32) {
        self.painter
            .line_segment([from, to], Stroke::new(width, color));
    }

    fn polyline(&mut self, points: &[Pos2], width: f32, color: Color32) {
        self.painter.add(egui::Shape::line(
            points.to_vec(),
            Stroke::new(width, color),
        ));
    }

    fn marker(&mut self, at: Pos2, radius: f32, fill: Color32, ring: Color32) {
        self.painter
            .circle(at, radius, fill, Stroke::new(2.0, ring));
    }

    fn text(&mut self, at: Pos2, anchor: Anchor, text: &str, size: f32, color: Color32) {
        let align = match anchor {
            Anchor::LeftCenter => Align2::LEFT_CENTER,
            Anchor::RightCenter => Align2::RIGHT_CENTER,
            Anchor::CenterTop => Align2::CENTER_TOP,
        };
        self.painter
            .text(at, align, text, FontId::proportional(size), color);
    }
}
