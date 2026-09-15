//! The pieces the panels share: a dropdown that knows when not to be one, a
//! cross that does not depend on a font, and the sizing of the browse line.

use eframe::egui;

use benchmark_spec::BenchmarkMetric;

/// Draws the browse line a notch larger than the rest of the window: it is what
/// everything else follows from, and its checkboxes are the smallest targets in
/// the app. Absolute sizes rather than a multiplier, so that applying it twice,
/// as the menus do, changes nothing.
pub fn enlarge(ui: &mut egui::Ui) {
    let style = ui.style_mut();
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(17.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(17.0));

    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.interact_size.y = 26.0;
    // The tick box and the tick inside it.
    style.spacing.icon_width = 20.0;
    style.spacing.icon_width_inner = 11.0;
}

/// Taller than this and a menu scrolls instead of running off the screen.
pub const MENU_MAX_HEIGHT: f32 = 340.0;

/// The body of a menu whose entries are a list.
///
/// A menu opens in its own area: it inherits nothing from the line that spawned
/// it, and, unlike a combo box, it does not scroll on its own. A level holding
/// forty operations would be unreachable at both ends.
pub fn menu_list(ui: &mut egui::Ui, min_width: f32, body: impl FnOnce(&mut egui::Ui)) {
    enlarge(ui);
    ui.set_min_width(min_width);
    egui::ScrollArea::vertical()
        .max_height(MENU_MAX_HEIGHT)
        .show(ui, body);
}

/// A dropdown when there is a choice, plain text when there is not.
pub fn dimension<T, F>(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash,
    values: &[T],
    current: &T,
    target: &mut Option<T>,
    width: f32,
    label: F,
) where
    T: PartialEq + Clone,
    F: Fn(&T) -> String,
{
    // Not a choice, so not a control: one option reads as plain text.
    if values.len() < 2 {
        ui.label(egui::RichText::new(label(current)).weak());
        return;
    }

    egui::ComboBox::new(id, "")
        .selected_text(label(current))
        .width(width)
        .show_ui(ui, |ui| {
            for value in values {
                if ui
                    .selectable_label(value == current, label(value))
                    .clicked()
                {
                    *target = Some(value.clone());
                }
            }
        });
}

/// A square button with a cross painted in it. Painted rather than written:
/// none of the fonts egui ships carries a cross, and a missing glyph shows up
/// as a box.
pub fn close_button(ui: &mut egui::Ui) -> egui::Response {
    let side = ui.spacing().interact_size.y;
    let (rect, response) = ui.allocate_exact_size(egui::Vec2::splat(side), egui::Sense::click());

    let visuals = *ui.style().interact(&response);
    let painter = ui.painter();
    painter.rect_filled(rect, 3.0, visuals.weak_bg_fill);

    let cross = rect.shrink(side * 0.32);
    let stroke = egui::Stroke::new(1.6, visuals.fg_stroke.color);
    painter.line_segment([cross.left_top(), cross.right_bottom()], stroke);
    painter.line_segment([cross.right_top(), cross.left_bottom()], stroke);

    response
}

pub fn metric_name(metric: BenchmarkMetric) -> &'static str {
    match metric {
        BenchmarkMetric::Latency => "latency",
        BenchmarkMetric::Throughput => "throughput",
        BenchmarkMetric::PbsCount => "pbs count",
        BenchmarkMetric::KeySize => "key size",
    }
}

/// An empty parameter set or run variant is a value, not a missing one.
pub fn or_none(value: &str) -> String {
    if value.is_empty() {
        "(none)".to_string()
    } else {
        value.to_string()
    }
}
