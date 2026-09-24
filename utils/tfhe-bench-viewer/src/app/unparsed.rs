//! The stored ids the spec does not parse, verbatim, with what the parser said
//! about each.
//!
//! Printed raw: the whole point is to read the strings the grammar choked on,
//! so nothing here reformats them. They are plottable all the same, since a
//! failed parse loses the name, not the value.

use eframe::egui;

use crate::data::Fetch;
use crate::series::Series;

use super::{App, free_slot};

impl App {
    pub(super) fn unparsed_window(&mut self, ctx: &egui::Context) {
        let Self {
            fetch,
            show_unparsed,
            unparsed_filter,
            series,
            ..
        } = self;
        let Fetch::Ready(store) = fetch else {
            return;
        };

        let mut plot = None;
        let mut open = *show_unparsed;

        egui::Window::new("Ids outside the grammar")
            .open(&mut open)
            .default_size([880.0, 420.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("filter");
                    ui.text_edit_singleline(&mut *unparsed_filter);
                    if ui.button("clear").clicked() {
                        unparsed_filter.clear();
                    }
                });
                ui.label(
                    egui::RichText::new(format!(
                        "{} distinct ids, {} rows of the {} fetched",
                        store.unparsed.len(),
                        store.unparsed_rows,
                        store.fetched,
                    ))
                    .weak(),
                );
                ui.separator();

                let shown: Vec<&(String, String)> = store
                    .unparsed
                    .iter()
                    .filter(|(name, _)| name.contains(unparsed_filter.as_str()))
                    .collect();

                // Both styles share the row, so the taller one sets its height.
                let row_height = ui
                    .text_style_height(&egui::TextStyle::Monospace)
                    .max(ui.text_style_height(&egui::TextStyle::Body));
                // Virtualised: the list runs into the thousands on a wide
                // window, and only what is on screen is worth laying out.
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show_rows(ui, row_height, shown.len(), |ui, range| {
                        for (name, reason) in &shown[range] {
                            ui.horizontal(|ui| {
                                if ui
                                    .small_button("+")
                                    .on_hover_text("plot it under its stored name")
                                    .clicked()
                                {
                                    plot = Some(name.clone());
                                }
                                ui.label(egui::RichText::new(name.as_str()).monospace());
                                ui.label(egui::RichText::new(reason.as_str()).weak());
                            });
                        }
                    });
            });

        *show_unparsed = open;

        if let Some(id) = plot {
            if let Some(slot) = free_slot(series) {
                series.push(Series::raw(id, slot));
            }
        }
    }
}
