//! The window: what it holds, and the panels it is made of.
//!
//! Each panel lives in its own module and takes the whole [`App`], because
//! every one of them reads the fetch and writes the series list. What they do
//! not share is here.

mod browse;
mod files;
mod table;
mod unparsed;
mod widgets;

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};

use eframe::egui;

use benchmark_spec::BenchmarkMetric;

use crate::chart;
use crate::data::{self, Fetch, Store};
use crate::series::Series;

pub struct App {
    db: Result<data::Db, String>,
    fetch: Fetch,
    started: bool,
    days: i32,
    log_scale: bool,
    show_unparsed: bool,
    unparsed_filter: String,
    /// The branches the browse line is currently walked into. Holds no leaf: a
    /// leaf is not navigated to, it is ticked.
    browse: Vec<String>,
    /// Stem the saved files are named after. Nothing to name in a browser,
    /// where files come in by being dropped and do not go out.
    #[cfg(not(target_arch = "wasm32"))]
    file_base: String,
    file_status: String,
    tx: Sender<Result<Store, String>>,
    rx: Receiver<Result<Store, String>>,
    series: Vec<Series>,
}

impl App {
    pub fn new(config_file: Option<PathBuf>) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Self {
            db: data::Db::new(config_file).map_err(|err| format!("{err:#}")),
            fetch: Fetch::Idle,
            started: false,
            days: 7,
            log_scale: true,
            show_unparsed: false,
            unparsed_filter: String::new(),
            browse: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            file_base: "bench-view".to_string(),
            file_status: String::new(),
            tx,
            rx,
            series: Vec::new(),
        }
    }

    fn start_fetch(&mut self, ctx: &egui::Context) {
        let Self {
            db,
            fetch,
            tx,
            days,
            ..
        } = self;
        if let Ok(db) = db {
            *fetch = Fetch::Loading;
            db.fetch(*days, tx.clone(), ctx.clone());
        }
    }

    fn drain(&mut self) {
        while let Ok(reply) = self.rx.try_recv() {
            self.fetch = match reply {
                Ok(store) => Fetch::Ready(store),
                Err(err) => Fetch::Failed(err),
            };
        }
    }

    fn store(&self) -> Option<&Store> {
        match &self.fetch {
            Fetch::Ready(store) => Some(store),
            _ => None,
        }
    }

    fn status(&self) -> String {
        if let Err(err) = &self.db {
            return format!("no connection possible: {err}");
        }
        match &self.fetch {
            Fetch::Idle => "nothing loaded".to_string(),
            Fetch::Loading => "loading…".to_string(),
            Fetch::Failed(err) => format!("failed: {err}"),
            Fetch::Ready(store) => format!(
                "{} rows over {} days, {} paths",
                store.fetched,
                store.days,
                store.paths(),
            ),
        }
    }

    /// What the plots draw. Resolving a series is what decides which of the two
    /// boxes it belongs to, so it happens once, here.
    fn curves(&self) -> Vec<chart::Curve> {
        let Some(store) = self.store() else {
            return Vec::new();
        };

        self.series
            .iter()
            .filter(|serie| serie.visible)
            .filter_map(|serie| {
                let options = serie.options(store)?;
                let resolved = &options.resolved;

                let id = serie.id_prefix(resolved);
                let mut tail = format!("{} bits · {}", resolved.bits, resolved.machine);
                if !resolved.variant.is_empty() {
                    tail.push_str(&format!(" · {}", resolved.variant));
                }
                if !resolved.metric_known {
                    tail.push_str(" · metric assumed");
                }

                Some(chart::Curve {
                    // The tooltip has room to breathe, a legend row has not.
                    label: format!("{id}\n{tail}"),
                    legend: format!("{id} · {tail}"),
                    color_slot: serie.color_slot,
                    metric: resolved.metric,
                    samples: serie.curve(store, resolved),
                })
            })
            .collect()
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            let busy = matches!(self.fetch, Fetch::Loading);
            let button = egui::Button::new("Fetch");
            if ui.add_enabled(self.db.is_ok() && !busy, button).clicked() {
                self.start_fetch(ctx);
            }
            ui.add(egui::DragValue::new(&mut self.days).speed(1.0));
            self.days = self.days.clamp(1, 365);
            ui.label("days back");
            if busy {
                ui.spinner();
            }
            ui.label(egui::RichText::new(self.status()).weak());

            // What the spec has yet to cover. A count nobody can act on is not
            // worth printing, so it opens the list.
            let unparsed = self.store().map_or(0, |store| store.unparsed.len());
            if unparsed > 0
                && ui
                    .button(format!("{unparsed} unparsed ids"))
                    .on_hover_text("stored ids the current grammar does not parse")
                    .clicked()
            {
                self.show_unparsed = true;
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Clear all").clicked() {
                    self.series.clear();
                }
                ui.checkbox(&mut self.log_scale, "Log scale");
            });
        });
    }

    fn plots(&mut self, ui: &mut egui::Ui) {
        let curves = self.curves();
        let loaded = self.store().is_some();
        // Two boxes rather than one plot with a metric switch: nanoseconds and
        // operations per second do not share an axis.
        let height = ((ui.available_height() - 60.0) / 2.0).max(90.0);

        chart::show(
            ui,
            "Latency",
            BenchmarkMetric::Latency,
            &curves,
            loaded,
            self.log_scale,
            height,
        );
        ui.add_space(8.0);
        chart::show(
            ui,
            "Throughput",
            BenchmarkMetric::Throughput,
            &curves,
            loaded,
            self.log_scale,
            height,
        );
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain();
        self.take_drop(ctx);
        if !self.started {
            self.started = true;
            // egui's default sizing is tuned for a dense tool window; this one
            // is read at arm's length. Ctrl + and Ctrl - still work from here.
            ctx.set_zoom_factor(1.2);
            self.start_fetch(ctx);
        }

        // Three fixed-height rows, in the order they stack: what to fetch,
        // what to write, what to look at.
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(4.0);
            self.toolbar(ui, ctx);
            ui.add_space(4.0);
        });
        egui::TopBottomPanel::top("files").show(ctx, |ui| {
            ui.add_space(4.0);
            self.file_line(ui);
            ui.add_space(4.0);
        });
        egui::TopBottomPanel::top("browse").show(ctx, |ui| {
            ui.add_space(4.0);
            self.browse_line(ui);
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::top("series")
            .resizable(true)
            .default_height(240.0)
            .show(ctx, |ui| self.series_table(ui));

        self.unparsed_window(ctx);

        egui::CentralPanel::default().show(ctx, |ui| self.plots(ui));
    }
}

/// The lowest colour slot no series holds. Slots are never reused by rank, so
/// removing a series leaves the others' colours alone.
fn free_slot(series: &[Series]) -> Option<usize> {
    (0..chart::MAX_SERIES).find(|slot| series.iter().all(|s| s.color_slot != *slot))
}
