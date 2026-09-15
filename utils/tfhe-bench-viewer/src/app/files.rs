//! What leaves the window: the fetch, the view, and a plot.
//!
//! All three are named after one stem, so that a single field drives them
//! rather than five paths drifting apart.

use eframe::egui;

use crate::data::{Fetch, Store};
use crate::series::Series;

use super::App;

#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};
#[cfg(not(target_arch = "wasm32"))]
use benchmark_spec::BenchmarkMetric;
#[cfg(not(target_arch = "wasm32"))]
use crate::chart;

/// Everything a window holds that is worth finding again tomorrow. Not the
/// data: a view is a handful of choices, and it stays readable next to a
/// snapshot that weighs megabytes.
#[derive(serde::Serialize, serde::Deserialize)]
struct View {
    series: Vec<Series>,
    log_scale: bool,
    days: i32,
}

impl App {
    /// A file dropped on the window, whichever kind it is.
    ///
    /// The only way in on the web, where there is no filesystem to name a path
    /// in, and the shortest one natively. The extension picks the kind: a view
    /// and a snapshot are both JSON, and guessing between them by probing would
    /// turn a typo into a silent no-op.
    pub(super) fn take_drop(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|input| input.raw.dropped_files.clone());
        let Some(file) = dropped.into_iter().next() else {
            return;
        };

        // A browser hands over the bytes, a window manager hands over a path.
        let bytes = match (file.bytes, &file.path) {
            (Some(bytes), _) => Ok(bytes.to_vec()),
            (None, Some(path)) => std::fs::read(path).map_err(anyhow::Error::from),
            (None, None) => Err(anyhow::anyhow!("dropped file has no content")),
        };
        let name = match &file.path {
            Some(path) => path.display().to_string(),
            None => file.name.clone(),
        };

        self.file_status = match bytes.and_then(|bytes| self.take_bytes(&name, &bytes)) {
            Ok(()) => format!("read {name}"),
            Err(err) => format!("{name}: {err:#}"),
        };
    }

    fn take_bytes(&mut self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        if name.ends_with(".view.json") {
            let view: View = serde_json::from_slice(bytes)?;
            self.series = view.series;
            self.log_scale = view.log_scale;
            self.days = view.days;
        } else {
            let store = Store::from_json(bytes)?;
            self.days = store.days;
            self.fetch = Fetch::Ready(store);
        }
        Ok(())
    }

    pub(super) fn file_line(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Writing needs a filesystem, reading does not: the web build keeps
            // the drop and loses the rest.
            #[cfg(not(target_arch = "wasm32"))]
            self.disk_actions(ui);

            ui.label(egui::RichText::new("drop a .data.json or a .view.json here").weak());
            ui.label(egui::RichText::new(&self.file_status).weak());
        });
    }
}

/// The filesystem half of the window, which the web build has no use for.
#[cfg(not(target_arch = "wasm32"))]
impl App {
    fn disk_actions(&mut self, ui: &mut egui::Ui) {
        ui.label("file");
        ui.add(egui::TextEdit::singleline(&mut self.file_base).desired_width(200.0));

        if ui
            .button("Save data")
            .on_hover_text("the whole fetch, to hand to someone with no database access")
            .clicked()
        {
            self.save_data();
        }
        if ui.button("Load data").clicked() {
            self.load_data();
        }
        ui.separator();

        if ui
            .button("Save view")
            .on_hover_text("the series and their settings, not the data")
            .clicked()
        {
            self.save_view();
        }
        if ui.button("Load view").clicked() {
            self.load_view();
        }
        ui.separator();

        if ui.button("Export SVG").clicked() {
            self.export_svg();
        }
        ui.separator();
    }

    fn file(&self, suffix: &str) -> PathBuf {
        PathBuf::from(format!("{}{suffix}", self.file_base))
    }

    fn save_data(&mut self) {
        let path = self.file(".data.json");
        let outcome = match &self.fetch {
            Fetch::Ready(store) => store.save(&path),
            _ => Err(anyhow::anyhow!("nothing loaded to save")),
        };
        self.file_status = report(outcome, &path);
    }

    fn load_data(&mut self) {
        let path = self.file(".data.json");
        self.file_status = match Store::load(&path) {
            Ok(store) => {
                self.days = store.days;
                self.fetch = Fetch::Ready(store);
                format!("read {}", path.display())
            }
            Err(err) => format!("{}: {err:#}", path.display()),
        };
    }

    fn save_view(&mut self) {
        let path = self.file(".view.json");
        let view = View {
            series: std::mem::take(&mut self.series),
            log_scale: self.log_scale,
            days: self.days,
        };
        let outcome = write_json(&path, &view);
        // Handed back rather than cloned: a view holds the series themselves.
        self.series = view.series;
        self.file_status = report(outcome, &path);
    }

    fn load_view(&mut self) {
        let path = self.file(".view.json");
        self.file_status = match read_json::<View>(&path) {
            Ok(view) => {
                self.series = view.series;
                self.log_scale = view.log_scale;
                self.days = view.days;
                format!("read {}", path.display())
            }
            Err(err) => format!("{}: {err:#}", path.display()),
        };
    }

    /// One file per plot that has something in it. An empty plot is not a file
    /// worth writing, and a reader who got one would have to guess why.
    fn export_svg(&mut self) {
        let curves = self.curves();
        let mut written = Vec::new();

        for (title, metric, suffix) in [
            ("Latency", BenchmarkMetric::Latency, "-latency.svg"),
            ("Throughput", BenchmarkMetric::Throughput, "-throughput.svg"),
        ] {
            let drawn: Vec<&chart::Curve> = curves
                .iter()
                .filter(|curve| curve.metric == metric)
                .collect();
            let Some(body) = chart::render(title, metric, &drawn, self.log_scale) else {
                continue;
            };

            let path = self.file(suffix);
            if let Err(err) = std::fs::write(&path, body) {
                self.file_status = format!("{}: {err}", path.display());
                return;
            }
            written.push(path.display().to_string());
        }

        self.file_status = if written.is_empty() {
            "no curve to export".to_string()
        } else {
            format!("wrote {}", written.join(", "))
        };
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// Says what happened, and to which file. A status line that only says "done"
/// leaves the reader hunting for where.
#[cfg(not(target_arch = "wasm32"))]
fn report(outcome: anyhow::Result<()>, path: &Path) -> String {
    match outcome {
        Ok(()) => format!("wrote {}", path.display()),
        Err(err) => format!("{}: {err:#}", path.display()),
    }
}
