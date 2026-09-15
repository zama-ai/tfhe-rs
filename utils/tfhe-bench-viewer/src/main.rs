//! A local explorer for the tfhe-rs benchmark results.
//!
//! One fetch, then everything is local: the menus only ever offer what that
//! fetch brought back, so a selection that plots nothing is not reachable. The
//! X axis is time, so a series is one benchmark followed across the window
//! rather than a shape across ciphertext sizes.
//!
//! What it holds can leave it: the fetch as a file to hand around, the view as
//! a file to come back to, and a plot as an SVG. The modules are layered, see
//! the README.

mod app;
mod catalogue;
mod chart;
mod data;
mod series;

use eframe::egui;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> eframe::Result<()> {
    // Optional TOML credentials; the DATA_EXTRACTOR_DATABASE_* variables are
    // enough on their own and win over it.
    let config_file = std::env::args().nth(1).map(std::path::PathBuf::from);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1360.0, 900.0]),
        ..Default::default()
    };
    eframe::run_native(
        "tfhe-rs bench viewer",
        options,
        Box::new(|_cc| Ok(Box::new(app::App::new(config_file)))),
    )
}

/// The same window, in a canvas. No database to reach from here, so it opens on
/// an empty view and waits for a snapshot to be dropped on it.
#[cfg(target_arch = "wasm32")]
fn main() {
    use eframe::wasm_bindgen::JsCast as _;

    wasm_bindgen_futures::spawn_local(async {
        let canvas = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.get_element_by_id("viewer"))
            .expect("index.html holds a canvas with id `viewer`")
            .dyn_into::<web_sys::HtmlCanvasElement>()
            .expect("`viewer` is a canvas");

        eframe::WebRunner::new()
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(|_cc| Ok(Box::new(app::App::new(None)))),
            )
            .await
            .expect("failed to start the viewer");
    });
}
