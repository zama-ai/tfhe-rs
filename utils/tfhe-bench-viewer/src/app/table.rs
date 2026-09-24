//! The series table: one row per curve, one column per thing that narrows it
//! down, and the menu that re-points a row at another benchmark.

use eframe::egui;

use crate::catalogue::{Node, join};
use crate::chart;
use crate::data::{Fetch, Store};
use crate::series::{Options, Series};

use super::widgets::{
    MENU_MAX_HEIGHT, close_button, dimension, enlarge, menu_list, metric_name, or_none,
};
use super::{App, free_slot};

/// What narrows a curve down, in the order the row asks for it. Naming the
/// columns is most of what makes a row readable: without a header, a dropdown
/// holding `64 bits` and one holding an alias look alike.
const DIMENSIONS: [&str; 6] = [
    "backend",
    "metric",
    "machine",
    "size",
    "parameters",
    "variant",
];

/// Swatch, path, the dimensions, the point count, then the two buttons.
const COLUMNS: usize = DIMENSIONS.len() + 5;

enum Action {
    Duplicate(usize),
    Remove(usize),
}

impl App {
    pub(super) fn series_table(&mut self, ui: &mut egui::Ui) {
        let Self { fetch, series, .. } = self;
        let Fetch::Ready(store) = fetch else {
            ui.add_space(6.0);
            ui.label(egui::RichText::new("results are not in yet").weak());
            return;
        };

        let dark = ui.visuals().dark_mode;
        let mut action = None;

        // Both directions: the row is wider than most windows, and its columns
        // are only readable if they stay aligned.
        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("series")
                .num_columns(COLUMNS)
                .striped(true)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    let headers = ["", "path"]
                        .into_iter()
                        .chain(DIMENSIONS)
                        .chain(["points", "", ""]);
                    for header in headers {
                        ui.label(egui::RichText::new(header).strong());
                    }
                    ui.end_row();

                    for (index, serie) in series.iter_mut().enumerate() {
                        row(ui, index, serie, store, dark, &mut action);
                    }
                });
        });

        match action {
            Some(Action::Remove(index)) => {
                series.remove(index);
            }
            Some(Action::Duplicate(index)) => duplicate(series, index, store),
            None => {}
        }
    }
}

fn row(
    ui: &mut egui::Ui,
    index: usize,
    serie: &mut Series,
    store: &Store,
    dark: bool,
    action: &mut Option<Action>,
) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(12.0), egui::Sense::hover());
        ui.painter()
            .rect_filled(rect, 2.0, chart::series_color(serie.color_slot, dark));
        ui.checkbox(&mut serie.visible, "");
    });

    let path = serie.path();
    if serie.raw {
        ui.label(egui::RichText::new(path).monospace());
    } else {
        // Re-pointable in place: a row built with a machine and a parameter set
        // can be aimed at the next operation without being rebuilt.
        ui.menu_button(egui::RichText::new(path.clone()).monospace(), |ui| {
            repoint_menu(ui, &store.tree, &path, &mut |picked| {
                serie.segments = picked.split("::").map(str::to_string).collect();
            });
        });
    }

    match serie.options(store) {
        Some(options) => {
            dimensions(ui, index, serie, &options);
            ui.label(egui::RichText::new(format!("{}", options.matching)).weak());
        }
        None => {
            ui.label(egui::RichText::new("no result under this path").weak());
            // The grid has no colspan, so the row is filled out by hand.
            for _ in 0..DIMENSIONS.len() {
                ui.label("");
            }
        }
    }

    if ui
        .button("+")
        .on_hover_text("same path, another backend")
        .clicked()
    {
        *action = Some(Action::Duplicate(index));
    }
    if close_button(ui).on_hover_text("remove").clicked() {
        *action = Some(Action::Remove(index));
    }
    ui.end_row();
}

/// One control per dimension, each offering only what the dimensions before it
/// left available. Emits exactly one grid cell per dimension.
fn dimensions(ui: &mut egui::Ui, index: usize, serie: &mut Series, options: &Options) {
    let resolved = &options.resolved;

    match resolved.backend {
        Some(backend) => dimension(
            ui,
            (index, "backend"),
            &options.backends,
            &backend,
            &mut serie.backend,
            90.0,
            |backend| backend.to_string(),
        ),
        // Guessing one would invent what the reader came here to find out.
        None => {
            ui.label(egui::RichText::new("unknown").weak());
        }
    }

    dimension(
        ui,
        (index, "metric"),
        &options.metrics,
        &resolved.metric,
        &mut serie.metric,
        110.0,
        // A metric nothing in the id supports is a declaration, not a reading,
        // and the control says so.
        |metric| {
            let name = metric_name(*metric);
            if resolved.metric_known {
                name.to_string()
            } else {
                format!("{name}?")
            }
        },
    );
    dimension(
        ui,
        (index, "machine"),
        &options.machines,
        &resolved.machine,
        &mut serie.machine,
        170.0,
        Clone::clone,
    );
    dimension(
        ui,
        (index, "bits"),
        &options.bits,
        &resolved.bits,
        &mut serie.bits,
        80.0,
        |bits| format!("{bits} bits"),
    );
    dimension(
        ui,
        (index, "params"),
        &options.params,
        &resolved.params,
        &mut serie.params,
        260.0,
        |params| or_none(params),
    );
    dimension(
        ui,
        (index, "variant"),
        &options.variants,
        &resolved.variant,
        &mut serie.variant,
        150.0,
        |variant| or_none(variant),
    );
}

/// Re-pointing a row: its neighbours, flat, one click away.
///
/// Swapping one operation for the next is a sibling move, so the siblings are
/// the menu. Walking back down from the root would cost four hovers to land one
/// level from where it started; the whole tree is still there, one entry lower.
fn repoint_menu(ui: &mut egui::Ui, root: &Node, current: &str, pick: &mut dyn FnMut(&str)) {
    enlarge(ui);
    ui.set_min_width(260.0);

    let (prefix, _) = current.rsplit_once("::").unwrap_or(("", current));
    if let Some(parent) = root.find(prefix) {
        // Outside the scrolled part: the family names the list, and `elsewhere`
        // has to stay reachable however long that list is.
        ui.label(egui::RichText::new(prefix).weak());
        egui::ScrollArea::vertical()
            .max_height(MENU_MAX_HEIGHT)
            .show(ui, |ui| {
                for child in &parent.children {
                    if !child.is_leaf() {
                        continue;
                    }
                    let path = join(prefix, &child.segment);
                    if ui
                        .selectable_label(path == current, child.segment.as_str())
                        .clicked()
                    {
                        pick(&path);
                        ui.close_menu();
                    }
                }
            });
    }

    ui.separator();
    ui.menu_button("elsewhere", |ui| {
        path_menu(ui, root, "", current, &mut *pick);
    });
}

/// The whole tree as one menu, for the rarer move across families.
fn path_menu(
    ui: &mut egui::Ui,
    node: &Node,
    prefix: &str,
    current: &str,
    pick: &mut dyn FnMut(&str),
) {
    menu_list(ui, 220.0, |ui| {
        for child in &node.children {
            let path = join(prefix, &child.segment);
            if child.is_leaf() {
                if ui
                    .selectable_label(path == current, child.segment.as_str())
                    .clicked()
                {
                    pick(&path);
                    ui.close_menu();
                }
            } else {
                ui.menu_button(child.segment.as_str(), |ui| {
                    // Reborrowed: a move would leave nothing for the next branch.
                    path_menu(ui, child, &path, current, &mut *pick);
                });
            }
        }
    });
}

/// Copies a series, switching to another backend when the data holds one: that
/// is the CPU/GPU overlay, in one click.
fn duplicate(series: &mut Vec<Series>, index: usize, store: &Store) {
    let Some(slot) = free_slot(series) else {
        return;
    };

    let source = &series[index];
    let mut copy = Series::new(slot);
    copy.segments = source.segments.clone();
    copy.raw = source.raw;
    copy.backend = source.backend;
    copy.metric = source.metric;
    copy.machine = source.machine.clone();
    copy.bits = source.bits;
    copy.params = source.params.clone();
    copy.variant = source.variant.clone();

    if let Some(options) = copy.options(store) {
        let current = options.resolved.backend;
        if let Some(other) = options.backends.into_iter().find(|b| Some(*b) != current) {
            copy.backend = Some(other);
            // Another backend runs on another machine, with its own parameters.
            copy.machine = None;
            copy.params = None;
        }
    }

    series.push(copy);
}
