//! The browse line: one menu per level of the tree, and the checkbox that turns
//! a benchmark into a series.
//!
//! A level's entries are of two kinds, on purpose: a branch navigates and
//! closes the menu, a benchmark is a checkbox that leaves it open. Plotting
//! `add` and `mul` is two ticks in one menu, not two round trips through it.

use eframe::egui;

use crate::catalogue::{Node, join};
use crate::chart;
use crate::data::Fetch;
use crate::series::Series;

use super::widgets::{enlarge, menu_list};
use super::{App, free_slot};

impl App {
    pub(super) fn browse_line(&mut self, ui: &mut egui::Ui) {
        let Self {
            fetch,
            series,
            browse,
            ..
        } = self;
        let Fetch::Ready(store) = fetch else {
            return;
        };

        // Read once: the menu shows what is plotted while the callback below
        // holds the only mutable borrow of the list.
        let plotted: Vec<String> = series
            .iter()
            .filter(|serie| !serie.raw)
            .map(Series::path)
            .collect();
        let can_add = free_slot(series).is_some();
        let points = |path: &str| store.points.get(path).map_or(0, Vec::len);
        let leaves = LeafState {
            plotted: &plotted,
            can_add,
            points: &points,
        };

        ui.horizontal(|ui| {
            // Before the label, so the whole line grows, not just the menus.
            enlarge(ui);
            ui.label(egui::RichText::new("browse").strong());

            picker(
                ui,
                &store.tree,
                "browse",
                browse,
                &leaves,
                &mut |path: &str, on: bool| {
                    if on {
                        if let Some(slot) = free_slot(series) {
                            let segments = path.split("::").map(str::to_string).collect();
                            series.push(Series::picked(segments, slot));
                        }
                    } else {
                        series.retain(|serie| serie.raw || serie.path() != path);
                    }
                },
            );

            if !can_add {
                ui.label(
                    egui::RichText::new(format!(
                        "{} series at most: past that a categorical palette stops being readable",
                        chart::MAX_SERIES
                    ))
                    .weak(),
                );
            }
        });
    }
}

struct LeafState<'a> {
    plotted: &'a [String],
    can_add: bool,
    points: &'a dyn Fn(&str) -> usize,
}

fn picker(
    ui: &mut egui::Ui,
    root: &Node,
    id: &str,
    segments: &mut Vec<String>,
    leaves: &LeafState<'_>,
    toggle: &mut dyn FnMut(&str, bool),
) {
    enlarge(ui);

    let mut node = root;
    let mut depth = 0;

    while !node.is_leaf() {
        // A single branch is not a choice, so it is written out rather than
        // hidden behind a menu. A single benchmark still needs its checkbox.
        if let [only] = node.children.as_slice() {
            if !only.is_leaf() {
                if segments.get(depth).map(String::as_str) != Some(only.segment.as_str()) {
                    segments.truncate(depth);
                    segments.push(only.segment.clone());
                }
                ui.label(egui::RichText::new(only.segment.as_str()).weak());
                node = only;
                depth += 1;
                continue;
            }
        }

        let prefix = segments[..depth].join("::");
        let current = segments.get(depth).cloned();
        let mut picked = None;

        ui.push_id((id, depth), |ui| {
            ui.menu_button(
                level_label(node, &prefix, current.as_deref(), leaves),
                |ui| {
                    menu_list(ui, 240.0, |ui| {
                        for child in &node.children {
                            if child.is_leaf() {
                                // Reborrowed: a move would leave nothing for the next.
                                leaf_entry(
                                    ui,
                                    &join(&prefix, &child.segment),
                                    &child.segment,
                                    leaves,
                                    &mut *toggle,
                                );
                            } else {
                                let selected = current.as_deref() == Some(child.segment.as_str());
                                if ui
                                    .selectable_label(selected, child.segment.as_str())
                                    .clicked()
                                {
                                    picked = Some(child.segment.clone());
                                    ui.close_menu();
                                }
                            }
                        }
                    });
                },
            );
        });

        if let Some(segment) = picked {
            // A change upstream invalidates everything downstream of it.
            segments.truncate(depth);
            segments.push(segment);
        }

        let Some(next) = segments.get(depth).and_then(|s| node.child(s)) else {
            break;
        };
        node = next;
        depth += 1;
    }

    // A path deeper than the tree is a leftover from an earlier selection.
    segments.truncate(depth);
}

/// A benchmark, and how much of it there is: the count is what says whether
/// ticking it is worth the trouble.
fn leaf_entry(
    ui: &mut egui::Ui,
    path: &str,
    segment: &str,
    leaves: &LeafState<'_>,
    toggle: &mut dyn FnMut(&str, bool),
) {
    let mut on = leaves.plotted.iter().any(|plotted| plotted == path);
    ui.horizontal(|ui| {
        // Disabled is not unticked: a full palette must not look like a
        // benchmark nobody picked.
        let enabled = on || leaves.can_add;
        if ui
            .add_enabled(enabled, egui::Checkbox::new(&mut on, segment))
            .changed()
        {
            toggle(path, on);
        }
        ui.label(egui::RichText::new(format!("{}", (leaves.points)(path))).weak());
    });
}

/// The branch that was taken, or how many of the level's benchmarks are on
/// screen.
fn level_label(node: &Node, prefix: &str, current: Option<&str>, leaves: &LeafState<'_>) -> String {
    if let Some(segment) = current {
        return segment.to_string();
    }

    let plotted = node
        .children
        .iter()
        .filter(|child| child.is_leaf())
        .filter(|child| {
            let path = join(prefix, &child.segment);
            leaves.plotted.iter().any(|plotted| *plotted == path)
        })
        .count();

    if plotted == 0 {
        "select".to_string()
    } else {
        format!("{plotted} plotted")
    }
}
