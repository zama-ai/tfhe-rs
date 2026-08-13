//! The report humans read: a PR comment, a run summary, an artifact.
//!
//! Only the columns `nightly` produced make it to the table on top, since they
//! are the only ones this branch can move. The exhaustive one is folded away
//! right below, for whoever wants the whole picture.

use std::fmt::Write;

use crate::baseline::{BASELINE_FILE, BaselineDiff, describe_key};
use crate::matrix::Matrix;
use crate::outcome::{Outcome, single_line};

/// Make a failure reason safe to inline in a markdown table cell.
fn sanitize(detail: &str) -> String {
    single_line(detail).replace('|', "\\|")
}

impl Matrix {
    pub fn render_markdown(&self, diff: Option<&BaselineDiff>) -> String {
        let mut out = String::new();
        out.push_str("## Forward Compatibility Matrix\n\n");
        out.push_str(
            "Which released versions can load data produced by this branch. \
             A :x: is not a failure by itself: it only means forward compatibility \
             is not (or no longer) provided for that type. What matters is whether \
             it was reviewed.\n\n",
        );

        if let Some(diff) = diff {
            out.push_str(&Self::render_baseline_verdict(diff));
            out.push('\n');
        }

        let cols = self.nightly_cols();
        let notes = self.failure_notes(&cols);
        let headers: Vec<String> = cols
            .iter()
            .map(|&col| self.versions[self.directions[col].1].clone())
            .collect();

        out.push_str(&self.render_table(&cols, &headers, |cell| match cell {
            None => "-".to_string(),
            Some(outcome) if outcome.ok => ":white_check_mark:".to_string(),
            Some(outcome) => match notes.iter().position(|n| *n == sanitize(&outcome.detail)) {
                Some(idx) => format!(":x: ({})", idx + 1),
                None => ":x:".to_string(),
            },
        }));

        if !notes.is_empty() {
            out.push('\n');
            for (idx, note) in notes.iter().enumerate() {
                let _ = writeln!(out, "{}. {note}", idx + 1);
            }
        }

        let all_cols: Vec<usize> = (0..self.directions.len()).collect();
        let all_headers: Vec<String> = all_cols.iter().map(|&col| self.col_label(col)).collect();
        out.push_str("\n<details>\n<summary>Full matrix (every version pair)</summary>\n\n");
        out.push_str(&self.render_table(&all_cols, &all_headers, Self::cell_str));
        out.push_str("\n</details>\n");
        out
    }

    fn render_baseline_verdict(diff: &BaselineDiff) -> String {
        if diff.is_empty() {
            return ":white_check_mark: **Unchanged**: the matrix matches the committed baseline.\n"
                .to_string();
        }

        let mut out = String::new();
        if diff.has_status_changes() {
            out.push_str(":warning: **The matrix moved compared to the committed baseline.**\n\n");
            for (key, was, now) in &diff.changed {
                let _ = writeln!(out, "- {} : `{was}` → `{now}`", describe_key(key));
            }
            for (key, now) in &diff.added {
                let _ = writeln!(out, "- {} : new cell, `{now}`", describe_key(key));
            }
            for (key, was) in &diff.removed {
                let _ = writeln!(out, "- {} : cell gone, was `{was}`", describe_key(key));
            }
        } else {
            out.push_str(
                ":information_source: **Same statuses as the baseline, but a failure \
                 now reports a different reason.**\n\n",
            );
        }

        if !diff.reason_changed.is_empty() {
            out.push_str("\n<details>\n<summary>Reasons that changed</summary>\n\n");
            for (key, was, now) in &diff.reason_changed {
                let _ = writeln!(
                    out,
                    "- {}\n  - was: {was}\n  - now: {now}",
                    describe_key(key)
                );
            }
            out.push_str("\n</details>\n");
        }

        let _ = write!(
            out,
            "\nIf these changes are intended, run `make generate_forward_compat_matrix` \
             and commit `{BASELINE_FILE}`.\n"
        );
        out
    }

    fn col_label(&self, col: usize) -> String {
        let (producer, consumer) = self.directions[col];
        format!(
            "{} loads {} data",
            self.versions[consumer], self.versions[producer]
        )
    }

    /// The exhaustive table is folded away, so it can afford the whole reason.
    fn cell_str(cell: &Option<Outcome>) -> String {
        match cell {
            None => "-".to_string(),
            Some(outcome) if outcome.ok => "OK".to_string(),
            Some(outcome) => {
                let reason = sanitize(&outcome.detail);
                if reason.is_empty() {
                    "FAIL".to_string()
                } else {
                    format!("FAIL: {reason}")
                }
            }
        }
    }

    /// Failure reasons found in `cols`, deduplicated, in order of first appearance.
    fn failure_notes(&self, cols: &[usize]) -> Vec<String> {
        let mut notes: Vec<String> = Vec::new();
        for (_, cells) in &self.rows {
            for outcome in cols.iter().filter_map(|&col| cells[col].as_ref()) {
                let reason = sanitize(&outcome.detail);
                if !outcome.ok && !reason.is_empty() && !notes.contains(&reason) {
                    notes.push(reason);
                }
            }
        }
        notes
    }

    fn render_table(
        &self,
        cols: &[usize],
        headers: &[String],
        cell: impl Fn(&Option<Outcome>) -> String,
    ) -> String {
        let mut out = String::new();
        out.push_str("| TYPE |");
        for header in headers {
            let _ = write!(out, " {header} |");
        }
        out.push_str("\n| --- |");
        for _ in headers {
            out.push_str(" --- |");
        }
        out.push('\n');
        for (name, cells) in &self.rows {
            let _ = write!(out, "| {name} |");
            for &col in cols {
                let _ = write!(out, " {} |", cell(&cells[col]));
            }
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::diff_baseline;
    use crate::test_fixtures::{key, matrix};

    #[test]
    fn identical_failure_reasons_share_a_single_note() {
        let matrix = matrix();
        assert_eq!(matrix.failure_notes(&matrix.nightly_cols()), vec!["boom"]);

        let rendered = matrix.render_markdown(None);

        assert_eq!(rendered.matches(":x: (1)").count(), 2);
        assert_eq!(rendered.matches("1. boom").count(), 1);
    }

    #[test]
    fn the_summary_table_leaves_the_released_pairs_to_the_details() {
        let rendered = matrix().render_markdown(None);
        let (summary, details) = rendered.split_once("<details>").unwrap();

        assert!(!summary.contains("1.5.5 loads 1.6.3 data"));
        assert!(details.contains("1.5.5 loads 1.6.3 data"));
    }

    #[test]
    fn a_matching_baseline_is_stated_in_one_line() {
        let baseline = matrix().baseline();
        let diff = diff_baseline(&baseline, &baseline);

        assert!(Matrix::render_baseline_verdict(&diff).contains("Unchanged"));
    }

    #[test]
    fn a_status_that_moved_is_spelled_out() {
        let current = matrix().baseline();
        let mut reviewed = current.clone();
        reviewed.get_mut(&key("A", "1.5.5")).unwrap().status = "OK".to_string();

        let verdict = Matrix::render_baseline_verdict(&diff_baseline(&reviewed, &current));

        assert!(verdict.contains("1.5.5 loads nightly data"));
        assert!(verdict.contains("`OK` → `FAIL`"));
        assert!(verdict.contains(BASELINE_FILE));
    }

    #[test]
    fn a_reason_that_moved_alone_is_reported_without_a_warning() {
        let current = matrix().baseline();
        let mut reviewed = current.clone();
        reviewed.get_mut(&key("A", "1.5.5")).unwrap().reason = "was something else".to_string();

        let verdict = Matrix::render_baseline_verdict(&diff_baseline(&reviewed, &current));

        assert!(verdict.contains("different reason"));
        assert!(!verdict.contains(":warning:"));
        assert!(verdict.contains("was: was something else"));
    }
}
