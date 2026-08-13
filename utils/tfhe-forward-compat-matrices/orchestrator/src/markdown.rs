//! The report humans read: a PR comment, a run summary, an artifact.
//!
//! Only the columns `nightly` produced make it to the table on top, since they
//! are the only ones this branch can move. The exhaustive one is folded away
//! right below, for whoever wants the whole picture.

use std::fmt::Write;

use forward_common::{Outcome, single_line};

use crate::baseline::{BASELINE_FILE, BaselineDiff, describe_key};
use crate::matrix::Matrix;

/// Make a failure reason safe to inline in a markdown table cell.
fn sanitize(detail: &str) -> String {
    single_line(detail).replace('|', "\\|")
}

const TABLE_LEGEND: &str = "Which released versions can load data produced by this branch. \
     A :x: is not a failure by itself: it only means forward compatibility is not \
     (or no longer) provided for that type. What matters is whether it was reviewed.";

impl Matrix {
    pub fn render_markdown(&self, diff: Option<&BaselineDiff>) -> String {
        // Stay to a single line when nothing moved, so that the day it grows
        // into a report people actually notice.
        if diff.is_some_and(BaselineDiff::is_empty) {
            return self.render_unchanged();
        }

        let mut out = String::new();
        out.push_str("## Forward Compatibility Matrix\n\n");
        out.push_str(TABLE_LEGEND);
        out.push_str("\n\n");

        if let Some(diff) = diff {
            out.push_str(&Self::render_baseline_verdict(diff));
            out.push('\n');
        }

        let cols = self.nightly_cols();
        let notes = self.failure_notes(&cols);
        let headers = self.nightly_headers(&cols);

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

    /// Neither the reasons nor the exhaustive table make it here: they describe a
    /// state that was already reviewed and committed.
    fn render_unchanged(&self) -> String {
        let cols = self.nightly_cols();
        let headers = self.nightly_headers(&cols);

        let mut out = String::new();
        out.push_str(
            ":white_check_mark: **Forward compatibility matrix unchanged**: \
             it still matches the committed baseline.\n\n",
        );
        out.push_str("<details>\n<summary>Matrix</summary>\n\n");
        out.push_str(TABLE_LEGEND);
        out.push_str("\n\n");
        out.push_str(&self.render_table(&cols, &headers, Self::tick));
        out.push_str("\n</details>\n");
        out
    }

    fn render_baseline_verdict(diff: &BaselineDiff) -> String {
        let mut out = String::new();
        if diff.has_status_changes() {
            out.push_str(":warning: **The matrix moved compared to the committed baseline.**\n\n");
            for (key, was, now) in &diff.changed {
                let _ = writeln!(out, "- {} : `{was:?}` → `{now:?}`", describe_key(key));
            }
            for (key, now) in &diff.added {
                let _ = writeln!(out, "- {} : new cell, `{now:?}`", describe_key(key));
            }
            for (key, was) in &diff.removed {
                let _ = writeln!(out, "- {} : cell gone, was `{was:?}`", describe_key(key));
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

    /// Consumer versions, the only varying part of the columns nightly produced.
    fn nightly_headers(&self, cols: &[usize]) -> Vec<String> {
        cols.iter()
            .map(|&col| self.versions[self.directions[col].1].clone())
            .collect()
    }

    /// The bare verdict of a cell, with no reference to a reason.
    fn tick(cell: &Option<Outcome>) -> String {
        match cell {
            None => "-".to_string(),
            Some(outcome) if outcome.ok => ":white_check_mark:".to_string(),
            Some(_) => ":x:".to_string(),
        }
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
    use crate::baseline::{Status, diff_baseline};
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
    fn a_matching_baseline_reports_one_line_and_folds_the_rest() {
        let matrix = matrix();
        let baseline = matrix.baseline();

        let rendered = matrix.render_markdown(Some(&diff_baseline(&baseline, &baseline)));
        let (visible, folded) = rendered.split_once("<details>").unwrap();

        assert!(visible.contains("unchanged"));
        assert_eq!(visible.lines().filter(|l| !l.is_empty()).count(), 1);
        // The matrix is there, but stripped of everything already reviewed.
        assert!(folded.contains(":x:"));
        assert!(!rendered.contains("boom"));
        assert!(!rendered.contains("Full matrix"));
    }

    #[test]
    fn a_status_that_moved_is_spelled_out() {
        let current = matrix().baseline();
        let mut reviewed = current.clone();
        reviewed.get_mut(&key("A", "1.5.5")).unwrap().status = Status::Ok;

        let verdict = Matrix::render_baseline_verdict(&diff_baseline(&reviewed, &current));

        assert!(verdict.contains("1.5.5 loads nightly data"));
        assert!(verdict.contains("`Ok` → `Fail`"));
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
