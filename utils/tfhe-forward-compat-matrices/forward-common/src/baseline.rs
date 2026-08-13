//! The reviewed state of the matrix, committed in the repository.
//!
//! Losing forward compatibility is a legitimate outcome, so the file is not a
//! list of things that must pass: it is what a human last looked at. Only a
//! status moving away from it means something needs a review.

use std::collections::BTreeMap;
use std::fmt::Write;

/// File holding the reviewed state, next to the per-version crates.
pub const BASELINE_FILE: &str = "matrix.baseline.csv";

/// Kept free of commas so each line stays a single cell wherever the file is
/// rendered as a table.
const BASELINE_HEADER: &str = "\
# Reviewed state of the forward compatibility matrix.
# Regenerate with `make generate_forward_compat_matrix` then commit the changes:
# a FAIL is acceptable but an unreviewed one is not.
# The reason is documentation only. It moves with serde and with the variant
# count of the versioning enums so it never fails the CI on its own.
";

/// Real header row rather than one more comment: review tools show it as the
/// column names it is.
const BASELINE_COLUMNS: &str = "artifact,consumer,producer,status,reason";

/// Identifies one cell of the matrix: (artifact, consumer version, producer version).
pub type BaselineKey = (String, String, String);

/// Reviewed state of every cell, ordered by key so the file diffs cleanly.
pub type Baseline = BTreeMap<BaselineKey, CellState>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellState {
    /// `OK`, `FAIL` or `-`, kept as a string so an unknown token from a newer
    /// baseline parses instead of blowing up.
    pub status: String,
    /// Why it failed, empty for anything else. Never gates.
    pub reason: String,
}

/// A failure reason is full of commas, and the file is rendered as a table by
/// review tools: quote it so it stays one column. Doubling is how csv escapes a
/// quote sitting inside a quoted field.
fn quote(reason: &str) -> String {
    format!("\"{}\"", reason.replace('"', "\"\""))
}

/// Tolerant on purpose: an unquoted field is returned as it is.
fn unquote(field: &str) -> String {
    let field = field.trim();
    field
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .map_or_else(|| field.to_string(), |inner| inner.replace("\"\"", "\""))
}

pub fn describe_key(key: &BaselineKey) -> String {
    let (artifact, consumer, producer) = key;
    format!("`{artifact}` ({consumer} loads {producer} data)")
}

pub fn parse_baseline(content: &str) -> Baseline {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && *line != BASELINE_COLUMNS)
        .filter_map(|line| {
            // The reason comes last and holds commas of its own, so it takes
            // whatever follows the fourth separator.
            let mut fields = line.splitn(5, ',');
            let key = (
                fields.next()?.to_string(),
                fields.next()?.to_string(),
                fields.next()?.to_string(),
            );
            let state = CellState {
                status: fields.next()?.to_string(),
                reason: fields.next().map(unquote).unwrap_or_default(),
            };
            Some((key, state))
        })
        .collect()
}

pub fn render_baseline(baseline: &Baseline) -> String {
    let mut out = String::from(BASELINE_HEADER);
    let _ = writeln!(out, "{BASELINE_COLUMNS}");
    for ((artifact, consumer, producer), state) in baseline {
        let CellState { status, reason } = state;
        let _ = write!(out, "{artifact},{consumer},{producer},{status}");
        // Skip the trailing separator entirely when there is nothing to say.
        if reason.is_empty() {
            out.push('\n');
        } else {
            let _ = writeln!(out, ",{}", quote(reason));
        }
    }
    out
}

#[derive(Debug, Default)]
pub struct BaselineDiff {
    /// Cells whose status moved, as (key, reviewed, current).
    pub changed: Vec<(BaselineKey, String, String)>,
    /// Cells absent from the baseline: a new artifact or a new version.
    pub added: Vec<(BaselineKey, String)>,
    /// Cells the baseline knows about but the run no longer produces.
    pub removed: Vec<(BaselineKey, String)>,
    /// Cells that still fail, but differently. Informational: a variant count or
    /// a serde bump rewrites these messages without anything really moving.
    pub reason_changed: Vec<(BaselineKey, String, String)>,
}

impl BaselineDiff {
    pub fn is_empty(&self) -> bool {
        !self.has_status_changes() && self.reason_changed.is_empty()
    }

    /// Whether a human has to look: this is what the CI gates on.
    pub fn has_status_changes(&self) -> bool {
        !(self.changed.is_empty() && self.added.is_empty() && self.removed.is_empty())
    }
}

pub fn diff_baseline(reviewed: &Baseline, current: &Baseline) -> BaselineDiff {
    let mut diff = BaselineDiff::default();
    for (key, now) in current {
        match reviewed.get(key) {
            None => diff.added.push((key.clone(), now.status.clone())),
            Some(was) if was.status != now.status => {
                diff.changed
                    .push((key.clone(), was.status.clone(), now.status.clone()));
            }
            Some(was) if was.reason != now.reason => {
                diff.reason_changed
                    .push((key.clone(), was.reason.clone(), now.reason.clone()));
            }
            Some(_) => {}
        }
    }
    for (key, was) in reviewed {
        if !current.contains_key(key) {
            diff.removed.push((key.clone(), was.status.clone()));
        }
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{key, matrix};

    #[test]
    fn every_cell_is_recorded_including_the_released_pairs() {
        let baseline = matrix().baseline();

        assert_eq!(baseline.len(), 6);
        assert_eq!(baseline[&key("A", "1.5.5")].status, "FAIL");
        assert_eq!(baseline[&key("A", "1.5.5")].reason, "boom");
        assert_eq!(baseline[&key("B", "1.6.3")].status, "-");
        assert!(baseline[&key("B", "1.6.3")].reason.is_empty());
    }

    #[test]
    fn the_file_format_round_trips() {
        let baseline = matrix().baseline();

        assert_eq!(parse_baseline(&render_baseline(&baseline)), baseline);
    }

    #[test]
    fn a_reason_holding_commas_stays_one_column() {
        let reason = "invalid value: integer `1`, expected variant index 0 <= i < 1";
        let mut baseline = matrix().baseline();
        baseline.get_mut(&key("A", "1.5.5")).unwrap().reason = reason.to_string();

        let rendered = render_baseline(&baseline);

        assert!(rendered.contains(&format!("A,1.5.5,nightly,FAIL,\"{reason}\"")));
        assert_eq!(parse_baseline(&rendered), baseline);
    }

    #[test]
    fn a_reason_holding_quotes_round_trips_too() {
        let reason = r#"unknown variant `x`, expected one of "A", "B""#;
        let mut baseline = matrix().baseline();
        baseline.get_mut(&key("A", "1.5.5")).unwrap().reason = reason.to_string();

        let parsed = parse_baseline(&render_baseline(&baseline));

        assert_eq!(parsed[&key("A", "1.5.5")].reason, reason);
        assert_eq!(parsed, baseline);
    }

    #[test]
    fn neither_the_comments_nor_the_column_row_are_data() {
        let rendered = render_baseline(&Baseline::new());

        assert!(rendered.contains(BASELINE_COLUMNS));
        assert!(parse_baseline(&rendered).is_empty());
    }

    #[test]
    fn an_unquoted_reason_is_still_read() {
        let parsed = parse_baseline("A,1.5.5,nightly,FAIL,plain reason");

        assert_eq!(parsed[&key("A", "1.5.5")].reason, "plain reason");
    }

    #[test]
    fn nothing_moves_against_itself() {
        let baseline = matrix().baseline();

        assert!(diff_baseline(&baseline, &baseline).is_empty());
    }

    #[test]
    fn a_reason_moving_on_its_own_never_gates() {
        let current = matrix().baseline();
        let mut reviewed = current.clone();
        reviewed.get_mut(&key("A", "1.5.5")).unwrap().reason =
            "expected variant index 0 <= i < 2".to_string();

        let diff = diff_baseline(&reviewed, &current);

        assert!(!diff.has_status_changes());
        assert!(!diff.is_empty());
        assert_eq!(diff.reason_changed.len(), 1);
    }

    #[test]
    fn changed_added_and_removed_cells_are_told_apart() {
        let current = matrix().baseline();
        let mut reviewed = current.clone();
        reviewed.get_mut(&key("A", "1.5.5")).unwrap().status = "OK".to_string();
        reviewed.remove(&key("B", "1.5.5"));
        reviewed.insert(
            key("C", "1.5.5"),
            CellState {
                status: "OK".to_string(),
                reason: String::new(),
            },
        );

        let diff = diff_baseline(&reviewed, &current);

        assert_eq!(diff.changed.len(), 1);
        let (changed, was, now) = &diff.changed[0];
        assert_eq!(changed, &key("A", "1.5.5"));
        assert_eq!((was.as_str(), now.as_str()), ("OK", "FAIL"));

        assert_eq!(diff.added.len(), 1);
        assert_eq!(&diff.added[0].0, &key("B", "1.5.5"));
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(&diff.removed[0].0, &key("C", "1.5.5"));
    }
}
