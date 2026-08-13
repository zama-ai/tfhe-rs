//! The reviewed state of the matrix, committed in the repository.
//!
//! Losing forward compatibility is a legitimate outcome, so the file is not a
//! list of things that must pass: it is what a human last looked at. Only a
//! status moving away from it means something needs a review.

use std::collections::BTreeMap;

use ron::ser::PrettyConfig;
use serde::{Deserialize, Serialize};

/// File holding the reviewed state, next to the per-version crates.
pub const BASELINE_FILE: &str = "matrix.baseline.ron";

/// Prepended by hand: the serializer does not emit comments, but the parser
/// skips them for free.
const BASELINE_HEADER: &str = "\
// Reviewed state of the forward compatibility matrix.
// Regenerate with `make generate_forward_compat_matrix` then commit the changes:
// a Fail is acceptable but an unreviewed one is not.
// The `reason` field is documentation only. It moves with serde and with the variant
// count of the versioning enums, so it never fails the CI on its own.
";

/// Identifies one cell of the matrix: (artifact, consumer version, producer version).
pub type BaselineKey = (String, String, String);

/// Reviewed state of every cell, ordered by key so the file diffs cleanly.
pub type Baseline = BTreeMap<BaselineKey, CellState>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Ok,
    Fail,
    /// The pair ran but said nothing about this artifact.
    Missing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellState {
    pub status: Status,
    /// Why it failed, empty for anything else. Never gates.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

pub fn describe_key(key: &BaselineKey) -> String {
    let (artifact, consumer, producer) = key;
    format!("`{artifact}` ({consumer} loads {producer} data)")
}

/// The error only ever reaches a human, so it does not carry ron's type along.
pub fn parse_baseline(content: &str) -> Result<Baseline, String> {
    ron::from_str(content).map_err(|err| err.to_string())
}

pub fn render_baseline(baseline: &Baseline) -> String {
    // Expand the map one entry per line but keep the state it maps to inline:
    // one cell per line is what makes the review diff readable.
    let body = ron::ser::to_string_pretty(baseline, PrettyConfig::new().depth_limit(1))
        .expect("a baseline is always serializable");
    format!("{BASELINE_HEADER}{body}\n")
}

#[derive(Debug, Default)]
pub struct BaselineDiff {
    /// Cells whose status moved, as (key, reviewed, current).
    pub changed: Vec<(BaselineKey, Status, Status)>,
    /// Cells absent from the baseline: a new artifact or a new version.
    pub added: Vec<(BaselineKey, Status)>,
    /// Cells the baseline knows about but the run no longer produces.
    pub removed: Vec<(BaselineKey, Status)>,
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
            None => diff.added.push((key.clone(), now.status)),
            Some(was) if was.status != now.status => {
                diff.changed.push((key.clone(), was.status, now.status));
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
            diff.removed.push((key.clone(), was.status));
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
        assert_eq!(baseline[&key("A", "1.5.5")].status, Status::Fail);
        assert_eq!(baseline[&key("A", "1.5.5")].reason, "boom");
        assert_eq!(baseline[&key("B", "1.6.3")].status, Status::Missing);
        assert!(baseline[&key("B", "1.6.3")].reason.is_empty());
    }

    #[test]
    fn the_file_format_round_trips() {
        let baseline = matrix().baseline();

        assert_eq!(
            parse_baseline(&render_baseline(&baseline)).unwrap(),
            baseline
        );
    }

    #[test]
    fn a_reason_full_of_punctuation_round_trips() {
        let reason = "invalid value: integer `1`, expected one of \"A\", \"B\"\nand more";
        let mut baseline = matrix().baseline();
        baseline.get_mut(&key("A", "1.5.5")).unwrap().reason = reason.to_string();

        let parsed = parse_baseline(&render_baseline(&baseline)).unwrap();

        assert_eq!(parsed[&key("A", "1.5.5")].reason, reason);
        assert_eq!(parsed, baseline);
    }

    #[test]
    fn the_header_comments_are_not_data() {
        let rendered = render_baseline(&Baseline::new());

        assert!(rendered.starts_with("//"));
        assert!(parse_baseline(&rendered).unwrap().is_empty());
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
        reviewed.get_mut(&key("A", "1.5.5")).unwrap().status = Status::Ok;
        reviewed.remove(&key("B", "1.5.5"));
        reviewed.insert(
            key("C", "1.5.5"),
            CellState {
                status: Status::Ok,
                reason: String::new(),
            },
        );

        let diff = diff_baseline(&reviewed, &current);

        assert_eq!(diff.changed.len(), 1);
        let (changed, was, now) = &diff.changed[0];
        assert_eq!(changed, &key("A", "1.5.5"));
        assert_eq!((*was, *now), (Status::Ok, Status::Fail));

        assert_eq!(diff.added.len(), 1);
        assert_eq!(&diff.added[0].0, &key("B", "1.5.5"));
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(&diff.removed[0].0, &key("C", "1.5.5"));
    }
}
