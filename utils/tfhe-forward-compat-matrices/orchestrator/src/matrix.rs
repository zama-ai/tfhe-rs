//! What every version pair made of every artifact.

use forward_common::{Outcome, single_line};

use crate::baseline::{Baseline, CellState, Status};

/// Label of the version built from the current branch.
pub const NIGHTLY: &str = "nightly";

pub struct Matrix {
    /// Every version taking part, sorted, `nightly` included.
    pub versions: Vec<String>,
    /// The pairs actually run, as (producer, consumer) indices into `versions`.
    pub directions: Vec<(usize, usize)>,
    /// One row per artifact: its name, then one cell per direction.
    pub rows: Vec<(String, Vec<Option<Outcome>>)>,
}

impl Matrix {
    /// Columns where `nightly` produced the data. Every other column pairs two
    /// released versions, so no change on this branch can ever move it.
    pub(crate) fn nightly_cols(&self) -> Vec<usize> {
        (0..self.directions.len())
            .filter(|&col| self.versions[self.directions[col].0] == NIGHTLY)
            .collect()
    }

    fn cell_state(cell: &Option<Outcome>) -> CellState {
        let (status, reason) = match cell {
            None => (Status::Missing, ""),
            Some(outcome) if outcome.ok => (Status::Ok, ""),
            Some(outcome) => (Status::Fail, outcome.detail.as_str()),
        };
        CellState {
            status,
            reason: single_line(reason),
        }
    }

    pub fn baseline(&self) -> Baseline {
        let mut entries = Baseline::new();
        for (name, cells) in &self.rows {
            for (col, &(producer, consumer)) in self.directions.iter().enumerate() {
                let key = (
                    name.clone(),
                    self.versions[consumer].clone(),
                    self.versions[producer].clone(),
                );
                entries.insert(key, Self::cell_state(&cells[col]));
            }
        }
        entries
    }
}

#[cfg(test)]
mod tests {
    use crate::test_fixtures::matrix;

    #[test]
    fn only_the_columns_nightly_produced_can_move() {
        assert_eq!(matrix().nightly_cols(), vec![1, 2]);
    }
}
