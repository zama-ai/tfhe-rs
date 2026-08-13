//! A matrix small enough to reason about: three versions, so one direction
//! between released versions and two involving nightly, over two artifacts.

use crate::baseline::BaselineKey;
use crate::matrix::{Matrix, NIGHTLY};
use crate::outcome::Outcome;

pub(crate) fn outcome(ok: bool) -> Option<Outcome> {
    Some(Outcome {
        ok,
        detail: if ok { "" } else { "boom" }.to_string(),
    })
}

/// The cell of `artifact` where `consumer` loads nightly data.
pub(crate) fn key(artifact: &str, consumer: &str) -> BaselineKey {
    (
        artifact.to_string(),
        consumer.to_string(),
        NIGHTLY.to_string(),
    )
}

pub(crate) fn matrix() -> Matrix {
    Matrix {
        versions: vec![
            "1.5.5".to_string(),
            "1.6.3".to_string(),
            NIGHTLY.to_string(),
        ],
        directions: vec![(1, 0), (2, 0), (2, 1)],
        rows: vec![
            (
                "A".to_string(),
                vec![outcome(true), outcome(false), outcome(false)],
            ),
            ("B".to_string(), vec![outcome(true), outcome(true), None]),
        ],
    }
}
