use std::num::NonZeroU32;

use crate::traits::SpecNode;

#[derive(Debug, Clone, Copy)]
pub enum BitonicShuffleSpec {
    CollisionProbability(f64),
    AttackerAdvantage {
        advantage: f64,
        // Contrary to the param in tfhe-rs we don't have an option here
        // as it can specify num_revealed = num_elements
        num_revealed: NonZeroU32,
    },
}

impl std::fmt::Display for BitonicShuffleSpec {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::CollisionProbability(p) => {
                write!(fmt, "p_{p:e}")
            }
            Self::AttackerAdvantage {
                advantage,
                num_revealed,
            } => {
                write!(fmt, "attacker_advantage::{advantage:e}::{num_revealed}")
            }
        }
    }
}

impl SpecNode for BitonicShuffleSpec {
    fn child(&self) -> Option<&dyn SpecNode> {
        None
    }
}
