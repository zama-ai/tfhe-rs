use strum::Display;

use crate::traits::SpecLeafNode;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum NoiseSquashingKind {
    NoiseSquash,
    DecompNoiseSquashComp,
}

impl SpecLeafNode for NoiseSquashingKind {}
