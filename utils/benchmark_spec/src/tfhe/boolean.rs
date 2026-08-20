use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::SpecNode;

pub use super::key_size::KeyKind;

/// Benchmarks of the `boolean` layer: the gates, and the size of the keys they
/// run on.
#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(BooleanBenchKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum BooleanBench {
    And,
    Nand,
    Or,
    Xor,
    Xnor,
    Not,
    Mux,
    Keys(KeyKind),
}

impl SpecNode for BooleanBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        match self {
            BooleanBench::Keys(key) => Some(key),
            BooleanBench::And
            | BooleanBench::Nand
            | BooleanBench::Or
            | BooleanBench::Xor
            | BooleanBench::Xnor
            | BooleanBench::Not
            | BooleanBench::Mux => None,
        }
    }
}

impl FromStr for BooleanBench {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        let kind = BooleanBenchKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown boolean bench: {head}")))?;
        match kind {
            BooleanBenchKind::Keys => Ok(Self::Keys(rest.parse()?)),
            // Leaf variants close the bench path: what follows belongs to the
            // trailing part of the id, not to this node.
            _ if !rest.is_empty() => Err(SpecParseError::Unknown(format!(
                "unexpected {rest:?} after boolean bench {head}"
            ))),
            BooleanBenchKind::And => Ok(Self::And),
            BooleanBenchKind::Nand => Ok(Self::Nand),
            BooleanBenchKind::Or => Ok(Self::Or),
            BooleanBenchKind::Xor => Ok(Self::Xor),
            BooleanBenchKind::Xnor => Ok(Self::Xnor),
            BooleanBenchKind::Not => Ok(Self::Not),
            BooleanBenchKind::Mux => Ok(Self::Mux),
        }
    }
}
