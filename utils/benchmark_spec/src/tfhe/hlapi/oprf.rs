use strum::Display;

use crate::traits::SpecNode;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum OprfKind {
    AnyRange,
}

impl SpecNode for OprfKind {}
