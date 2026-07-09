use strum::Display;

use crate::traits::SpecLeafNode;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum OprfKind {
    AnyRange,
}

impl SpecLeafNode for OprfKind {}
