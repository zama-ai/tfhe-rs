use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// Re-randomization modes.
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerRerandMode {
    LegacyKeyswitch,
    NoKeyswitch,
}

impl SpecLeafNode for IntegerRerandMode {}
