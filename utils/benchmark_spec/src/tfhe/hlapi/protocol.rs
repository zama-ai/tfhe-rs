use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// Spans of one protocol transaction: F1 is the transfer graph, F2 the noise squashing after it.
///
/// NoRerand variants only exist to price re-randomization by difference.
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum ProtocolKind {
    DecompTransferComp,
    DecompTransferCompNoRerand,
    DecompNoiseSquashComp,
    FullTransaction,
    FullTransactionNoRerand,
}

impl SpecLeafNode for ProtocolKind {}
