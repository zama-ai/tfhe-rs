use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// Spans of one protocol transaction: TFHEw runs the transfer graph, SNSw the noise squashing.
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
