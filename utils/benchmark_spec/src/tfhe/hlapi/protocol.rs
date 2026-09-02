use strum::Display;

use crate::traits::SpecLeafNode;

/// Spans of one protocol transaction, the ERC-7984 whitepaper transfer surrounded by the storage
/// and threshold decryption stages a coprocessor runs around it.
///
/// ```text
/// F1: decompress inputs -> transfer graph -> compress results
/// F2: decompress        -> noise squash   -> compress 128 bit
/// ```
///
/// The `NoRerand` variants only exist to price re-randomization.
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ProtocolKind {
    DecompTransferComp,
    DecompTransferCompNoRerand,
    DecompNoiseSquashComp,
    FullTransaction,
    FullTransactionNoRerand,
}

impl SpecLeafNode for ProtocolKind {}
