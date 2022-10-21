use crate::core_crypto::specification::entities::markers::PlaintextKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a plaintext.
///
/// # Formal Definition
pub trait PlaintextEntity: AbstractEntity<Kind = PlaintextKind> {}
