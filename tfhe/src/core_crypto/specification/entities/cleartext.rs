use crate::core_crypto::specification::entities::markers::CleartextKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a cleartext entity.
///
/// # Formal Definition
pub trait CleartextEntity: AbstractEntity<Kind = CleartextKind> {}
