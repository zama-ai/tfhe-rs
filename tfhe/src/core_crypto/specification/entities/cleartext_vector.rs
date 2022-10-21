use crate::core_crypto::prelude::CleartextCount;
use crate::core_crypto::specification::entities::markers::CleartextVectorKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a cleartext vector entity.
///
/// # Formal Definition
pub trait CleartextVectorEntity: AbstractEntity<Kind = CleartextVectorKind> {
    /// Returns the number of cleartext contained in the vector.
    fn cleartext_count(&self) -> CleartextCount;
}
