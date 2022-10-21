use super::engine_error;
use crate::core_crypto::prelude::AbstractEntity;
use crate::core_crypto::specification::engines::AbstractEngine;

engine_error! {
    EntitySerializationError for EntitySerializationEngine @
}

/// A trait for engines serializing entities.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a value containing the serialization
/// of `entity`.
pub trait EntitySerializationEngine<Entity, Serialized>: AbstractEngine
where
    Entity: AbstractEntity,
{
    /// Serializes an entity.
    fn serialize(
        &mut self,
        entity: &Entity,
    ) -> Result<Serialized, EntitySerializationError<Self::EngineError>>;

    /// Unsafely serializes an entity.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`EntitySerializationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn serialize_unchecked(&mut self, entity: &Entity) -> Serialized;
}
