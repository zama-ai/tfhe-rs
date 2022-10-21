use super::engine_error;
use crate::core_crypto::prelude::AbstractEntity;
use crate::core_crypto::specification::engines::AbstractEngine;

engine_error! {
    EntityDeserializationError for EntityDeserializationEngine @
}

/// A trait for engines deserializing entities.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an entity containing the
/// deserialization of the `serialized` type.
pub trait EntityDeserializationEngine<Serialized, Entity>: AbstractEngine
where
    Entity: AbstractEntity,
{
    /// Deserializes an entity.
    fn deserialize(
        &mut self,
        serialized: Serialized,
    ) -> Result<Entity, EntityDeserializationError<Self::EngineError>>;

    /// Unsafely deserializes an entity.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`EntityDeserializationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn deserialize_unchecked(&mut self, serialized: Serialized) -> Entity;
}
