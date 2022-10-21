use super::engine_error;
use crate::core_crypto::prelude::LweSize;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorCreationError for LweCiphertextVectorCreationEngine @
    EmptyContainer => "The container used to create the LWE ciphertext vector is of length 0!"
}

impl<EngineError: std::error::Error> LweCiphertextVectorCreationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(container_length: usize) -> Result<(), Self> {
        if container_length == 0 {
            return Err(Self::EmptyContainer);
        }
        Ok(())
    }
}

/// A trait for engines creating an LWE ciphertext vector from an arbitrary container.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation creates an LWE ciphertext vector from the
/// arbitrary `container`. By arbitrary here, we mean that `Container` can be any type that
/// allows to
/// instantiate an `LweCiphertextVectorEntity`.
pub trait LweCiphertextVectorCreationEngine<Container, CiphertextVector>: AbstractEngine
where
    CiphertextVector: LweCiphertextVectorEntity,
{
    /// Creates an LWE ciphertext from an arbitrary container.
    fn create_lwe_ciphertext_vector_from(
        &mut self,
        container: Container,
        lwe_size: LweSize,
    ) -> Result<CiphertextVector, LweCiphertextVectorCreationError<Self::EngineError>>;

    /// Unsafely creates an LWE ciphertext vector from an arbitrary container.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorCreationError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn create_lwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: Container,
        lwe_size: LweSize,
    ) -> CiphertextVector;
}
