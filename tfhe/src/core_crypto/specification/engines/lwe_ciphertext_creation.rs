use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextCreationError for LweCiphertextCreationEngine @
    EmptyContainer => "The container used to create the LWE ciphertext is of length 0!"
}

impl<EngineError: std::error::Error> LweCiphertextCreationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(container_length: usize) -> Result<(), Self> {
        if container_length == 0 {
            return Err(Self::EmptyContainer);
        }
        Ok(())
    }
}

/// A trait for engines creating an LWE ciphertext from an arbitrary container.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation creates an LWE ciphertext from the abitrary
/// `container`. By arbitrary here, we mean that `Container` can be any type that allows to
/// instantiate an `LweCiphertextEntity`.
pub trait LweCiphertextCreationEngine<Container, Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
{
    /// Creates an LWE ciphertext from an arbitrary container.
    fn create_lwe_ciphertext_from(
        &mut self,
        container: Container,
    ) -> Result<Ciphertext, LweCiphertextCreationError<Self::EngineError>>;

    /// Unsafely creates an LWE ciphertext from an arbitrary container.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextCreationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn create_lwe_ciphertext_from_unchecked(&mut self, container: Container) -> Ciphertext;
}
