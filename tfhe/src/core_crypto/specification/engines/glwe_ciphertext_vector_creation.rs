use super::engine_error;
use crate::core_crypto::prelude::{GlweDimension, GlweSize, PolynomialSize};
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::GlweCiphertextVectorEntity;

engine_error! {
    GlweCiphertextVectorCreationError for GlweCiphertextVectorCreationEngine @
    EmptyContainer => "The container used to create the GLWE ciphertext is of length 0!",
    InvalidContainerSize => "The length of the container used to create the GLWE ciphertext \
    needs to be a multiple of `polynomial_size`."
}

impl<EngineError: std::error::Error> GlweCiphertextVectorCreationError<EngineError> {
    /// Validates the inputs, the container is expected to have a length of
    /// glwe_size * polynomial_size, during construction we only get the container and the
    /// polynomial size so we check the length is consistent, the GLWE size is deduced by the
    /// ciphertext implementation from the container and the polynomial size.
    pub fn perform_generic_checks(
        container_length: usize,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
    ) -> Result<(), Self> {
        if container_length == 0 {
            return Err(Self::EmptyContainer);
        }
        if container_length % (polynomial_size.0 * glwe_size.0) != 0 {
            return Err(Self::InvalidContainerSize);
        }

        Ok(())
    }
}

/// A trait for engines creating a GLWE ciphertext vector from an arbitrary container.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation creates a GLWE ciphertext vector from the
/// arbitrary `container`. By arbitrary here, we mean that `Container` can be any type that
/// allows to
/// instantiate a `GlweCiphertextVectorEntity`.
pub trait GlweCiphertextVectorCreationEngine<Container, CiphertextVector>: AbstractEngine
where
    CiphertextVector: GlweCiphertextVectorEntity,
{
    /// Creates a GLWE ciphertext vector from an arbitrary container.
    fn create_glwe_ciphertext_vector_from(
        &mut self,
        container: Container,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<CiphertextVector, GlweCiphertextVectorCreationError<Self::EngineError>>;

    /// Unsafely creates a GLWE ciphertext vector from an arbitrary container.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorCreationError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn create_glwe_ciphertext_vector_from_unchecked(
        &mut self,
        container: Container,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> CiphertextVector;
}
