use super::engine_error;
use crate::core_crypto::prelude::LweCiphertextRange;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorLoadingError for LweCiphertextVectorLoadingEngine @
    UnorderedInputRange => "The input range bounds must be ordered.",
    OutOfVectorInputRange => "The input vector must contain the input range."
}

impl<EngineError: std::error::Error> LweCiphertextVectorLoadingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<CiphertextVector, SubCiphertextVector>(
        vector: &CiphertextVector,
        range: LweCiphertextRange,
    ) -> Result<(), Self>
    where
        CiphertextVector: LweCiphertextVectorEntity,
        SubCiphertextVector: LweCiphertextVectorEntity,
    {
        if !range.is_ordered() {
            return Err(Self::UnorderedInputRange);
        }

        if range.1 >= vector.lwe_ciphertext_count().0 {
            return Err(Self::OutOfVectorInputRange);
        }
        Ok(())
    }
}

/// A trait for engines loading a sub LWE ciphertext vector from another one.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext vector containing
/// a piece of the `vector` LWE ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorLoadingEngine<CiphertextVector, SubCiphertextVector>:
    AbstractEngine
where
    CiphertextVector: LweCiphertextVectorEntity,
    SubCiphertextVector: LweCiphertextVectorEntity,
{
    /// Loads a subpart of an LWE ciphertext vector.
    fn load_lwe_ciphertext_vector(
        &mut self,
        vector: &CiphertextVector,
        range: LweCiphertextRange,
    ) -> Result<SubCiphertextVector, LweCiphertextVectorLoadingError<Self::EngineError>>;

    /// Unsafely loads a subpart of an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorLoadingError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn load_lwe_ciphertext_vector_unchecked(
        &mut self,
        vector: &CiphertextVector,
        range: LweCiphertextRange,
    ) -> SubCiphertextVector;
}
