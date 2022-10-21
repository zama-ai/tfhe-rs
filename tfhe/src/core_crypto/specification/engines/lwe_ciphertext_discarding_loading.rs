use super::engine_error;
use crate::core_crypto::prelude::LweCiphertextIndex;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextEntity, LweCiphertextVectorEntity,
};

engine_error! {
    LweCiphertextDiscardingLoadingError for LweCiphertextDiscardingLoadingEngine @
    LweDimensionMismatch => "The output and input LWE dimension must be the same.",
    IndexTooLarge => "The index must not exceed the size of the vector."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingLoadingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<CiphertextVector, Ciphertext>(
        ciphertext: &Ciphertext,
        vector: &CiphertextVector,
        i: LweCiphertextIndex,
    ) -> Result<(), Self>
    where
        Ciphertext: LweCiphertextEntity,
        CiphertextVector: LweCiphertextVectorEntity,
    {
        if ciphertext.lwe_dimension() != vector.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        if i.0 >= vector.lwe_ciphertext_count().0 {
            return Err(Self::IndexTooLarge);
        }
        Ok(())
    }
}

/// A trait for engines loading (discarding) an LWE ciphertext from a LWE ciphertext vector.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `ciphertext` LWE ciphertext
/// with the `i`th LWE ciphertext of the `vector` LWE ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextDiscardingLoadingEngine<CiphertextVector, Ciphertext>:
    AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
    CiphertextVector: LweCiphertextVectorEntity,
{
    /// Loads an LWE ciphertext from an LWE ciphertext vector.
    fn discard_load_lwe_ciphertext(
        &mut self,
        ciphertext: &mut Ciphertext,
        vector: &CiphertextVector,
        i: LweCiphertextIndex,
    ) -> Result<(), LweCiphertextDiscardingLoadingError<Self::EngineError>>;

    /// Unsafely loads an LWE ciphertext from an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingLoadingError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_load_lwe_ciphertext_unchecked(
        &mut self,
        ciphertext: &mut Ciphertext,
        vector: &CiphertextVector,
        i: LweCiphertextIndex,
    );
}
