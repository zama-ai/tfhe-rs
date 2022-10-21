use super::engine_error;
use crate::core_crypto::prelude::LweCiphertextIndex;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{LweCiphertextEntity, LweCiphertextVectorEntity};

engine_error! {
    LweCiphertextLoadingError for LweCiphertextLoadingEngine @
    IndexTooLarge => "The index must not exceed the size of the vector."
}

impl<EngineError: std::error::Error> LweCiphertextLoadingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Ciphertext, CiphertextVector>(
        vector: &CiphertextVector,
        i: LweCiphertextIndex,
    ) -> Result<(), Self>
    where
        Ciphertext: LweCiphertextEntity,
        CiphertextVector: LweCiphertextVectorEntity,
    {
        if i.0 >= vector.lwe_ciphertext_count().0 {
            return Err(Self::IndexTooLarge);
        }
        Ok(())
    }
}

/// A trait for engines loading LWE ciphertexts from LWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext containing the
/// `i`th LWE ciphertext of the `vector` LWE ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextLoadingEngine<CiphertextVector, Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
    CiphertextVector: LweCiphertextVectorEntity,
{
    /// Loads an LWE ciphertext from an LWE ciphertext vector.
    fn load_lwe_ciphertext(
        &mut self,
        vector: &CiphertextVector,
        i: LweCiphertextIndex,
    ) -> Result<Ciphertext, LweCiphertextLoadingError<Self::EngineError>>;

    /// Unsafely loads an LWE ciphertext from an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextLoadingError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn load_lwe_ciphertext_unchecked(
        &mut self,
        vector: &CiphertextVector,
        i: LweCiphertextIndex,
    ) -> Ciphertext;
}
