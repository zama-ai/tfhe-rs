use super::engine_error;
use crate::core_crypto::prelude::{LweDimension, MonomialIndex};
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweCiphertextEntity, LweCiphertextEntity,
};

engine_error! {
    LweCiphertextDiscardingExtractionError for LweCiphertextDiscardingExtractionEngine @
    SizeMismatch => "The sizes of the output LWE (LWE dimension) and the input GLWE (GLWE \
                     dimension * poly size) must be compatible.",
    MonomialIndexTooLarge => "The monomial index must be smaller than the GLWE polynomial size."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingExtractionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<GlweCiphertext, LweCiphertext>(
        output: &LweCiphertext,
        input: &GlweCiphertext,
        nth: MonomialIndex,
    ) -> Result<(), Self>
    where
        GlweCiphertext: GlweCiphertextEntity,
        LweCiphertext: LweCiphertextEntity,
    {
        if output.lwe_dimension()
            != LweDimension(input.polynomial_size().0 * input.glwe_dimension().0)
        {
            return Err(Self::SizeMismatch);
        }
        if nth.0 >= input.polynomial_size().0 {
            return Err(Self::MonomialIndexTooLarge);
        }
        Ok(())
    }
}

/// A trait for engines extracting (discarding) LWE ciphertext from GLWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the extraction of the `nth` coefficient of the `input` GLWE ciphertext.
///
/// # Formal definition
///
/// This operation is usually referred to as a _sample extract_ in the literature.
pub trait LweCiphertextDiscardingExtractionEngine<GlweCiphertext, LweCiphertext>:
    AbstractEngine
where
    GlweCiphertext: GlweCiphertextEntity,
    LweCiphertext: LweCiphertextEntity,
{
    /// Extracts an LWE ciphertext from a GLWE ciphertext.
    fn discard_extract_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext,
        input: &GlweCiphertext,
        nth: MonomialIndex,
    ) -> Result<(), LweCiphertextDiscardingExtractionError<Self::EngineError>>;

    /// Unsafely extracts an LWE ciphertext from a GLWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingExtractionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_extract_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext,
        input: &GlweCiphertext,
        nth: MonomialIndex,
    );
}
