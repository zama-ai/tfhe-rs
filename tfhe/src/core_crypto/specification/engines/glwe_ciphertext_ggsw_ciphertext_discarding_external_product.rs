use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{GgswCiphertextEntity, GlweCiphertextEntity};

use super::engine_error;

engine_error! {
    GlweCiphertextGgswCiphertextDiscardingExternalProductError for
    GlweCiphertextGgswCiphertextDiscardingExternalProductEngine @
    PolynomialSizeMismatch => "All the GGSW and GLWE ciphertexts polynomial sizes must be the same.",
    GlweDimensionMismatch => "All the GGSW and GLWE ciphertexts GLWE dimension must be the same."
}

impl<EngineError: std::error::Error>
    GlweCiphertextGgswCiphertextDiscardingExternalProductError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<GlweCiphertext, GgswCiphertext>(
        glwe_input: &GlweCiphertext,
        ggsw_input: &GgswCiphertext,
        output: &GlweCiphertext,
    ) -> Result<(), Self>
    where
        GlweCiphertext: GlweCiphertextEntity,
        GgswCiphertext: GgswCiphertextEntity,
    {
        if glwe_input.polynomial_size().0 != ggsw_input.polynomial_size().0
            || glwe_input.polynomial_size().0 != output.polynomial_size().0
        {
            return Err(Self::PolynomialSizeMismatch);
        }
        if glwe_input.glwe_dimension().0 != ggsw_input.glwe_dimension().0
            || glwe_input.glwe_dimension().0 != output.glwe_dimension().0
        {
            return Err(Self::PolynomialSizeMismatch);
        }
        Ok(())
    }
}

/// A trait for engines computing the external product between a GLWE ciphertext
/// and a GSW ciphertext.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext with
/// the result of the external product between a `glwe_input` GLWE ciphertext and
/// a `ggsw_input` GSW ciphertext.
///
/// # Formal Definition
pub trait GlweCiphertextGgswCiphertextDiscardingExternalProductEngine<GlweInput, GgswInput, Output>:
    AbstractEngine
where
    GlweInput: GlweCiphertextEntity,
    GgswInput: GgswCiphertextEntity,
    Output: GlweCiphertextEntity,
{
    /// Computes the discarding external product between a GLWE and a GSW ciphertext.
    fn discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext(
        &mut self,
        glwe_input: &GlweInput,
        ggsw_input: &GgswInput,
        output: &mut Output,
    ) -> Result<(), GlweCiphertextGgswCiphertextDiscardingExternalProductError<Self::EngineError>>;

    /// Unsafely computes the discarding external product between a GLWE and a GSW ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextGgswCiphertextDiscardingExternalProductError`]. For safety concerns
    /// _specific_ to an engine, refer to the implementer safety section.
    unsafe fn discard_compute_external_product_glwe_ciphertext_ggsw_ciphertext_unchecked(
        &mut self,
        glwe_input: &GlweInput,
        ggsw_input: &GgswInput,
        output: &mut Output,
    );
}
