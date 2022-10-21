use super::engine_error;
use crate::core_crypto::prelude::GgswCiphertextEntity;
use crate::core_crypto::specification::engines::AbstractEngine;

engine_error! {
    GgswCiphertextDiscardingConversionError for GgswCiphertextDiscardingConversionEngine @
    GlweDimensionMismatch => "The input and output GLWE dimensions must be the same.",
    PolynomialSizeMismatch => "The input and output polynomial sizes must be the same.",
    DecompositionLevelCountMismatch => "The input and output decomposition level counts must be the same.",
    DecompositionBaseLogMismatch => "The input and output decomposition base log must be the same."
}

impl<EngineError: std::error::Error> GgswCiphertextDiscardingConversionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Input, Output>(output: &Output, input: &Input) -> Result<(), Self>
    where
        Input: GgswCiphertextEntity,
        Output: GgswCiphertextEntity,
    {
        if input.glwe_dimension() != output.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }

        if input.polynomial_size() != output.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }

        if input.decomposition_level_count() != output.decomposition_level_count() {
            return Err(Self::DecompositionLevelCountMismatch);
        }

        if input.decomposition_base_log() != output.decomposition_base_log() {
            return Err(Self::DecompositionBaseLogMismatch);
        }

        Ok(())
    }
}

/// A trait for engines converting (discarding) GGSW ciphertexts .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GGSW ciphertext with
/// the conversion of the `input` GGSW ciphertext to a type with a different representation (for
/// instance from standard to Fourier domain).
///
/// # Formal Definition
pub trait GgswCiphertextDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: GgswCiphertextEntity,
    Output: GgswCiphertextEntity,
{
    /// Converts a GGSW ciphertext .
    fn discard_convert_ggsw_ciphertext(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), GgswCiphertextDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a GGSW ciphertext .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GgswCiphertextDiscardingConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_convert_ggsw_ciphertext_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
