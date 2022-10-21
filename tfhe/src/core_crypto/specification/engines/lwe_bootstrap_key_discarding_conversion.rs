use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweBootstrapKeyEntity;

engine_error! {
    LweBootstrapKeyDiscardingConversionError for LweBootstrapKeyDiscardingConversionEngine @
    LweDimensionMismatch => "The two keys must have the same LWE dimension.",
    GlweDimensionMismatch => "The two keys must have the same GLWE dimension.",
    PolynomialSizeMismatch => "The two keys must have the same polynomial size.",
    DecompositionBaseLogMismatch => "The two keys must have the same base logarithms.",
    DecompositionLevelCountMismatch => "The two keys must have the same level counts."
}

impl<EngineError: std::error::Error> LweBootstrapKeyDiscardingConversionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Input, Output>(output: &Output, input: &Input) -> Result<(), Self>
    where
        Input: LweBootstrapKeyEntity,
        Output: LweBootstrapKeyEntity,
    {
        if input.input_lwe_dimension() != output.input_lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        if input.glwe_dimension() != output.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }

        if input.polynomial_size() != output.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }

        if input.decomposition_base_log() != output.decomposition_base_log() {
            return Err(Self::DecompositionBaseLogMismatch);
        }

        if input.decomposition_level_count() != output.decomposition_level_count() {
            return Err(Self::DecompositionLevelCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines converting (discarding) LWE bootstrap keys .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE bootstrap key with
/// the conversion of the `input` LWE bootstrap key to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweBootstrapKeyDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweBootstrapKeyEntity,
    Output: LweBootstrapKeyEntity,
{
    /// Converts a LWE bootstrap key .
    fn discard_convert_lwe_bootstrap_key(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweBootstrapKeyDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a LWE bootstrap key .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweBootstrapKeyDiscardingConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_convert_lwe_bootstrap_key_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
