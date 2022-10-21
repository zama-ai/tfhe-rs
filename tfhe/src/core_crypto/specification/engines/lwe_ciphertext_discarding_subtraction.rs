use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextDiscardingSubtractionError for LweCiphertextDiscardingSubtractionEngine @
    LweDimensionMismatch => "All the ciphertext LWE dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingSubtractionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertext, OutputCiphertext>(
        output: &OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &InputCiphertext,
    ) -> Result<(), Self>
    where
        InputCiphertext: LweCiphertextEntity,
        OutputCiphertext: LweCiphertextEntity,
    {
        if output.lwe_dimension() != input_1.lwe_dimension()
            || output.lwe_dimension() != input_2.lwe_dimension()
        {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines subtracting (discarding) LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the subtraction of the `input_1` LWE ciphertext and the `input_2` LWE ciphertext, that is
/// `input_1` - `input_2`.
///
/// # Formal Definition
pub trait LweCiphertextDiscardingSubtractionEngine<InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
{
    /// Subtracts two LWE ciphertexts.
    fn discard_sub_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &InputCiphertext,
    ) -> Result<(), LweCiphertextDiscardingSubtractionError<Self::EngineError>>;

    /// Unsafely substracts two LWE ciphertexts.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingSubtractionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_sub_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &InputCiphertext,
    );
}
