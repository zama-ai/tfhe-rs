use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{LweCiphertextEntity, PlaintextEntity};

engine_error! {
    LweCiphertextPlaintextDiscardingSubtractionError for LweCiphertextPlaintextDiscardingSubtractionEngine @
    LweDimensionMismatch => "The input and output ciphertext LWE dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextPlaintextDiscardingSubtractionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertext, OutputCiphertext>(
        output: &OutputCiphertext,
        input_1: &InputCiphertext,
    ) -> Result<(), Self>
    where
        InputCiphertext: LweCiphertextEntity,
        OutputCiphertext: LweCiphertextEntity,
    {
        if input_1.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines subtracting (discarding) plaintext to LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the supbtraction of the `input_2` plaintext to the `input_1` LWE ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextPlaintextDiscardingSubtractionEngine<
    InputCiphertext,
    Plaintext,
    OutputCiphertext,
>: AbstractEngine where
    Plaintext: PlaintextEntity,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
{
    /// Subtracts a plaintext to an LWE ciphertext.
    fn discard_sub_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &Plaintext,
    ) -> Result<(), LweCiphertextPlaintextDiscardingSubtractionError<Self::EngineError>>;

    /// Unsafely subtracts a plaintext to an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextPlaintextDiscardingSubtractionError`]. For safety concerns _specific_ to
    /// an engine, refer to the implementer safety section.
    unsafe fn discard_sub_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &Plaintext,
    );
}
