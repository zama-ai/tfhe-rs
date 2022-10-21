use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextFusingSubtractionError for LweCiphertextFusingSubtractionEngine @
    LweDimensionMismatch => "The input and output LWE dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextFusingSubtractionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertext, OutputCiphertext>(
        output: &OutputCiphertext,
        input: &InputCiphertext,
    ) -> Result<(), Self>
    where
        InputCiphertext: LweCiphertextEntity,
        OutputCiphertext: LweCiphertextEntity,
    {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines subtracting (fusing) LWE ciphertexts.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation subtracts the `input` LWE ciphertext to the
/// `output` LWE ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextFusingSubtractionEngine<InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
{
    /// Subtracts an LWE ciphertext to an other.
    fn fuse_sub_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    ) -> Result<(), LweCiphertextFusingSubtractionError<Self::EngineError>>;

    /// Unsafely subtracts an LWE ciphertext to another.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextFusingSubtractionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn fuse_sub_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    );
}
