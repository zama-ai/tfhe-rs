use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextFusingAdditionError for LweCiphertextFusingAdditionEngine @
    LweDimensionMismatch => "The input and output LWE dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextFusingAdditionError<EngineError> {
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

/// A trait for engines adding (fusing) LWE ciphertexts.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation adds the `input` LWE ciphertext to the
/// `output` LWE ciphertext.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextDiscardingAdditionEngine`)
pub trait LweCiphertextFusingAdditionEngine<InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
{
    /// Adds an LWE ciphertext to an other.
    fn fuse_add_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    ) -> Result<(), LweCiphertextFusingAdditionError<Self::EngineError>>;

    /// Unsafely add an LWE ciphertext to an other.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextFusingAdditionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn fuse_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    );
}
