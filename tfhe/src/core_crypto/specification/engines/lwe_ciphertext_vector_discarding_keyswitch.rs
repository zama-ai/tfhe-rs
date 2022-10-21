use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;

use crate::core_crypto::specification::entities::{
    LweCiphertextVectorEntity, LweKeyswitchKeyEntity,
};

engine_error! {
    LweCiphertextVectorDiscardingKeyswitchError for LweCiphertextVectorDiscardingKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext vector and keyswitch key input LWE \
                                  dimension must be the same.",
    OutputLweDimensionMismatch => "The output ciphertext vector and keyswitch key output LWE \
                                   dimension must be the same.",
    CiphertextCountMismatch => "The input and output ciphertexts have different ciphertext counts."
}

impl<EngineError: std::error::Error> LweCiphertextVectorDiscardingKeyswitchError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<KeyswitchKey, InputCiphertextVector, OutputCiphertextVector>(
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
        ksk: &KeyswitchKey,
    ) -> Result<(), Self>
    where
        KeyswitchKey: LweKeyswitchKeyEntity,
        InputCiphertextVector: LweCiphertextVectorEntity,
        OutputCiphertextVector: LweCiphertextVectorEntity,
    {
        if input.lwe_dimension() != ksk.input_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }

        if output.lwe_dimension() != ksk.output_lwe_dimension() {
            return Err(Self::OutputLweDimensionMismatch);
        }

        if input.lwe_ciphertext_count() != output.lwe_ciphertext_count() {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines keyswitching (discarding) LWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext vector
/// with the element-wise keyswitch of the `input` LWE ciphertext vector, under the `ksk` lwe
/// keyswitch key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextDiscardingKeyswitchEngine`)
pub trait LweCiphertextVectorDiscardingKeyswitchEngine<
    KeyswitchKey,
    InputCiphertextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    KeyswitchKey: LweKeyswitchKeyEntity,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Keyswitch an LWE ciphertext vector.
    fn discard_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
        ksk: &KeyswitchKey,
    ) -> Result<(), LweCiphertextVectorDiscardingKeyswitchError<Self::EngineError>>;

    /// Unsafely keyswitch an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingKeyswitchError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
        ksk: &KeyswitchKey,
    );
}
