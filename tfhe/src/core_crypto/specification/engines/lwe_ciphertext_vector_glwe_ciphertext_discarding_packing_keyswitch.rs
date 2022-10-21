use super::engine_error;
use crate::core_crypto::prelude::{GlweCiphertextEntity, LwePackingKeyswitchKeyEntity};
use crate::core_crypto::specification::engines::AbstractEngine;

use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchError for LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext vector and input packing keyswitch key LWE \
                                    dimension must be the same.",
    OutputGlweDimensionMismatch => "The output ciphertext vector and packing keyswitch key output \
                                    GLWE dimensions must be the same.",
    OutputPolynomialSizeMismatch => "The output ciphertext vector and packing keyswitch key \
                                    polynomial sizes must be the same.",
    CiphertextCountMismatch => "The input ciphertext count is bigger than the output polynomial \
                                    size."
}

impl<EngineError: std::error::Error>
    LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks<LwePackingKeyswitchKey, InputCiphertextVector, OutputCiphertext>(
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        ksk: &LwePackingKeyswitchKey,
    ) -> Result<(), Self>
    where
        LwePackingKeyswitchKey: LwePackingKeyswitchKeyEntity,
        InputCiphertextVector: LweCiphertextVectorEntity,
        OutputCiphertext: GlweCiphertextEntity,
    {
        if input.lwe_dimension() != ksk.input_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }

        if output.glwe_dimension() != ksk.output_glwe_dimension() {
            return Err(Self::OutputGlweDimensionMismatch);
        }

        if output.polynomial_size() != ksk.output_polynomial_size() {
            return Err(Self::OutputPolynomialSizeMismatch);
        }

        if input.lwe_ciphertext_count().0 > output.polynomial_size().0 {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines packing keyswitching (discarding) LWE ciphertext vectors into a GLWE
/// ciphertext.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext
/// with the packing keyswitch of the `input` LWE ciphertext vector, under the `pksk` packing
/// keyswitch key.
///
/// # Formal Definition
pub trait LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchEngine<
    LwePackingKeyswitchKey,
    InputCiphertextVector,
    OutputCiphertext,
>: AbstractEngine where
    LwePackingKeyswitchKey: LwePackingKeyswitchKeyEntity,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertext: GlweCiphertextEntity,
{
    /// Packing keyswitch an LWE ciphertext vector.
    fn discard_packing_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        pksk: &LwePackingKeyswitchKey,
    ) -> Result<
        (),
        LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchError<Self::EngineError>,
    >;

    /// Unsafely packing keyswitches an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorGlweCiphertextDiscardingPackingKeyswitchError`]. For safety concerns
    /// _specific_ to an engine, refer to the implementer safety section.
    unsafe fn discard_packing_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertextVector,
        pksk: &LwePackingKeyswitchKey,
    );
}
