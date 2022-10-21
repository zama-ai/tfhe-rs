use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;

use crate::core_crypto::specification::entities::{
    GlweCiphertextVectorEntity, LweBootstrapKeyEntity, LweCiphertextVectorEntity,
};

engine_error! {
    LweCiphertextVectorDiscardingBootstrapError for LweCiphertextVectorDiscardingBootstrapEngine @
    InputLweDimensionMismatch => "The input vector and key input LWE dimension must be the same.",
    OutputLweDimensionMismatch => "The output vector and key output LWE dimension must be the same.",
    AccumulatorGlweDimensionMismatch => "The accumulator vector and key GLWE dimension must be the same.",
    AccumulatorPolynomialSizeMismatch => "The accumulator vector and key polynomial size must be the same.",
    AccumulatorCountMismatch => "The accumulator count and input ciphertext count must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextVectorDiscardingBootstrapError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<
        BootstrapKey,
        AccumulatorVector,
        InputCiphertextVector,
        OutputCiphertextVector,
    >(
        output: &OutputCiphertextVector,
        input: &InputCiphertextVector,
        acc: &AccumulatorVector,
        bsk: &BootstrapKey,
    ) -> Result<(), Self>
    where
        BootstrapKey: LweBootstrapKeyEntity,
        AccumulatorVector: GlweCiphertextVectorEntity,
        InputCiphertextVector: LweCiphertextVectorEntity,
        OutputCiphertextVector: LweCiphertextVectorEntity,
    {
        if bsk.input_lwe_dimension() != input.lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }

        if bsk.output_lwe_dimension() != output.lwe_dimension() {
            return Err(Self::OutputLweDimensionMismatch);
        }

        if bsk.glwe_dimension() != acc.glwe_dimension() {
            return Err(Self::AccumulatorGlweDimensionMismatch);
        }

        if bsk.polynomial_size() != acc.polynomial_size() {
            return Err(Self::AccumulatorPolynomialSizeMismatch);
        }
        if acc.glwe_ciphertext_count().0 != input.lwe_ciphertext_count().0 {
            return Err(Self::AccumulatorCountMismatch);
        }

        if input.lwe_ciphertext_count() != output.lwe_ciphertext_count() {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines bootstrapping (discarding) LWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext vector
/// with the element-wise bootstrap of the `input` LWE ciphertext vector, using the `acc`
/// accumulator as lookup-table, and the `bsk` bootstrap key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextDiscardingBootstrapEngine`)
pub trait LweCiphertextVectorDiscardingBootstrapEngine<
    BootstrapKey,
    AccumulatorVector,
    InputCiphertextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    BootstrapKey: LweBootstrapKeyEntity,
    AccumulatorVector: GlweCiphertextVectorEntity,
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Bootstraps an LWE ciphertext vector.
    fn discard_bootstrap_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
        acc: &AccumulatorVector,
        bsk: &BootstrapKey,
    ) -> Result<(), LweCiphertextVectorDiscardingBootstrapError<Self::EngineError>>;

    /// Unsafely bootstraps an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingBootstrapError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_bootstrap_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
        acc: &AccumulatorVector,
        bsk: &BootstrapKey,
    );
}
