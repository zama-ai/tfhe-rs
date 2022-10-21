use super::engine_error;
use crate::core_crypto::prelude::LweCiphertextRange;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorDiscardingLoadingError for LweCiphertextVectorDiscardingLoadingEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    UnorderedInputRange => "The input range bounds must be ordered.",
    OutOfVectorInputRange => "The input vector must contain the input range.",
    UnorderedOutputRange => "The output range bound must be ordered.",
    OutOfVectorOutputRange => "The output vector must contain the output range.",
    RangeSizeMismatch => "The input and output range must have the same size."
}

impl<EngineError: std::error::Error> LweCiphertextVectorDiscardingLoadingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertextVector, OutputCiphertextVector>(
        output_vector: &OutputCiphertextVector,
        input_vector: &InputCiphertextVector,
        output_range: LweCiphertextRange,
        input_range: LweCiphertextRange,
    ) -> Result<(), Self>
    where
        InputCiphertextVector: LweCiphertextVectorEntity,
        OutputCiphertextVector: LweCiphertextVectorEntity,
    {
        if input_vector.lwe_dimension() != output_vector.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        if !input_range.is_ordered() {
            return Err(Self::UnorderedInputRange);
        }

        if !output_range.is_ordered() {
            return Err(Self::UnorderedOutputRange);
        }

        if output_range.1 >= output_vector.lwe_ciphertext_count().0 {
            return Err(Self::OutOfVectorOutputRange);
        }

        if input_range.1 >= input_vector.lwe_ciphertext_count().0 {
            return Err(Self::OutOfVectorInputRange);
        }

        let input_range_size = input_range.1 - input_range.0;
        let output_range_size = output_range.1 - output_range.0;
        if input_range_size != output_range_size {
            return Err(Self::RangeSizeMismatch);
        }

        Ok(())
    }
}

/// A trait for engines loading (discarding) a sub LWE ciphertext vector from another one.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills a piece of the `output_vector` lwe
/// ciphertext vector with a piece of the `input_vector` LWE ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorDiscardingLoadingEngine<InputCiphertextVector, OutputCiphertextVector>:
    AbstractEngine
where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Loads a subpart of an LWE ciphertext vector into another LWE ciphertext vector.
    fn discard_load_lwe_ciphertext_vector(
        &mut self,
        output_vector: &mut OutputCiphertextVector,
        input_vector: &InputCiphertextVector,
        output_range: LweCiphertextRange,
        input_range: LweCiphertextRange,
    ) -> Result<(), LweCiphertextVectorDiscardingLoadingError<Self::EngineError>>;

    /// Unsafely loads a subpart of an LWE ciphertext vector into another LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingLoadingError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_load_lwe_ciphertext_vector_unchecked(
        &mut self,
        output_vector: &mut OutputCiphertextVector,
        input_vector: &InputCiphertextVector,
        output_range: LweCiphertextRange,
        input_range: LweCiphertextRange,
    );
}
