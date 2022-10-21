use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorFusingOppositeError for LweCiphertextVectorFusingOppositeEngine @
}

/// A trait for engines computing the opposite (fusing) LWE ciphertext vectors.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation computes the opposite of the `input` LWE
/// ciphertext vector.
///
///  # Formal Definition
pub trait LweCiphertextVectorFusingOppositeEngine<CiphertextVector>: AbstractEngine
where
    CiphertextVector: LweCiphertextVectorEntity,
{
    /// Computes the opposite of an LWE ciphertext vector.
    fn fuse_opp_lwe_ciphertext_vector(
        &mut self,
        input: &mut CiphertextVector,
    ) -> Result<(), LweCiphertextVectorFusingOppositeError<Self::EngineError>>;

    /// Unsafely computes the opposite of an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorFusingOppositeError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn fuse_opp_lwe_ciphertext_vector_unchecked(&mut self, input: &mut CiphertextVector);
}
