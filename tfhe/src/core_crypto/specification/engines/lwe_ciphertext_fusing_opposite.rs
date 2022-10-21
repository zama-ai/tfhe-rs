use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextFusingOppositeError for LweCiphertextFusingOppositeEngine @
}

/// A trait for engines computing the opposite (fusing) LWE ciphertexts.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation computes the opposite of the `input` LWE
/// ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextFusingOppositeEngine<Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
{
    /// Computes the opposite of an LWE ciphertext.
    fn fuse_opp_lwe_ciphertext(
        &mut self,
        input: &mut Ciphertext,
    ) -> Result<(), LweCiphertextFusingOppositeError<Self::EngineError>>;

    /// Unsafely computes the opposite of an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextFusingOppositeError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn fuse_opp_lwe_ciphertext_unchecked(&mut self, input: &mut Ciphertext);
}
