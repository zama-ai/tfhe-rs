use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{CleartextEntity, LweCiphertextEntity};

engine_error! {
    LweCiphertextCleartextFusingMultiplicationError for LweCiphertextCleartextFusingMultiplicationEngine @
}

/// A trait for engines multiplying (fusing) LWE ciphertexts by cleartexts.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation multiply the `output` LWE ciphertext with
/// the `input` cleartext.
///
/// # Formal Definition
///
/// cf
/// [`here`](`crate::core_crypto::specification::engines::LweCiphertextCleartextDiscardingMultiplicationEngine`)
pub trait LweCiphertextCleartextFusingMultiplicationEngine<Ciphertext, Cleartext>:
    AbstractEngine
where
    Cleartext: CleartextEntity,
    Ciphertext: LweCiphertextEntity,
{
    /// Multiply an LWE ciphertext with a cleartext.
    fn fuse_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut Ciphertext,
        input: &Cleartext,
    ) -> Result<(), LweCiphertextCleartextFusingMultiplicationError<Self::EngineError>>;

    /// Unsafely multiply an LWE ciphertext with a cleartext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextCleartextFusingMultiplicationError`]. For safety concerns _specific_ to
    /// an engine, refer to the implementer safety section.
    unsafe fn fuse_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &Cleartext,
    );
}
