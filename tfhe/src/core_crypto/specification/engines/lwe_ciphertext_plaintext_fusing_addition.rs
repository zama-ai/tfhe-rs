use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{LweCiphertextEntity, PlaintextEntity};

engine_error! {
    LweCiphertextPlaintextFusingAdditionError for LweCiphertextPlaintextFusingAdditionEngine @
}

/// A trait for engines adding (fusing) plaintexts to LWE ciphertexts.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation adds the `input` plaintext to the `output`
/// LWE ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextPlaintextFusingAdditionEngine<Ciphertext, Plaintext>:
    AbstractEngine
where
    Plaintext: PlaintextEntity,
    Ciphertext: LweCiphertextEntity,
{
    /// Add a plaintext to an LWE ciphertext.
    fn fuse_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut Ciphertext,
        input: &Plaintext,
    ) -> Result<(), LweCiphertextPlaintextFusingAdditionError<Self::EngineError>>;

    /// Unsafely add a plaintext to an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextPlaintextFusingAdditionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn fuse_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &Plaintext,
    );
}
