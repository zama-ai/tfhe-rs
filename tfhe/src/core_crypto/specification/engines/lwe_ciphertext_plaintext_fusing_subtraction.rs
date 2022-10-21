use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{LweCiphertextEntity, PlaintextEntity};

engine_error! {
    LweCiphertextPlaintextFusingSubtractionError for LweCiphertextPlaintextFusingSubtractionEngine @
}

/// A trait for engines subtracting (fusing) plaintexts to LWE ciphertexts.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation subtracts the `input` plaintext to the
/// `output` LWE ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextPlaintextFusingSubtractionEngine<Ciphertext, Plaintext>:
    AbstractEngine
where
    Plaintext: PlaintextEntity,
    Ciphertext: LweCiphertextEntity,
{
    /// Subtracts a plaintext to an LWE ciphertext.
    fn fuse_sub_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut Ciphertext,
        input: &Plaintext,
    ) -> Result<(), LweCiphertextPlaintextFusingSubtractionError<Self::EngineError>>;

    /// Unsafely subtracts a plaintext to an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextPlaintextFusingSubtractionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn fuse_sub_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &Plaintext,
    );
}
