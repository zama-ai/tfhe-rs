use super::engine_error;

use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity,
};

engine_error! {
    LweCiphertextDecryptionError for LweCiphertextDecryptionEngine @
}

/// A trait for engines decrypting LWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an plaintext containing the
/// decryption of the `input` LWE ciphertext, under the `key` secret key.
///
/// # Formal Definition
///
/// ## LWE Decryption
/// ###### inputs:
/// - $\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt} )\subseteq
///   \mathbb{Z}\_q^{(n+1)}$: an LWE ciphertext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
///
/// ###### outputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
///
/// ###### algorithm:
/// 1. compute $\mathsf{pt} = b - \left\langle \vec{a} , \vec{s} \right\rangle \in\mathbb{Z}\_q$
/// 3. output $\mathsf{pt}$
///
/// **Remark:** Observe that the decryption is followed by a decoding phase that will contain a
/// rounding.
pub trait LweCiphertextDecryptionEngine<SecretKey, Ciphertext, Plaintext>: AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    Ciphertext: LweCiphertextEntity,
    Plaintext: PlaintextEntity,
{
    /// Decrypts an LWE ciphertext.
    fn decrypt_lwe_ciphertext(
        &mut self,
        key: &SecretKey,
        input: &Ciphertext,
    ) -> Result<Plaintext, LweCiphertextDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn decrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        input: &Ciphertext,
    ) -> Plaintext;
}
