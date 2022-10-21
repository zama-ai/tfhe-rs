use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweCiphertextDecryptionError for GlweCiphertextDecryptionEngine @
    GlweDimensionMismatch => "The ciphertext and secret key GLWE dimension must be the same.",
    PolynomialSizeMismatch => "The ciphertext and secret key polynomial size must be the same."
}

impl<EngineError: std::error::Error> GlweCiphertextDecryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, Ciphertext>(
        key: &SecretKey,
        input: &Ciphertext,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        Ciphertext: GlweCiphertextEntity,
    {
        if input.glwe_dimension() != key.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }
        if input.polynomial_size() != key.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }
        Ok(())
    }
}

/// A trait for engines decrypting GLWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector containing the
/// decryption of the `input` ciphertext, under the `key` secret key.
///
/// # Formal Definition
///
/// ## GLWE Decryption
/// ###### inputs:
/// - $\mathsf{CT} = \left( \vec{A} , B \right) \in \mathsf{GLWE}\_{\vec{S}}( \mathsf{PT} )\subseteq
///   \mathcal{R}\_q^{k+1}$: an GLWE ciphertext
/// - $\vec{S} \in\mathcal{R}\_q^k$: a secret key
///
/// ###### outputs:
/// - $\mathsf{PT}\in\mathcal{R}\_q$: a plaintext
///
/// ###### algorithm:
///
/// 1. compute $\mathsf{PT} = B - \left\langle \vec{A} , \vec{S} \right\rangle \in\mathcal{R}\_q$
/// 3. output $\mathsf{PT}$
///
/// **Remark:** Observe that the decryption is followed by a decoding phase that will contain a
/// rounding.
pub trait GlweCiphertextDecryptionEngine<SecretKey, Ciphertext, PlaintextVector>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    Ciphertext: GlweCiphertextEntity,
    PlaintextVector: PlaintextVectorEntity,
{
    /// Decrypts a GLWE ciphertext into a plaintext vector.
    fn decrypt_glwe_ciphertext(
        &mut self,
        key: &SecretKey,
        input: &Ciphertext,
    ) -> Result<PlaintextVector, GlweCiphertextDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts a GLWE ciphertext into a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextDecryptionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn decrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        input: &Ciphertext,
    ) -> PlaintextVector;
}
