use super::engine_error;
use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweCiphertextEncryptionError for GlweCiphertextEncryptionEngine @
    PlaintextCountMismatch => "The plaintext count of the input vector and the key polynomial size \
                               must be the same."
}

impl<EngineError: std::error::Error> GlweCiphertextEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, PlaintextVector>(
        key: &SecretKey,
        input: &PlaintextVector,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        PlaintextVector: PlaintextVectorEntity,
    {
        if key.polynomial_size().0 != input.plaintext_count().0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting GLWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext containing the
/// encryptions of the `input` plaintext vector, under the `key` secret key.
///
/// # Formal Definition
///
/// ## GLWE Encryption
/// ###### inputs:
/// - $\mathsf{PT}\in\mathcal{R}\_q$: a plaintext
/// - $\vec{S} \in\mathcal{R}\_q^k$: a secret key
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and mean $\mu$
///
/// ###### outputs:
/// - $\mathsf{CT} = \left( \vec{A} , B \right) \in \mathsf{GLWE}\_{\vec{S}}( \mathsf{PT} )\subseteq
///   \mathcal{R}\_q^{k+1}$: an GLWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample each coefficient of the polynomial vector $\vec{A}\in\mathcal{R}^k\_q$
/// 2. sample each integer error coefficient of an error polynomial $E\in\mathcal{R}\_q$ from
/// $\mathcal{D\_{\sigma^2,\mu}}$ 3. compute $B = \left\langle \vec{A} , \vec{S} \right\rangle +
/// \mathsf{PT} + E \in\mathcal{R}\_q$ 4. output $\left( \vec{A} , B \right)$
pub trait GlweCiphertextEncryptionEngine<SecretKey, PlaintextVector, Ciphertext>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    Ciphertext: GlweCiphertextEntity,
{
    /// Encrypts a plaintext vector into a GLWE ciphertext.
    fn encrypt_glwe_ciphertext(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<Ciphertext, GlweCiphertextEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a plaintext vector into a GLWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextEncryptionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Ciphertext;
}
