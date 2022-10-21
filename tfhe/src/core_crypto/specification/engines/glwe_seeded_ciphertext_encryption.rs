use super::engine_error;

use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweSecretKeyEntity, GlweSeededCiphertextEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweSeededCiphertextEncryptionError for GlweSeededCiphertextEncryptionEngine @
    PlaintextCountMismatch => "The plaintext count of the input vector and the key polynomial size \
    must be the same."
}

impl<EngineError: std::error::Error> GlweSeededCiphertextEncryptionError<EngineError> {
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

/// A trait for engines encrypting seeded GLWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext containing the
/// encryption of the `input` plaintext vetor under the `key` secret key.
///
/// # Formal Definition
///
/// ## Seeded GLWE Encryption
/// ###### inputs:
/// - $\mathsf{PT}\in\mathcal{R}\_q$: a plaintext
/// - $\vec{S} \in\mathcal{R}\_q^k$: a secret key
/// - $\mathsf{seed} \in\mathcal{S}$: a public seed
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean $\mu$
///
/// ###### outputs:
/// - $\tilde{\mathsf{CT}} = \left( \mathsf{seed} , B \right) \in \mathsf{SeededGLWE}^k\_{\vec{S},
///   G}( \mathsf{PT} )\subseteq \mathcal{S}\times \mathcal{R}\_q$: a seeded GLWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample each coefficient of the polynomial vector $\vec{A}\in\mathcal{R}^k\_q$ from
/// $G$ with the seed $\mathsf{seed}\in\mathcal{S}$
/// 2. sample each integer error coefficient of an error polynomial $E\in\mathcal{R}\_q$ from
/// $\mathcal{D\_{\sigma^2,\mu}}$
/// 3. compute $B = \left\langle \vec{A} , \vec{S} \right\rangle + \mathsf{PT} + E
/// \in\mathcal{R}\_q$
/// 4. output $\left( \mathsf{seed} , B \right)$
pub trait GlweSeededCiphertextEncryptionEngine<SecretKey, PlaintextVector, Ciphertext>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    Ciphertext: GlweSeededCiphertextEntity,
{
    /// Encrypts a seeded GLWE ciphertext.
    fn encrypt_glwe_seeded_ciphertext(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<Ciphertext, GlweSeededCiphertextEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a seeded GLWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSeededCiphertextEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_glwe_seeded_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Ciphertext;
}
