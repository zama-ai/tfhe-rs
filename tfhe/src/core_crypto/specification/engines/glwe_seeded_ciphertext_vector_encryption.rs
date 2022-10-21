use super::engine_error;
use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweSecretKeyEntity, GlweSeededCiphertextVectorEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweSeededCiphertextVectorEncryptionError for GlweSeededCiphertextVectorEncryptionEngine @
    PlaintextCountMismatch => "The key polynomial size must divide the plaintext count of the input \
                               vector."
}

impl<EngineError: std::error::Error> GlweSeededCiphertextVectorEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, PlaintextVector>(
        key: &SecretKey,
        input: &PlaintextVector,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        PlaintextVector: PlaintextVectorEntity,
    {
        if (input.plaintext_count().0 % key.polynomial_size().0) != 0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting GLWE seeded ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE seeded ciphertext vector
/// containing the piece-wise encryptions of the `input` plaintext vector, under the `key` secret
/// key.
///
/// # Formal Definition
///
/// ## Seeded GLWE vector encryption
/// ###### inputs:
/// - $\vec{\mathsf{PT}}\in\mathcal{R}\_q^t$: a plaintext vector
/// - $\vec{S} \in\mathcal{R}\_q^k$: a secret key
/// - $\mathsf{seed} \in\mathcal{S}$: a public seed
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\mathcal{D}\_{\sigma^2,\mu}$: a normal distribution of variance $\sigma^2$ and a mean $\mu$
///
/// ###### outputs:
/// - $\vec{\tilde{\mathsf{CT}}} = \left( \mathsf{seed} , \vec{\tilde{B}} \right) \in
///   \mathsf{SeededGLWEVector}^{k,t}\_{\vec{S}, G}( \vec{\mathsf{PT}} )\subseteq \mathcal{S}\times
///   \mathcal{R}\_q^t$: a seeded GLWE ciphertext vector
///
/// ###### algorithm:
/// 1. let $\vec{B} \in \mathcal{R}\_q^t$
/// 2. Seed $G$ with the seed $\mathsf{seed}\in\mathcal{S}$
/// 3. for each $(B\_i, \mathsf{PT\_i})$ in $(\vec{B}, \vec{\mathsf{PT}})$
///     - uniformly sample each coefficient of the polynomial vector $\vec{A}\in\mathcal{R}^k\_q$
///       from $G$
///     - sample each integer error coefficient of an error polynomial $E\in\mathcal{R}\_q$ from
///       $\mathcal{D\_{\sigma^2,\mu}}$
///     - compute $B\_i = \left\langle \vec{A} , \vec{S} \right\rangle + \mathsf{PT} + E
/// \in\mathcal{R}\_q$
/// 4. output $\left( \mathsf{seed} , \vec{B}\right)$
pub trait GlweSeededCiphertextVectorEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    CiphertextVector: GlweSeededCiphertextVectorEntity,
{
    /// Encrypts a GLWE seeded ciphertext vector.
    fn encrypt_glwe_seeded_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<CiphertextVector, GlweSeededCiphertextVectorEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a GLWE seeded ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSeededCiphertextVectorEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_glwe_seeded_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> CiphertextVector;
}
