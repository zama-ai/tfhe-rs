use super::engine_error;
use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweSecretKeyEntity, LweSeededCiphertextVectorEntity, PlaintextVectorEntity,
};

engine_error! {
    LweSeededCiphertextVectorEncryptionError for LweSeededCiphertextVectorEncryptionEngine @
}

/// A trait for engines encrypting seeded LWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a seeded LWE ciphertext vector
/// containing the element-wise encryption of the `input` plaintext vector, under the `key` secret
/// key.
///
/// # Formal Definition
///
/// ## Seeded LWE vector encryption
/// ###### inputs:
/// - $\vec{\mathsf{pt}}\in\mathbb{Z}\_q^t$: a plaintext vector
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
/// - $\mathsf{seed} \in\mathcal{S}$: a public seed
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\mathcal{D}\_{\sigma^2,\mu}$: a normal distribution of variance $\sigma^2$ and mean $\mu$
///
/// ###### outputs:
/// - $\vec{\tilde{\mathsf{ct}}} = \left( \mathsf{seed} , \vec{b}\right) \in
///   \mathsf{SeededLWEVector}^{n, t}\_{\vec{s}, G}(
///  \vec{\mathsf{pt}})\subseteq \mathcal{S}\times \mathbb{Z}\_q^t$: a seeded LWE ciphertext vector
///
/// ###### algorithm:
/// 1. let $\vec{b} \in \mathbb{Z}\_q^t$
/// 2. Seed $G$ with the seed $\mathsf{seed}\in\mathcal{S}$
/// 3. for each $(b\_i, \mathsf{pt\_i})$ in $(\vec{b}, \vec{\mathsf{pt}})$
///     - uniformly sample $n$ integers in $\mathbb{Z}\_q$ from $G$ and store them in
/// $\vec{a}\in\mathbb{Z}^n\_q$
///     - sample an integer error term $e \hookleftarrow\mathcal{D}\_{\sigma^2,\mu}$
///     - compute $b\_i = \left\langle \vec{a} , \vec{s} \right\rangle + \mathsf{pt\_i} + e
/// \in\mathbb{Z}\_q$
/// 4. output $\left( \mathsf{seed} , \vec{b}\right)$
pub trait LweSeededCiphertextVectorEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    CiphertextVector: LweSeededCiphertextVectorEntity,
{
    /// Encrypts a seeded LWE ciphertext vector.
    fn encrypt_lwe_seeded_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<CiphertextVector, LweSeededCiphertextVectorEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a seeded LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededCiphertextVectorEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_lwe_seeded_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> CiphertextVector;
}
