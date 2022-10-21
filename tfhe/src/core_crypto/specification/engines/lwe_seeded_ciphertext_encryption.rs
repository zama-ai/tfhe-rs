use super::engine_error;

use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweSecretKeyEntity, LweSeededCiphertextEntity, PlaintextEntity,
};

engine_error! {
    LweSeededCiphertextEncryptionError for LweSeededCiphertextEncryptionEngine @
}

/// A trait for engines encrypting seeded LWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext containing the
/// encryption of the `input` plaintext under the `key` secret key.
///
/// # Formal Definition
///
/// ## Seeded LWE Encryption
/// ###### inputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
/// - $\mathsf{seed} \in\mathcal{S}$: a public seed
/// - $G$: a CSPRNG working with seeds from $\mathcal{S}$
/// - $\mathcal{D}\_{\sigma^2,\mu}$: a normal distribution of variance $\sigma^2$ and a mean $\mu$
///
/// ###### outputs:
/// - $\tilde{\mathsf{ct}} = \left( \mathsf{seed} , b\right) \in \mathsf{SeededLWE}^n\_{\vec{s}, G}(
///  \mathsf{pt})\subseteq \mathcal{S}\times \mathbb{Z}\_q$: a seeded LWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample $n$ integers in $\mathbb{Z}\_q$ from $G$ with the seed
/// $\mathsf{seed}\in\mathcal{S}$ and store them in $\vec{a}\in\mathbb{Z}^n\_q$
/// 2. sample an integer error term $e \hookleftarrow \mathcal{D}\_{\sigma^2,\mu}$
/// 3. compute $b = \left\langle \vec{a} , \vec{s} \right\rangle + \mathsf{pt} + e \in\mathbb{Z}\_q$
/// 4. output $\left( \mathsf{seed} , b\right)$
pub trait LweSeededCiphertextEncryptionEngine<SecretKey, Plaintext, Ciphertext>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    Plaintext: PlaintextEntity,
    Ciphertext: LweSeededCiphertextEntity,
{
    /// Encrypts a seeded LWE ciphertext.
    fn encrypt_lwe_seeded_ciphertext(
        &mut self,
        key: &SecretKey,
        input: &Plaintext,
        noise: Variance,
    ) -> Result<Ciphertext, LweSeededCiphertextEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a seeded LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededCiphertextEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_lwe_seeded_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        input: &Plaintext,
        noise: Variance,
    ) -> Ciphertext;
}
