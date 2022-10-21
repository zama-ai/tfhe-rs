use super::engine_error;

use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity,
};

engine_error! {
    LweCiphertextEncryptionError for LweCiphertextEncryptionEngine @
}

/// A trait for engines encrypting LWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext containing the
/// encryption of the `input` plaintext under the `key` secret key.
///
/// # Formal Definition
///
/// ## LWE Encryption
/// ###### inputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean $\mu$
///
/// ###### outputs:
/// - $\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt} )\subseteq
///   \mathbb{Z}\_q^{(n+1)}$: an LWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample a vector $\vec{a}\in\mathbb{Z}\_q^n$
/// 2. sample an integer error term $e \hookleftarrow \mathcal{D\_{\sigma^2,\mu}}$
/// 3. compute $b = \left\langle \vec{a} , \vec{s} \right\rangle + \mathsf{pt} + e \in\mathbb{Z}\_q$
/// 4. output $\left( \vec{a} , b\right)$
pub trait LweCiphertextEncryptionEngine<SecretKey, Plaintext, Ciphertext>: AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    Plaintext: PlaintextEntity,
    Ciphertext: LweCiphertextEntity,
{
    /// Encrypts an LWE ciphertext.
    fn encrypt_lwe_ciphertext(
        &mut self,
        key: &SecretKey,
        input: &Plaintext,
        noise: Variance,
    ) -> Result<Ciphertext, LweCiphertextEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        input: &Plaintext,
        noise: Variance,
    ) -> Ciphertext;
}
