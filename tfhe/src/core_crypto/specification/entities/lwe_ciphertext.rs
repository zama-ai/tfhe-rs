use crate::core_crypto::prelude::LweDimension;
use crate::core_crypto::specification::entities::markers::LweCiphertextKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an LWE ciphertext.
///
/// # Formal Definition
///
/// ## LWE Ciphertext
///
/// An LWE ciphertext is an encryption of a plaintext.
/// It is secure under the hardness assumption called Learning With Errors (LWE).
/// It is a specialization of
/// [`GLWE ciphertext`](`crate::core_crypto::specification::entities::GlweCiphertextEntity`).
///
/// We indicate an LWE ciphertext of a plaintext $\mathsf{pt} \in\mathbb{Z}\_q$ as the following
/// couple: $$\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt}
/// )\subseteq \mathbb{Z}\_q^{(n+1)}$$ We call $q$ the ciphertext modulus and $n$ the LWE dimension.
///
/// ## LWE dimension
/// It corresponds to the number of element in the LWE secret key.
/// In an LWE ciphertext, it is the length of the vector $\vec{a}$.
/// At [`encryption`](`crate::core_crypto::specification::engines::LweCiphertextEncryptionEngine`)
/// time, it is the number of uniformly random
/// integers generated.
pub trait LweCiphertextEntity: AbstractEntity<Kind = LweCiphertextKind> {
    /// Returns the LWE dimension of the ciphertext.
    fn lwe_dimension(&self) -> LweDimension;
}
