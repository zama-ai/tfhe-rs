use crate::core_crypto::prelude::{GlweDimension, PolynomialSize};
use crate::core_crypto::specification::entities::markers::GlweCiphertextKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a GLWE ciphertext.
///
/// **Remark:** GLWE ciphertexts generalize LWE ciphertexts by definition, however in this library,
/// GLWE
/// ciphertext entities do not generalize LWE ciphertexts, i.e., polynomial size cannot be 1.
///
/// # Formal Definition
///
/// ## GLWE Ciphertext
///
/// A GLWE ciphertext is an encryption of a polynomial plaintext.
/// It is secure under the hardness assumption called General Learning With Errors (GLWE).
/// It is a generalization of both
/// [`LWE ciphertexts`](`crate::core_crypto::specification::entities::LweCiphertextEntity`)
/// and RLWE ciphertexts. GLWE requires a cyclotomic ring.
/// We use the notation $\mathcal{R}\_q$ for the following cyclotomic ring:
/// $\mathbb{Z}\_q\[X\]/\left\langle X^N + 1\right\rangle$ where $N\in\mathbb{N}$ is a power of two.
///
/// We call $q$ the ciphertext modulus and $N$ the ring dimension.
///
/// We indicate a GLWE ciphertext of a plaintext $\mathsf{PT} \in\mathcal{R}\_q^{k+1}$ as the
/// following couple: $$\mathsf{CT} = \left( \vec{A}, B\right) = \left( A\_0, \ldots, A\_{k-1},
/// B\right) \in \mathsf{GLWE}\_{\vec{S}} \left( \mathsf{PT} \right) \subseteq
/// \mathcal{R}\_q^{k+1}$$
///
/// ## Generalisation of LWE and RLWE
///
/// When we set $k=1$ a GLWE ciphertext becomes an RLWE ciphertext.
/// When we set $N=1$ a GLWE ciphertext becomes an LWE ciphertext with $n=k$.
pub trait GlweCiphertextEntity: AbstractEntity<Kind = GlweCiphertextKind> {
    /// Returns the GLWE dimension of the ciphertext.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertext.
    fn polynomial_size(&self) -> PolynomialSize;
}
