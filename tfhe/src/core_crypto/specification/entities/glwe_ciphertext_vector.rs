use crate::core_crypto::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
use crate::core_crypto::specification::entities::markers::GlweCiphertextVectorKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a GLWE ciphertext vector.
///
/// **Remark:** GLWE ciphertexts generalize LWE ciphertexts by definition, however in this library,
/// GLWE ciphertext entities do not generalize LWE ciphertexts, i.e., polynomial size cannot be 1.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::entities::GlweCiphertextEntity`)
pub trait GlweCiphertextVectorEntity: AbstractEntity<Kind = GlweCiphertextVectorKind> {
    /// Returns the GLWE dimension of the ciphertexts.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertexts.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of ciphertexts in the vector.
    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount;
}
