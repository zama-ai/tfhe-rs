use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
use crate::core_crypto::specification::entities::markers::GlweSeededCiphertextVectorKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a seeded GLWE ciphertext vector.
///
/// **Remark:** GLWE ciphertexts generalize LWE ciphertexts by definition, however in this library,
/// GLWE ciphertext entities do not generalize LWE ciphertexts, i.e., polynomial size cannot be 1.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::entities::GlweSeededCiphertextEntity`)
pub trait GlweSeededCiphertextVectorEntity:
    AbstractEntity<Kind = GlweSeededCiphertextVectorKind>
{
    /// Returns the GLWE dimension of the ciphertexts.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertexts.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of ciphertexts in the vector.
    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount;

    /// Returns the compression seed used to generate the mask of the LWE ciphertext during
    /// encryption.
    fn compression_seed(&self) -> CompressionSeed;
}
