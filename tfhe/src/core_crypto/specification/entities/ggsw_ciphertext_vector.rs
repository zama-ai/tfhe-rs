use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GgswCiphertextCount, GlweDimension,
    PolynomialSize,
};
use crate::core_crypto::specification::entities::markers::GgswCiphertextVectorKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a GGSW ciphertext vector.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::entities::GgswCiphertextEntity`)
pub trait GgswCiphertextVectorEntity: AbstractEntity<Kind = GgswCiphertextVectorKind> {
    /// Returns the GLWE dimension of the ciphertexts.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertexts.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of decomposition levels of the ciphertexts.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the ciphertexts.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;

    /// Returns the number of ciphertexts in the vector.
    fn ggsw_ciphertext_count(&self) -> GgswCiphertextCount;
}
