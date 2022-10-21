use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::core_crypto::specification::entities::markers::LweSeededBootstrapKeyKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a seeded LWE bootstrap key.
///
/// # Formal Definition
///
/// ## Seeded Bootstrapping Key
///
/// TODO
pub trait LweSeededBootstrapKeyEntity: AbstractEntity<Kind = LweSeededBootstrapKeyKind> {
    /// Returns the GLWE dimension of the key.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the key.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the input LWE dimension of the key.
    fn input_lwe_dimension(&self) -> LweDimension;

    /// Returns the output LWE dimension of the key.
    fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.glwe_dimension().0 * self.polynomial_size().0)
    }

    /// Returns the number of decomposition levels of the key.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;

    /// Returns the logarithm of the base used in the key.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the compression seed used to generate the seeded LWE bootstrap key during
    /// encryption.
    fn compression_seed(&self) -> CompressionSeed;
}
