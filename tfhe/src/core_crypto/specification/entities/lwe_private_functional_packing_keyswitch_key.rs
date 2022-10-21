use crate::core_crypto::prelude::markers::LwePrivateFunctionalPackingKeyswitchKeyKind;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a private functional packing keyswitch key.
///
/// # Formal Definition
pub trait LwePrivateFunctionalPackingKeyswitchKeyEntity:
    AbstractEntity<Kind = LwePrivateFunctionalPackingKeyswitchKeyKind>
{
    /// Returns the input LWE dimension of the key.
    fn input_lwe_dimension(&self) -> LweDimension;

    /// Returns the output GLWE dimension of the key.
    fn output_glwe_dimension(&self) -> GlweDimension;

    /// Returns the output polynomial degree of the key.
    fn output_polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of decomposition levels of the key.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the key.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;
}
