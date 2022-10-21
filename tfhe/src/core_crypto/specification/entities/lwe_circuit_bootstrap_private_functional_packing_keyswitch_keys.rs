use crate::core_crypto::prelude::markers::LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, FunctionalPackingKeyswitchKeyCount,
    GlweDimension, LweDimension, PolynomialSize,
};
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a private functional packing keyswitch key vector used
/// for circuit bootstrapping.
///
/// # Formal Definition
pub trait LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity:
    AbstractEntity<Kind = LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysKind>
{
    /// Returns the input LWE dimension of the keys.
    fn input_lwe_dimension(&self) -> LweDimension;

    /// Returns the output GLWE dimension of the keys.
    fn output_glwe_dimension(&self) -> GlweDimension;

    /// Returns the output polynomial degree of the keys.
    fn output_polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of decomposition levels of the keys.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the keys.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;

    /// Returns the number of keys contained in the vector.
    fn key_count(&self) -> FunctionalPackingKeyswitchKeyCount;
}
