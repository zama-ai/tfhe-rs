use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, LweDimension,
};
use crate::core_crypto::specification::entities::markers::LweSeededKeyswitchKeyKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a seeded LWE keyswitch key.
///
/// # Formal Definition
///
/// ## Seeded Key Switching Key
///
/// TODO
pub trait LweSeededKeyswitchKeyEntity: AbstractEntity<Kind = LweSeededKeyswitchKeyKind> {
    /// Returns the input LWE dimension of the key.
    fn input_lwe_dimension(&self) -> LweDimension;

    /// Returns the output lew dimension of the key.
    fn output_lwe_dimension(&self) -> LweDimension;

    /// Returns the number of decomposition levels of the key.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the key.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;

    /// Returns the compression seed used to generate the mask of the LWE ciphertext during
    /// encryption.
    fn compression_seed(&self) -> CompressionSeed;
}
