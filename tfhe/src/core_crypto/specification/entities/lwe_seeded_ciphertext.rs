use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::prelude::LweDimension;
use crate::core_crypto::specification::entities::markers::LweSeededCiphertextKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a seeded LWE ciphertext.
///
/// A seeded LWE ciphertext is a compressed version of a regular LWE ciphertext. It uses a CSPRNG to
/// deterministically generate its mask from a given seed. Because the mask can be regenerated from
/// a seeded CSPRNG, the seeded LWE ciphertext only stores the seed (128 bits) instead of the whole
/// mask which can contain hundreds of u32 or u64. This lightweight seeded LWE ciphertext can be
/// more efficiently sent over the network for example. It can then be decompressed into a regular
/// LWE ciphertext that can be used in homomorphic computations.
pub trait LweSeededCiphertextEntity: AbstractEntity<Kind = LweSeededCiphertextKind> {
    /// Returns the LWE dimension of the ciphertext.
    fn lwe_dimension(&self) -> LweDimension;

    /// Returns the compression seed used to generate the mask of the LWE ciphertext during
    /// encryption.
    fn compression_seed(&self) -> CompressionSeed;
}
