use crate::generators::aes_ctr::{AES_CALLS_PER_BATCH, BYTES_PER_AES_CALL, BYTES_PER_BATCH};

/// Represents a key used in the AES block cipher.
///
/// The u128 endianness should be ignored by implementations and the u128 should be seen as a simple
/// [u8; 16].
///
/// Therefore, except when loading the key from a [`Seed`](`crate::seeders::Seed`), whose bytes
/// needs to be loaded with [u128::from_le] (to keep consistency of the loaded bytes across systems
/// endianness), the rest of the code should use the [`AesKey`] with native endian ordering such
/// that the internal u128 is equivalent to [u8; 16].
#[derive(Clone, Copy, Debug)]
pub struct AesKey(pub(crate) u128);

/// A trait for AES block ciphers.
///
/// Note:
/// -----
///
/// The block cipher is used in a batched manner (to reduce amortized cost on special hardware).
/// For this reason we only expose a `generate_batch` method.
pub trait AesBlockCipher: Clone + Send + Sync {
    /// Instantiate a new generator from a secret key.
    fn new(key: AesKey) -> Self;
    /// Generates the batch corresponding to the given index.
    fn generate_batch(&mut self, data: [u128; AES_CALLS_PER_BATCH]) -> [u8; BYTES_PER_BATCH];
    /// Generate next bytes
    fn generate_next(&mut self, data: u128) -> [u8; BYTES_PER_AES_CALL];
}
