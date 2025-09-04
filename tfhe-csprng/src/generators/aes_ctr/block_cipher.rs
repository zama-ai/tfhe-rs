use crate::generators::aes_ctr::{AES_CALLS_PER_BATCH, BYTES_PER_AES_CALL, BYTES_PER_BATCH};

/// Represents a key used in the AES block cipher.
///
/// The u128 endianness should be ignored by implementations and the u128 should be seen as a simple
/// [u8; 16].
#[derive(Clone, Copy)]
pub(crate) struct AesKey(pub u128);

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
