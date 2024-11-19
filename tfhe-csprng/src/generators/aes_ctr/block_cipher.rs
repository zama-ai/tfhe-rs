use crate::generators::aes_ctr::index::AesIndex;
use crate::generators::aes_ctr::BYTES_PER_BATCH;

/// Represents a key used in the AES block cipher.
#[derive(Clone, Copy)]
pub struct AesKey(pub u128);

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
    fn generate_batch(&mut self, index: AesIndex) -> [u8; BYTES_PER_BATCH];
}
