//! Definition of the client key for radix decomposition

use super::ClientKey;
use crate::integer::RadixCiphertext;
use crate::shortint::{CiphertextBig as ShortintCiphertext, Parameters as ShortintParameters};

use serde::{Deserialize, Serialize};

/// Client key "specialized" for radix decomposition.
///
/// This key is a simple wrapper of the [ClientKey],
/// that only encrypt and decrypt in radix decomposition.
///
/// # Example
///
/// ```rust
/// use tfhe::integer::RadixClientKey;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
///
/// // 2 * 4 = 8 bits of message
/// let num_block = 4;
/// let cks = RadixClientKey::new(PARAM_MESSAGE_2_CARRY_2, num_block);
///
/// let msg = 167_u64;
///
/// let ct = cks.encrypt(msg);
///
/// // Decryption
/// let dec = cks.decrypt(&ct);
/// assert_eq!(msg, dec);
/// ```
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct RadixClientKey {
    key: ClientKey,
    num_blocks: usize,
}

impl AsRef<ClientKey> for RadixClientKey {
    fn as_ref(&self) -> &ClientKey {
        &self.key
    }
}

impl RadixClientKey {
    pub fn new(parameters: ShortintParameters, num_blocks: usize) -> Self {
        Self {
            key: ClientKey::new(parameters),
            num_blocks,
        }
    }

    pub fn encrypt(&self, message: u64) -> RadixCiphertext {
        self.key.encrypt_radix(message, self.num_blocks)
    }

    pub fn decrypt(&self, ciphertext: &RadixCiphertext) -> u64 {
        self.key.decrypt_radix(ciphertext)
    }

    /// Returns the parameters used by the client key.
    pub fn parameters(&self) -> ShortintParameters {
        self.key.parameters()
    }

    pub fn encrypt_one_block(&self, message: u64) -> ShortintCiphertext {
        self.key.encrypt_one_block(message)
    }

    pub fn decrypt_one_block(&self, ct: &ShortintCiphertext) -> u64 {
        self.key.decrypt_one_block(ct)
    }

    pub fn num_blocks(&self) -> usize {
        self.num_blocks
    }
}

impl From<(ClientKey, usize)> for RadixClientKey {
    fn from((key, num_blocks): (ClientKey, usize)) -> Self {
        Self { key, num_blocks }
    }
}
