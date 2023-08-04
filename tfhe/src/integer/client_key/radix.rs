//! Definition of the client key for radix decomposition

use super::{ClientKey, RecomposableSignedInteger};
use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::integer::ciphertext::{RadixCiphertext, SignedRadixCiphertext};
use crate::shortint::{Ciphertext as ShortintCiphertext, PBSParameters as ShortintParameters};
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
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
///
/// // 2 * 4 = 8 bits of message
/// let num_block = 4;
/// let cks = RadixClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);
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
    pub fn new<P>(parameters: P, num_blocks: usize) -> Self
    where
        P: Into<ShortintParameters>,
    {
        Self {
            key: ClientKey::new(parameters.into()),
            num_blocks,
        }
    }

    pub fn encrypt<T: DecomposableInto<u64> + UnsignedNumeric>(
        &self,
        message: T,
    ) -> RadixCiphertext {
        self.key.encrypt_radix(message, self.num_blocks)
    }

    pub fn encrypt_signed<T: DecomposableInto<u64> + SignedNumeric>(
        &self,
        message: T,
    ) -> SignedRadixCiphertext {
        self.key.encrypt_signed_radix(message, self.num_blocks)
    }

    pub fn decrypt<T>(&self, ciphertext: &RadixCiphertext) -> T
    where
        T: RecomposableFrom<u64> + UnsignedNumeric,
    {
        self.key.decrypt_radix(ciphertext)
    }

    pub fn decrypt_signed<T>(&self, ciphertext: &SignedRadixCiphertext) -> T
    where
        T: RecomposableSignedInteger,
    {
        self.key.decrypt_signed_radix(ciphertext)
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
