//! Definition of the client key for radix decomposition

use super::{ClientKey, RecomposableSignedInteger, SecretEncryptionKeyView};
use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::integer::backward_compatibility::client_key::RadixClientKeyVersions;
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::integer::ciphertext::{RadixCiphertext, SignedRadixCiphertext};
use crate::integer::compression_keys::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionPrivateKeys,
};
use crate::integer::BooleanBlock;
use crate::shortint::{Ciphertext as ShortintCiphertext, PBSParameters as ShortintParameters};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Client key "specialized" for radix decomposition.
///
/// This key is a simple wrapper of the [ClientKey],
/// that only encrypt and decrypt in radix decomposition.
///
/// # Example
///
/// ```rust
/// use tfhe::integer::RadixClientKey;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
///
/// // 2 * 4 = 8 bits of message
/// let num_block = 4;
/// let cks = RadixClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, num_block);
///
/// let msg = 167_u64;
///
/// let ct = cks.encrypt(msg);
///
/// let dec = cks.decrypt(&ct);
/// assert_eq!(msg, dec);
/// ```
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Versionize)]
#[versionize(RadixClientKeyVersions)]
pub struct RadixClientKey {
    key: ClientKey,
    num_blocks: usize,
}

impl AsRef<ClientKey> for RadixClientKey {
    fn as_ref(&self) -> &ClientKey {
        &self.key
    }
}

impl<'key> From<&'key RadixClientKey> for SecretEncryptionKeyView<'key> {
    fn from(value: &'key RadixClientKey) -> Self {
        Self {
            key: (&value.key.key).into(),
        }
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

    pub fn encrypt_without_padding<T: DecomposableInto<u64> + UnsignedNumeric>(
        &self,
        message: T,
    ) -> RadixCiphertext {
        self.key
            .encrypt_radix_without_padding(message, self.num_blocks)
    }

    pub fn encrypt_signed<T: DecomposableInto<u64> + SignedNumeric>(
        &self,
        message: T,
    ) -> SignedRadixCiphertext {
        self.key.encrypt_signed_radix(message, self.num_blocks)
    }

    pub fn encrypt_bool(&self, msg: bool) -> BooleanBlock {
        self.key.encrypt_bool(msg)
    }

    pub fn decrypt<T>(&self, ciphertext: &RadixCiphertext) -> T
    where
        T: RecomposableFrom<u64> + UnsignedNumeric,
    {
        self.key.decrypt_radix(ciphertext)
    }

    pub fn decrypt_without_padding<T>(&self, ctxt: &RadixCiphertext) -> T
    where
        T: RecomposableFrom<u64> + UnsignedNumeric,
    {
        self.key.decrypt_radix_without_padding(ctxt)
    }

    pub fn decrypt_signed<T>(&self, ciphertext: &SignedRadixCiphertext) -> T
    where
        T: RecomposableSignedInteger,
    {
        self.key.decrypt_signed_radix(ciphertext)
    }

    pub fn decrypt_bool(&self, ciphertext: &BooleanBlock) -> bool {
        self.key.decrypt_bool(ciphertext)
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

    pub fn new_compressed_compression_decompression_keys(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> (CompressedCompressionKey, CompressedDecompressionKey) {
        let (comp_key, decomp_key) = self
            .key
            .key
            .new_compressed_compression_decompression_keys(&private_compression_key.key);

        (
            CompressedCompressionKey { key: comp_key },
            CompressedDecompressionKey { key: decomp_key },
        )
    }
}

impl From<(ClientKey, usize)> for RadixClientKey {
    fn from((key, num_blocks): (ClientKey, usize)) -> Self {
        Self { key, num_blocks }
    }
}

impl From<RadixClientKey> for ClientKey {
    fn from(ck: RadixClientKey) -> Self {
        ck.key
    }
}
