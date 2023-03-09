use crate::integer::ciphertext::{CrtCiphertext, RadixCiphertext};
use crate::integer::client_key::ClientKey;
use crate::integer::encryption::{encrypt_crt, encrypt_words_radix_impl, AsLittleEndianWords};
use crate::shortint::parameters::MessageModulus;
use crate::shortint::CompressedPublicKey as ShortintCompressedPublicKey;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompressedPublicKey {
    key: ShortintCompressedPublicKey,
}

impl CompressedPublicKey {
    pub fn new(client_key: &ClientKey) -> Self {
        Self {
            key: ShortintCompressedPublicKey::new(&client_key.key),
        }
    }
    pub fn parameters(&self) -> crate::shortint::Parameters {
        self.key.parameters
    }

    pub fn encrypt_radix<T: AsLittleEndianWords>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> RadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::CompressedPublicKey::encrypt,
        )
    }

    pub fn encrypt_radix_without_padding(
        &self,
        message: u64,
        num_blocks: usize,
    ) -> RadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::CompressedPublicKey::encrypt_without_padding,
        )
    }

    pub fn encrypt_words_radix<Block, RadixCiphertextType, T, F>(
        &self,
        message_words: T,
        num_blocks: usize,
        encrypt_block: F,
    ) -> RadixCiphertextType
    where
        T: AsLittleEndianWords,
        F: Fn(&crate::shortint::CompressedPublicKey, u64) -> Block,
        RadixCiphertextType: From<Vec<Block>>,
    {
        encrypt_words_radix_impl(&self.key, message_words, num_blocks, encrypt_block)
    }

    pub fn encrypt_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(
            message,
            base_vec,
            crate::shortint::CompressedPublicKey::encrypt_with_message_modulus,
        )
    }

    pub fn encrypt_native_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(message, base_vec, |cks, msg, moduli| {
            cks.encrypt_native_crt(msg, moduli.0 as u8)
        })
    }

    fn encrypt_crt_impl<Block, CrtCiphertextType, F>(
        &self,
        message: u64,
        base_vec: Vec<u64>,
        encrypt_block: F,
    ) -> CrtCiphertextType
    where
        F: Fn(&crate::shortint::CompressedPublicKey, u64, MessageModulus) -> Block,
        CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
    {
        encrypt_crt(&self.key, message, base_vec, encrypt_block)
    }
}
