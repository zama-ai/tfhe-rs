use crate::integer::ciphertext::{CrtCiphertext, RadixCiphertext};
use crate::integer::client_key::ClientKey;
use crate::integer::encryption::{encrypt_crt, encrypt_words_radix_impl, AsLittleEndianWords};
use crate::shortint::ciphertext::{BootstrapKeyswitch, KeyswitchBootstrap};
use crate::shortint::parameters::MessageModulus;
use crate::shortint::{PBSOrderMarker, PublicKeyBase};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicKey<PBSOrder: PBSOrderMarker> {
    key: PublicKeyBase<PBSOrder>,
}

pub type PublicKeyBig = PublicKey<KeyswitchBootstrap>;
pub type PublicKeySmall = PublicKey<BootstrapKeyswitch>;

impl PublicKeyBig {
    pub fn new<C>(client_key: &C) -> Self
    where
        C: AsRef<ClientKey>,
    {
        Self {
            key: PublicKeyBase::<KeyswitchBootstrap>::new(&client_key.as_ref().key),
        }
    }

    pub fn encrypt_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(
            message,
            base_vec,
            PublicKeyBase::encrypt_with_message_modulus,
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
        F: Fn(&PublicKeyBase<KeyswitchBootstrap>, u64, MessageModulus) -> Block,
        CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
    {
        encrypt_crt(&self.key, message, base_vec, encrypt_block)
    }
}

impl PublicKeySmall {
    pub fn new<C>(client_key: &C) -> Self
    where
        C: AsRef<ClientKey>,
    {
        Self {
            key: PublicKeyBase::<BootstrapKeyswitch>::new(&client_key.as_ref().key),
        }
    }
}

impl<PBSOrder: PBSOrderMarker> PublicKey<PBSOrder> {
    pub fn parameters(&self) -> crate::shortint::PBSParameters {
        self.key.parameters.pbs_parameters().unwrap()
    }

    pub fn encrypt_radix<T: AsLittleEndianWords>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> RadixCiphertext<PBSOrder> {
        self.encrypt_words_radix(message, num_blocks, PublicKeyBase::encrypt)
    }

    pub fn encrypt_radix_without_padding(
        &self,
        message: u64,
        num_blocks: usize,
    ) -> RadixCiphertext<PBSOrder> {
        self.encrypt_words_radix(message, num_blocks, PublicKeyBase::encrypt_without_padding)
    }

    pub fn encrypt_words_radix<Block, RadixCiphertextType, T, F>(
        &self,
        message_words: T,
        num_blocks: usize,
        encrypt_block: F,
    ) -> RadixCiphertextType
    where
        T: AsLittleEndianWords,
        F: Fn(&PublicKeyBase<PBSOrder>, u64) -> Block,
        RadixCiphertextType: From<Vec<Block>>,
    {
        encrypt_words_radix_impl(&self.key, message_words, num_blocks, encrypt_block)
    }
}
