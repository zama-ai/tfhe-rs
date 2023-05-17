use crate::integer::ciphertext::{CrtCiphertext, RadixCiphertext};
use crate::integer::client_key::ClientKey;
use crate::integer::encryption::{encrypt_crt, encrypt_radix_impl};
use crate::shortint::ciphertext::{BootstrapKeyswitch, KeyswitchBootstrap};
use crate::shortint::parameters::MessageModulus;
use crate::shortint::PBSOrderMarker;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompressedPublicKeyBase<OpOrder: PBSOrderMarker> {
    key: crate::shortint::CompressedPublicKeyBase<OpOrder>,
}

pub type CompressedPublicKeyBig = CompressedPublicKeyBase<KeyswitchBootstrap>;
pub type CompressedPublicKeySmall = CompressedPublicKeyBase<BootstrapKeyswitch>;

impl CompressedPublicKeyBig {
    pub fn new<C>(client_key: &C) -> Self
    where
        C: AsRef<ClientKey>,
    {
        Self {
            key: crate::shortint::CompressedPublicKeyBase::<KeyswitchBootstrap>::new(
                &client_key.as_ref().key,
            ),
        }
    }

    pub fn encrypt_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(
            message,
            base_vec,
            crate::shortint::CompressedPublicKeyBig::encrypt_with_message_modulus,
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
        F: Fn(&crate::shortint::CompressedPublicKeyBig, u64, MessageModulus) -> Block,
        CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
    {
        encrypt_crt(&self.key, message, base_vec, encrypt_block)
    }
}

impl CompressedPublicKeySmall {
    pub fn new<C>(client_key: &C) -> Self
    where
        C: AsRef<ClientKey>,
    {
        Self {
            key: crate::shortint::CompressedPublicKeyBase::<BootstrapKeyswitch>::new(
                &client_key.as_ref().key,
            ),
        }
    }
}

impl<OpOrder: PBSOrderMarker> CompressedPublicKeyBase<OpOrder> {
    pub fn parameters(&self) -> crate::shortint::PBSParameters {
        self.key.parameters.pbs_parameters().unwrap()
    }

    pub fn encrypt_radix<T: bytemuck::Pod>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> RadixCiphertext<OpOrder> {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::CompressedPublicKeyBase::encrypt,
        )
    }

    pub fn encrypt_radix_without_padding(
        &self,
        message: u64,
        num_blocks: usize,
    ) -> RadixCiphertext<OpOrder> {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::CompressedPublicKeyBase::encrypt_without_padding,
        )
    }

    pub fn encrypt_words_radix<Block, RadixCiphertextType, T, F>(
        &self,
        message_words: T,
        num_blocks: usize,
        encrypt_block: F,
    ) -> RadixCiphertextType
    where
        T: bytemuck::Pod,
        F: Fn(&crate::shortint::CompressedPublicKeyBase<OpOrder>, u64) -> Block,
        RadixCiphertextType: From<Vec<Block>>,
    {
        encrypt_radix_impl(&self.key, message_words, num_blocks, encrypt_block)
    }
}
