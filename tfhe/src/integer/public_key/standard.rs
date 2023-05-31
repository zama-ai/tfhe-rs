use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{CrtCiphertext, RadixCiphertext};
use crate::integer::client_key::ClientKey;
use crate::integer::encryption::{encrypt_crt, encrypt_words_radix_impl};
use crate::integer::public_key::compressed::CompressedPublicKeyBase;
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

    pub fn encrypt_radix<T: DecomposableInto<u64>>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> RadixCiphertext<PBSOrder> {
        encrypt_words_radix_impl(&self.key, message, num_blocks, PublicKeyBase::encrypt)
    }

    pub fn encrypt_radix_without_padding(
        &self,
        message: u64,
        num_blocks: usize,
    ) -> RadixCiphertext<PBSOrder> {
        encrypt_words_radix_impl(
            &self.key,
            message,
            num_blocks,
            PublicKeyBase::encrypt_without_padding,
        )
    }
}

impl<PBSOrder: PBSOrderMarker> From<CompressedPublicKeyBase<PBSOrder>> for PublicKey<PBSOrder> {
    fn from(value: CompressedPublicKeyBase<PBSOrder>) -> Self {
        Self {
            key: value.key.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::integer::keycache::KEY_CACHE;
    use crate::shortint::parameters::*;
    use crate::shortint::PBSParameters;

    create_parametrized_test!(integer_public_key_decompression_small {
        PARAM_SMALL_MESSAGE_2_CARRY_2,
    });

    fn integer_public_key_decompression_small(param: PBSParameters) {
        let (cks, sks) = KEY_CACHE.get_from_params(param);

        let compressed_pk = crate::integer::CompressedPublicKeySmall::new(&cks);
        let pk = crate::integer::PublicKeySmall::from(compressed_pk);

        let a = pk.encrypt_radix(255u64, 4);
        let b = pk.encrypt_radix(1u64, 4);

        let c = sks.unchecked_add(&a, &b);

        let da: u64 = cks.decrypt_radix(&a);
        let db: u64 = cks.decrypt_radix(&b);
        let dc: u64 = cks.decrypt_radix(&c);

        assert_eq!(da, 255);
        assert_eq!(db, 1);
        assert_eq!(dc, 0);
    }
}
