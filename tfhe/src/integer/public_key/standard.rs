use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{CrtCiphertext, RadixCiphertext};
use crate::integer::client_key::ClientKey;
use crate::integer::encryption::{encrypt_crt, encrypt_words_radix_impl};
use crate::integer::public_key::compressed::CompressedPublicKey;
use crate::shortint::parameters::MessageModulus;
use crate::shortint::PublicKey as ShortintPublicKey;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    key: ShortintPublicKey,
}

impl PublicKey {
    pub fn new<C>(client_key: &C) -> Self
    where
        C: AsRef<ClientKey>,
    {
        Self {
            key: ShortintPublicKey::new(&client_key.as_ref().key),
        }
    }

    pub fn encrypt_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(
            message,
            base_vec,
            ShortintPublicKey::encrypt_with_message_modulus,
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
        F: Fn(&ShortintPublicKey, u64, MessageModulus) -> Block,
        CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
    {
        encrypt_crt(&self.key, message, base_vec, encrypt_block)
    }

    pub fn parameters(&self) -> crate::shortint::PBSParameters {
        self.key.parameters.pbs_parameters().unwrap()
    }

    pub fn encrypt_radix<T: DecomposableInto<u64>>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> RadixCiphertext {
        encrypt_words_radix_impl(&self.key, message, num_blocks, ShortintPublicKey::encrypt)
    }

    pub fn encrypt_radix_without_padding(
        &self,
        message: u64,
        num_blocks: usize,
    ) -> RadixCiphertext {
        encrypt_words_radix_impl(
            &self.key,
            message,
            num_blocks,
            ShortintPublicKey::encrypt_without_padding,
        )
    }
}

impl From<CompressedPublicKey> for PublicKey {
    fn from(value: CompressedPublicKey) -> Self {
        Self {
            key: value.key.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::integer::keycache::KEY_CACHE;
    use crate::shortint::parameters::*;
    use crate::shortint::ClassicPBSParameters;

    create_parametrized_test!(integer_public_key_decompression_small {
        PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    });

    fn integer_public_key_decompression_small(param: ClassicPBSParameters) {
        let (cks, sks) = KEY_CACHE.get_from_params(param);

        let compressed_pk = crate::integer::CompressedPublicKey::new(&cks);
        let pk = crate::integer::PublicKey::from(compressed_pk);

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
