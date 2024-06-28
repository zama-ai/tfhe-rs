use tfhe_versionable::Versionize;

use crate::integer::backward_compatibility::public_key::CompressedPublicKeyVersions;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{CrtCiphertext, RadixCiphertext};
use crate::integer::client_key::ClientKey;
use crate::integer::encryption::{create_clear_radix_block_iterator, encrypt_crt};
use crate::integer::{BooleanBlock, SignedRadixCiphertext};
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::MessageModulus;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedPublicKeyVersions)]
pub struct CompressedPublicKey {
    pub(crate) key: crate::shortint::CompressedPublicKey,
}

impl CompressedPublicKey {
    pub fn new<C>(client_key: &C) -> Self
    where
        C: AsRef<ClientKey>,
    {
        Self {
            key: crate::shortint::CompressedPublicKey::new(&client_key.as_ref().key),
        }
    }

    /// Deconstruct a [`CompressedPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> crate::shortint::CompressedPublicKey {
        self.key
    }

    /// Construct a [`CompressedPublicKey`] from its constituents.
    pub fn from_raw_parts(key: crate::shortint::CompressedPublicKey) -> Self {
        Self { key }
    }

    pub fn encrypt_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        // let mut ctxt_vect = Vec::with_capacity(base_vec.len());

        // // Put each decomposition into a new ciphertext
        // for modulus in base_vec.iter().copied() {
        //     let ct = self
        //         .key
        //         .encrypt_many_with_message_modulus(message, MessageModulus(modulus as usize));

        //     ctxt_vect.push(ct);
        // }

        // CrtCiphertext {
        //     blocks: ctxt_vect,
        //     moduli: base_vec,
        // }
        todo!()
    }

    pub fn encrypt_native_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        // let mut ctxt_vect = Vec::with_capacity(base_vec.len());

        // // Put each decomposition into a new ciphertext
        // for modulus in base_vec.iter().copied() {
        //     let ct = self
        //         .key
        //         .encrypt_native_crt(message, MessageModulus(modulus as usize));

        //     ctxt_vect.push(ct);
        // }

        // CrtCiphertext {
        //     blocks: ctxt_vect,
        //     moduli: base_vec,
        // }

        // // self.encrypt_crt_impl(message, base_vec, |cks, msg, moduli| {
        // //     cks.encrypt_native_crt(msg, moduli.0 as u8)
        // // })

        todo!()
    }

    pub fn parameters(&self) -> crate::shortint::PBSParameters {
        self.key.parameters.pbs_parameters().unwrap()
    }

    pub fn encrypt_radix<T: DecomposableInto<u64>>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> RadixCiphertext {
        let message_modulus = self.key.parameters.message_modulus();
        let clear_block_iterator =
            create_clear_radix_block_iterator(message, message_modulus, num_blocks);

        let blocks = self.key.encrypt_many(clear_block_iterator);

        RadixCiphertext { blocks }
    }

    pub fn encrypt_signed_radix<T: DecomposableInto<u64>>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> SignedRadixCiphertext {
        let message_modulus = self.key.parameters.message_modulus();
        let clear_block_iterator =
            create_clear_radix_block_iterator(message, message_modulus, num_blocks);

        let blocks = self.key.encrypt_many(clear_block_iterator);

        SignedRadixCiphertext { blocks }
    }

    pub fn encrypt_bool(&self, message: bool) -> BooleanBlock {
        let mut ciphertext = self.key.encrypt(u64::from(message));
        ciphertext.degree = Degree::new(1);
        BooleanBlock::new_unchecked(ciphertext)
    }

    pub fn encrypt_radix_without_padding(
        &self,
        message: u64,
        num_blocks: usize,
    ) -> RadixCiphertext {
        let message_modulus = self.key.parameters.message_modulus();
        let clear_block_iterator =
            create_clear_radix_block_iterator(message, message_modulus, num_blocks);

        let blocks = self.key.encrypt_many_without_padding(clear_block_iterator);

        RadixCiphertext { blocks }
    }
}
