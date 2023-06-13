//! Module with the definition of the compressed PublicKey.
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::{Ciphertext, PBSOrder};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{MessageModulus, ShortintParameterSet};
use crate::shortint::ClientKey;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// A structure containing a compressed public key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressedPublicKey {
    pub(crate) lwe_public_key: SeededLwePublicKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
    pub pbs_order: PBSOrder,
}

impl CompressedPublicKey {
    /// Generate a public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::public_key::CompressedPublicKey;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = CompressedPublicKey::new(&cks);
    /// ```
    pub fn new(client_key: &ClientKey) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_compressed_public_key(client_key).unwrap()
        })
    }

    /// Encrypts a small integer message using the client key.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{ClientKey, CompressedPublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = CompressedPublicKey::new(&cks);
    ///
    /// // Encryption of one message that is within the encrypted message modulus:
    /// let msg = 3;
    /// let ct = pk.encrypt(msg);
    ///
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// // Encryption of one message that is outside the encrypted message modulus:
    /// let msg = 5;
    /// let ct = pk.encrypt(msg);
    ///
    /// let dec = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn encrypt(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_with_compressed_public_key(self, message)
                .unwrap()
        })
    }

    /// Encrypts a small integer message using the client key with a specific message modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{MessageModulus, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
    /// use tfhe::shortint::{ClientKey, CompressedPublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = CompressedPublicKey::new(&cks);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = pk.encrypt_with_message_modulus(msg, MessageModulus(6));
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_with_message_modulus(
        &self,
        message: u64,
        message_modulus: MessageModulus,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_with_message_modulus_and_compressed_public_key(
                    self,
                    message,
                    message_modulus,
                )
                .unwrap()
        })
    }

    /// Encrypts an integer without reducing the input message modulus the message space
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{ClientKey, CompressedPublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = CompressedPublicKey::new(&cks);
    ///
    /// let msg = 7;
    /// let ct = pk.unchecked_encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 1  |   1 1   |
    ///
    /// let dec = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn unchecked_encrypt(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_encrypt_with_compressed_public_key(self, message)
                .unwrap()
        })
    }

    /// Encrypts a small integer message using the client key without padding bit.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{ClientKey, CompressedPublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// // DISCLAIMER: Note that this parameter is not guaranteed to be secure
    /// let pk = CompressedPublicKey::new(&cks);
    ///
    /// // Encryption of one message that is within the encrypted message modulus:
    /// let msg = 6;
    /// let ct = pk.encrypt_without_padding(msg);
    ///
    /// let dec = cks.decrypt_message_and_carry_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_without_padding(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_without_padding_with_compressed_public_key(self, message)
                .unwrap()
        })
    }

    /// Encrypts a small integer message using the client key without padding bit with some modulus.
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{ClientKey, CompressedPublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = CompressedPublicKey::new(&cks);
    ///
    /// let msg = 2;
    /// let modulus = 3;
    /// ```
    pub fn encrypt_native_crt(&self, message: u64, message_modulus: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_native_crt_with_compressed_public_key(self, message, message_modulus)
                .unwrap()
        })
    }
}
