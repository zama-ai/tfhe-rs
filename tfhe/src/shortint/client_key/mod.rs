//! Module with the definition of the ClientKey.

use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::{
    BootstrapKeyswitch, CiphertextBase, CompressedCiphertextBase, KeyswitchBootstrap,
    PBSOrderMarker,
};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{MessageModulus, Parameters};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs.
/// This secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
/// switching keys.
/// * `parameters` - the cryptographic parameter set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientKey<OpOrder: PBSOrderMarker> {
    /// The LWE secret key equivalent to the GLWE secret key
    pub(crate) large_lwe_secret_key: LweSecretKeyOwned<u64>,
    pub(crate) glwe_secret_key: GlweSecretKeyOwned<u64>,
    /// Key used as the output of the keyswitch operation
    pub(crate) small_lwe_secret_key: LweSecretKeyOwned<u64>,
    pub parameters: Parameters<OpOrder>,
}

pub type ClientKeyBig = ClientKey<KeyswitchBootstrap>;
pub type ClientKeySmall = ClientKey<BootstrapKeyswitch>;

impl<OpOrder: PBSOrderMarker> ClientKey<OpOrder> {
    /// Generate a client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::ClientKey;
    /// use tfhe::shortint::parameters::Parameters;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(Parameters::default());
    /// ```
    pub fn new(parameters: Parameters<OpOrder>) -> ClientKey<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| engine.new_client_key(parameters).unwrap())
    }

    /// Encrypt a small integer message using the client key.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// use tfhe::shortint::ClientKey;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encryption of one message that is within the encrypted message modulus:
    /// let msg = 3;
    /// let ct = cks.encrypt(msg);
    ///
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// // Encryption of one message that is outside the encrypted message modulus:
    /// let msg = 5;
    /// let ct = cks.encrypt(msg);
    ///
    /// let dec = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn encrypt(&self, message: u64) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| engine.encrypt(self, message).unwrap())
    }

    /// Encrypt a small integer message using the client key returning a compressed ciphertext.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// use tfhe::shortint::ClientKey;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encryption of one message that is within the encrypted message modulus:
    /// let msg = 3;
    /// let ct = cks.encrypt_compressed(msg);
    ///
    /// let ct = ct.decompress();
    ///
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// // Encryption of one message that is outside the encrypted message modulus:
    /// let msg = 5;
    /// let ct = cks.encrypt_compressed(msg);
    ///
    /// let ct = ct.decompress();
    ///
    /// let dec = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn encrypt_compressed(&self, message: u64) -> CompressedCiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_compressed(self, message).unwrap()
        })
    }

    /// Encrypt a small integer message using the client key with a specific message modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::MessageModulus;
    /// use tfhe::shortint::{ClientKey, Parameters};
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_with_message_modulus(msg, MessageModulus(6));
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_with_message_modulus(
        &self,
        message: u64,
        message_modulus: MessageModulus,
    ) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_with_message_modulus(self, message, message_modulus)
                .unwrap()
        })
    }

    /// Encrypt a small integer message using the client key with a specific message modulus
    /// returning a compressed ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::MessageModulus;
    /// use tfhe::shortint::{ClientKey, Parameters};
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_with_message_modulus_compressed(msg, MessageModulus(6));
    ///
    /// let ct = ct.decompress();
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_with_message_modulus_compressed(
        &self,
        message: u64,
        message_modulus: MessageModulus,
    ) -> CompressedCiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_with_message_modulus_compressed(self, message, message_modulus)
                .unwrap()
        })
    }

    /// Encrypt an integer without reducing the input message modulus the message space
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{ClientKey, Parameters};
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let msg = 7;
    /// let ct = cks.unchecked_encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 1  |   1 1   |
    ///
    /// let dec = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn unchecked_encrypt(&self, message: u64) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_encrypt(self, message).unwrap()
        })
    }
    /// Decrypt a ciphertext encrypting an integer message and carries using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// let cks = ClientKey::new(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_small(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_message_and_carry(&self, ct: &CiphertextBase<OpOrder>) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.decrypt_message_and_carry(self, ct).unwrap()
        })
    }

    /// Decrypt a ciphertext encrypting a message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    /// use tfhe::shortint::{ClientKey, Parameters};
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// let cks = ClientKey::new(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_small(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt(&self, ct: &CiphertextBase<OpOrder>) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| engine.decrypt(self, ct).unwrap())
    }

    /// Encrypt a small integer message using the client key without padding bit.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// use tfhe::shortint::ClientKey;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encryption of one message that is within the encrypted message modulus:
    /// let msg = 6;
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// let dec = cks.decrypt_message_and_carry_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_without_padding(&self, message: u64) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_without_padding(self, message).unwrap()
        })
    }

    /// Encrypt a small integer message using the client key without padding bit returning a
    /// compressed message.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// use tfhe::shortint::ClientKey;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encryption of one message that is within the encrypted message modulus:
    /// let msg = 6;
    /// let ct = cks.encrypt_without_padding_compressed(msg);
    ///
    /// let ct = ct.decompress();
    ///
    /// let dec = cks.decrypt_message_and_carry_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_without_padding_compressed(
        &self,
        message: u64,
    ) -> CompressedCiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_without_padding_compressed(self, message)
                .unwrap()
        })
    }

    /// Decrypt a ciphertext encrypting an integer message and carries using the client key,
    /// where the ciphertext is assumed to not have any padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_1_CARRY_1, PARAM_SMALL_MESSAGE_1_CARRY_1};
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_1_CARRY_1);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_and_carry_without_padding(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// let cks = ClientKey::new(PARAM_SMALL_MESSAGE_1_CARRY_1);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_and_carry_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_message_and_carry_without_padding(&self, ct: &CiphertextBase<OpOrder>) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .decrypt_message_and_carry_without_padding(self, ct)
                .unwrap()
        })
    }

    /// Decrypt a ciphertext encrypting an integer message using the client key,
    /// where the ciphertext is assumed to not have any padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 7;
    /// let modulus = 4;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_without_padding(&ct);
    /// assert_eq!(msg % modulus, dec);
    ///
    /// let cks = ClientKey::new(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_without_padding(&ct);
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn decrypt_without_padding(&self, ct: &CiphertextBase<OpOrder>) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.decrypt_without_padding(self, ct).unwrap()
        })
    }

    /// Encrypt a small integer message using the client key without padding bit with some modulus.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{ClientKey, Parameters};
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let msg = 2;
    /// let modulus = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt(msg, modulus);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus as u64);
    /// ```
    pub fn encrypt_native_crt(&self, message: u64, message_modulus: u8) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_native_crt(self, message, message_modulus)
                .unwrap()
        })
    }

    /// Encrypt a small integer message using the client key without padding bit with some modulus
    /// returning a compressed ciphertext.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{ClientKey, Parameters};
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let msg = 2;
    /// let modulus = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt_compressed(msg, modulus);
    ///
    /// let ct = ct.decompress();
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus as u64);
    /// ```
    pub fn encrypt_native_crt_compressed(
        &self,
        message: u64,
        message_modulus: u8,
    ) -> CompressedCiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_native_crt_compressed(self, message, message_modulus)
                .unwrap()
        })
    }

    /// Decrypt a ciphertext encrypting an integer message using the client key,
    /// where the ciphertext is assumed to not have any padding bit and is related to some modulus.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2;
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 1;
    /// let modulus = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt(msg, modulus);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus as u64);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt(msg, modulus);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus as u64);
    /// ```
    pub fn decrypt_message_native_crt(
        &self,
        ct: &CiphertextBase<OpOrder>,
        message_modulus: u8,
    ) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .decrypt_message_native_crt(self, ct, message_modulus as u64)
                .unwrap()
        })
    }
}
