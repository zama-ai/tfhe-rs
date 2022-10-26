//! Module with the definition of the ClientKey.

use crate::core_crypto::prelude::*;
#[cfg(not(feature = "__wasm_api"))]
use crate::shortint::ciphertext::Ciphertext;
#[cfg(not(feature = "__wasm_api"))]
use crate::shortint::engine::ShortintEngine;
#[cfg(not(feature = "__wasm_api"))]
use crate::shortint::parameters::MessageModulus;
use crate::shortint::parameters::Parameters;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;

/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs.
/// This secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
/// switching keys.
/// * `parameters` - the cryptographic parameter set.
#[derive(Clone, Debug, PartialEq)]
pub struct ClientKey {
    /// The actual encryption / decryption key
    pub(crate) lwe_secret_key: LweSecretKey64,
    pub(crate) glwe_secret_key: GlweSecretKey64,
    /// Key used as the output of the keyswitch operation
    pub(crate) lwe_secret_key_after_ks: LweSecretKey64,
    pub parameters: Parameters,
}

#[cfg(not(feature = "__wasm_api"))]
impl ClientKey {
    /// Generates a client key.
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
    pub fn new(parameters: Parameters) -> ClientKey {
        ShortintEngine::with_thread_local_mut(|engine| engine.new_client_key(parameters).unwrap())
    }

    /// Encrypts a small integer message using the client key.
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
    pub fn encrypt(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| engine.encrypt(self, message).unwrap())
    }

    /// Encrypts a small integer message using the client key with a specific message modulus
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
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_with_message_modulus(self, message, message_modulus)
                .unwrap()
        })
    }

    /// Encrypts an integer without reducing the input message modulus the message space
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
    pub fn unchecked_encrypt(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_encrypt(self, message).unwrap()
        })
    }

    /// Decrypts a ciphertext encrypting an integer message and carries using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{ClientKey, Parameters};
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_message_and_carry(&self, ct: &Ciphertext) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.decrypt_message_and_carry(self, ct).unwrap()
        })
    }

    /// Decrypts a ciphertext encrypting a message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{ClientKey, Parameters};
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt(&self, ct: &Ciphertext) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| engine.decrypt(self, ct).unwrap())
    }

    /// Encrypts a small integer message using the client key without padding bit.
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
    pub fn encrypt_without_padding(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_without_padding(self, message).unwrap()
        })
    }

    /// Decrypts a ciphertext encrypting an integer message and carries using the client key,
    /// where the ciphertext is assumed to not have any padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_1;
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
    /// ```
    pub fn decrypt_message_and_carry_without_padding(&self, ct: &Ciphertext) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .decrypt_message_and_carry_without_padding(self, ct)
                .unwrap()
        })
    }

    /// Decrypts a ciphertext encrypting an integer message using the client key,
    /// where the ciphertext is assumed to not have any padding bit.
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
    /// let modulus = 4;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_without_padding(&ct);
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn decrypt_without_padding(&self, ct: &Ciphertext) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.decrypt_without_padding(self, ct).unwrap()
        })
    }

    /// Encrypts a small integer message using the client key without padding bit with some modulus.
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
    pub fn encrypt_native_crt(&self, message: u64, message_modulus: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_native_crt(self, message, message_modulus)
                .unwrap()
        })
    }

    /// Decrypts a ciphertext encrypting an integer message using the client key,
    /// where the ciphertext is assumed to not have any padding bit and is related to some modulus.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{ClientKey, Parameters};
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(Parameters::default());
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
    /// ```
    pub fn decrypt_message_native_crt(&self, ct: &Ciphertext, message_modulus: u8) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .decrypt_message_native_crt(self, ct, message_modulus as u64)
                .unwrap()
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableClientKey {
    lwe_secret_key: Vec<u8>,
    glwe_secret_key: Vec<u8>,
    lwe_secret_key_after_ks: Vec<u8>,
    parameters: Parameters,
}

impl Serialize for ClientKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser_eng = DefaultSerializationEngine::new(()).map_err(serde::ser::Error::custom)?;

        let lwe_secret_key = ser_eng
            .serialize(&self.lwe_secret_key)
            .map_err(serde::ser::Error::custom)?;
        let glwe_secret_key = ser_eng
            .serialize(&self.glwe_secret_key)
            .map_err(serde::ser::Error::custom)?;
        let lwe_secret_key_after_ks = ser_eng
            .serialize(&self.lwe_secret_key_after_ks)
            .map_err(serde::ser::Error::custom)?;

        SerializableClientKey {
            lwe_secret_key,
            glwe_secret_key,
            lwe_secret_key_after_ks,
            parameters: self.parameters,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ClientKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let thing =
            SerializableClientKey::deserialize(deserializer).map_err(serde::de::Error::custom)?;
        let mut de_eng = DefaultSerializationEngine::new(()).map_err(serde::de::Error::custom)?;

        Ok(Self {
            lwe_secret_key: de_eng
                .deserialize(thing.lwe_secret_key.as_slice())
                .map_err(serde::de::Error::custom)?,
            glwe_secret_key: de_eng
                .deserialize(thing.glwe_secret_key.as_slice())
                .map_err(serde::de::Error::custom)?,
            lwe_secret_key_after_ks: de_eng
                .deserialize(thing.lwe_secret_key_after_ks.as_slice())
                .map_err(serde::de::Error::custom)?,
            parameters: thing.parameters,
        })
    }
}
