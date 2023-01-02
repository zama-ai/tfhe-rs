//! Module with the definition of the PublicKey.
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::Ciphertext;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{MessageModulus, Parameters};
use crate::shortint::{ClientKey, CompressedPublicKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;

/// A structure containing a public key.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    pub(crate) lwe_public_key: LwePublicKeyOwned<u64>,
    pub parameters: Parameters,
}

impl PublicKey {
    /// Generate a public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::ClientKey;
    /// use tfhe::shortint::parameters::Parameters;
    /// use tfhe::shortint::public_key::PublicKey;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let pk = PublicKey::new(&cks);
    /// ```
    pub fn new(client_key: &ClientKey) -> PublicKey {
        ShortintEngine::with_thread_local_mut(|engine| engine.new_public_key(client_key).unwrap())
    }

    pub fn bc_new(client_key: &ClientKey) -> PublicKey {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.bc_new_public_key(client_key).unwrap()
        })
    }

    /// Encrypt a small integer message using the client key.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// use tfhe::shortint::{ClientKey, PublicKey, ServerKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let pk = PublicKey::new(&cks);
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
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn encrypt(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_with_public_key(self, message).unwrap()
        })
    }

    /// Encrypt a small integer message using the client key with a specific message modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::MessageModulus;
    /// use tfhe::shortint::{ClientKey, Parameters, PublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let pk = PublicKey::new(&cks);
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
                .encrypt_with_message_modulus_and_public_key(self, message, message_modulus)
                .unwrap()
        })
    }

    /// Encrypt an integer without reducing the input message modulus the message space
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{ClientKey, Parameters, PublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let pk = PublicKey::new(&cks);
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
                .unchecked_encrypt_with_public_key(self, message)
                .unwrap()
        })
    }

    /// Encrypt a small integer message using the client key without padding bit.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// use tfhe::shortint::{ClientKey, PublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// // DISCLAIMER: Note that this parameter is not guaranteed to be secure
    /// let pk = PublicKey::new(&cks);
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
                .encrypt_without_padding_with_public_key(self, message)
                .unwrap()
        })
    }

    /// Encrypt a small integer message using the client key without padding bit with some modulus.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{ClientKey, Parameters, PublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(Parameters::default());
    ///
    /// let pk = PublicKey::new(&cks);
    ///
    /// let msg = 2;
    /// let modulus = 3;
    ///
    /// // Encryption of one message:
    /// let ct = pk.encrypt_native_crt(msg, modulus);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus as u64);
    /// ```
    pub fn encrypt_native_crt(&self, message: u64, message_modulus: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_native_crt_with_public_key(self, message, message_modulus)
                .unwrap()
        })
    }

    pub fn rc_unchecked_encrypt(&self, message: u64) -> (Ciphertext, Vec<u64>) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .rc_unchecked_encrypt_with_public_key(self, message)
                .unwrap()
        })
    }

    pub fn lwe_public_key(&self) -> &LwePublicKeyOwned<u64> {
        &self.lwe_public_key
    }
}

impl From<CompressedPublicKey> for PublicKey {
    fn from(compressed_public_key: CompressedPublicKey) -> Self {
        let parameters = compressed_public_key.parameters;

        let decompressed_public_key = compressed_public_key
            .lwe_public_key
            .decompress_into_lwe_public_key();

        Self {
            lwe_public_key: decompressed_public_key,
            parameters,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SerializablePublicKey {
    lwe_public_key: Vec<u8>,
    parameters: Parameters,
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let lwe_public_key =
            bincode::serialize(&self.lwe_public_key).map_err(serde::ser::Error::custom)?;

        SerializablePublicKey {
            lwe_public_key,
            parameters: self.parameters,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let thing =
            SerializablePublicKey::deserialize(deserializer).map_err(serde::de::Error::custom)?;

        let lwe_public_key = bincode::deserialize(thing.lwe_public_key.as_slice())
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            lwe_public_key,
            parameters: thing.parameters,
        })
    }
}
