//! Module with the definition of the encryption PublicKey.

use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::client_key::ClientKey;
use crate::boolean::engine::{BooleanEngine, WithThreadLocalEngine};
use crate::boolean::parameters::BooleanParameters;
use crate::core_crypto::entities::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A structure containing a public key.
#[derive(Clone)]
pub struct PublicKey {
    pub(crate) lwe_public_key: LwePublicKeyOwned<u32>,
    pub(crate) parameters: BooleanParameters,
}

impl PublicKey {
    /// Encrypt a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() {
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys();
    ///
    /// let pks = PublicKey::new(&cks);
    ///
    /// // Encryption of one message:
    /// let ct1 = pks.encrypt(true);
    /// let ct2 = pks.encrypt(false);
    /// let ct_res = sks.and(&ct1, &ct2);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(false, dec);
    /// # }
    /// ```
    pub fn encrypt(&self, message: bool) -> Ciphertext {
        BooleanEngine::with_thread_local_mut(|engine| engine.encrypt_with_public_key(message, self))
    }

    /// Allocate and generate a client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() {
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, mut sks) = gen_keys();
    ///
    /// let pks = PublicKey::new(&cks);
    /// # }
    /// ```
    pub fn new(client_key: &ClientKey) -> PublicKey {
        BooleanEngine::with_thread_local_mut(|engine| engine.create_public_key(client_key))
    }
}

#[derive(Serialize, Deserialize)]
struct SerializablePublicKey {
    lwe_public_key: Vec<u8>,
    parameters: BooleanParameters,
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

        Ok(Self {
            lwe_public_key: bincode::deserialize(thing.lwe_public_key.as_slice())
                .map_err(serde::de::Error::custom)?,
            parameters: thing.parameters,
        })
    }
}
