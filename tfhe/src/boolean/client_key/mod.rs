//! The secret key of the client.
//!
//! This module implements the generation of the client' secret keys, together with the
//! encryption and decryption methods.

use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::engine::{BooleanEngine, WithThreadLocalEngine};
use crate::boolean::parameters::BooleanParameters;
use crate::core_crypto::entities::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Formatter};

/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs.
/// This secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
/// switching keys.
/// * `parameters` - the cryptographic parameter set.
#[derive(Clone)]
pub struct ClientKey {
    pub(crate) lwe_secret_key: LweSecretKeyOwned<u32>,
    pub(crate) glwe_secret_key: GlweSecretKeyOwned<u32>,
    pub(crate) parameters: BooleanParameters,
}

impl PartialEq for ClientKey {
    fn eq(&self, other: &Self) -> bool {
        self.parameters == other.parameters
            && self.lwe_secret_key == other.lwe_secret_key
            && self.glwe_secret_key == other.glwe_secret_key
    }
}

impl Debug for ClientKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientKey {{ ")?;
        write!(f, "lwe_secret_key: {:?}, ", self.lwe_secret_key)?;
        write!(f, "glwe_secret_key: {:?}, ", self.glwe_secret_key)?;
        write!(f, "parameters: {:?}, ", self.parameters)?;
        write!(f, "engine: CoreEngine, ")?;
        write!(f, "}}")?;
        Ok(())
    }
}

impl ClientKey {
    /// Encrypt a Boolean message using the client key.
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
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(true, dec);
    /// # }
    /// ```
    pub fn encrypt(&self, message: bool) -> Ciphertext {
        BooleanEngine::with_thread_local_mut(|engine| engine.encrypt(message, self))
    }

    /// Decrypt a ciphertext encrypting a Boolean message using the client key.
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
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(true, dec);
    /// # }
    /// ```
    pub fn decrypt(&self, ct: &Ciphertext) -> bool {
        BooleanEngine::with_thread_local_mut(|engine| engine.decrypt(ct, self))
    }

    /// Allocate and generate a client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() {
    /// use tfhe::boolean::client_key::ClientKey;
    /// use tfhe::boolean::parameters::TFHE_LIB_PARAMETERS;
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(&TFHE_LIB_PARAMETERS);
    /// # }
    /// ```
    pub fn new(parameter_set: &BooleanParameters) -> ClientKey {
        BooleanEngine::with_thread_local_mut(|engine| engine.create_client_key(*parameter_set))
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableClientKey {
    lwe_secret_key: Vec<u8>,
    glwe_secret_key: Vec<u8>,
    parameters: BooleanParameters,
}

impl Serialize for ClientKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let lwe_secret_key =
            bincode::serialize(&self.lwe_secret_key).map_err(serde::ser::Error::custom)?;
        let glwe_secret_key =
            bincode::serialize(&self.glwe_secret_key).map_err(serde::ser::Error::custom)?;

        SerializableClientKey {
            lwe_secret_key,
            glwe_secret_key,
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

        Ok(Self {
            lwe_secret_key: bincode::deserialize(thing.lwe_secret_key.as_slice())
                .map_err(serde::de::Error::custom)?,
            glwe_secret_key: bincode::deserialize(thing.glwe_secret_key.as_slice())
                .map_err(serde::de::Error::custom)?,
            parameters: thing.parameters,
        })
    }
}
