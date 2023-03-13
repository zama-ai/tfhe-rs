//! Module with the definition of the encryption PublicKey.

use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::client_key::ClientKey;
use crate::boolean::engine::{BooleanEngine, WithThreadLocalEngine};
use crate::boolean::parameters::BooleanParameters;
use crate::core_crypto::entities::*;
use serde::{Deserialize, Serialize};

/// A structure containing a public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
