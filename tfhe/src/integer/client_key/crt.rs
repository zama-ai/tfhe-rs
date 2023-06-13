use super::ClientKey;
use crate::integer::CrtCiphertext;

use serde::{Deserialize, Serialize};

/// Client key "specialized" for CRT decomposition.
///
/// This key is a simple wrapper of the [ClientKey],
/// that only encrypt and decrypt in CRT decomposition.
///
/// # Example
///
/// ```rust
/// use tfhe::integer::CrtClientKey;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
///
/// let basis = vec![2, 3, 5];
/// let cks = CrtClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS, basis);
///
/// let msg = 13_u64;
///
/// // Encryption:
/// let ct = cks.encrypt(msg);
///
/// // Decryption:
/// let dec = cks.decrypt(&ct);
/// assert_eq!(msg, dec);
/// ```
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct CrtClientKey {
    key: ClientKey,
    moduli: Vec<u64>,
}

impl AsRef<ClientKey> for CrtClientKey {
    fn as_ref(&self) -> &ClientKey {
        &self.key
    }
}

impl CrtClientKey {
    pub fn new<P>(parameters: P, moduli: Vec<u64>) -> Self
    where
        P: Into<crate::shortint::PBSParameters>,
    {
        Self {
            key: ClientKey::new(parameters.into()),
            moduli,
        }
    }

    pub fn encrypt(&self, message: u64) -> CrtCiphertext {
        self.key.encrypt_crt(message, self.moduli.clone())
    }

    pub fn decrypt(&self, ciphertext: &CrtCiphertext) -> u64 {
        self.key.decrypt_crt(ciphertext)
    }

    /// Returns the parameters used by the client key.
    pub fn parameters(&self) -> crate::shortint::PBSParameters {
        self.key.parameters()
    }

    pub fn moduli(&self) -> &[u64] {
        self.moduli.as_slice()
    }
}

impl From<(ClientKey, Vec<u64>)> for CrtClientKey {
    fn from((key, moduli): (ClientKey, Vec<u64>)) -> Self {
        Self { key, moduli }
    }
}
