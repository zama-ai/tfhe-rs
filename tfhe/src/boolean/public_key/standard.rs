//! Module with the definition of the encryption PublicKey.

use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::client_key::ClientKey;
use crate::boolean::engine::{BooleanEngine, WithThreadLocalEngine};
use crate::boolean::parameters::BooleanParameters;
use crate::core_crypto::entities::*;
use serde::{Deserialize, Serialize};

use super::compressed::CompressedPublicKey;

/// A structure containing a public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) lwe_public_key: LwePublicKeyOwned<u32>,
    pub(crate) parameters: BooleanParameters,
}

impl PublicKey {
    /// Encrypt a Boolean message using the public key.
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
    /// let (cks, sks) = gen_keys();
    ///
    /// let pks = PublicKey::new(&cks);
    /// # }
    /// ```
    pub fn new(client_key: &ClientKey) -> PublicKey {
        BooleanEngine::with_thread_local_mut(|engine| engine.create_public_key(client_key))
    }
}

impl From<CompressedPublicKey> for PublicKey {
    fn from(compressed_public_key: CompressedPublicKey) -> Self {
        let parameters = compressed_public_key.parameters;

        let decompressed_public_key = compressed_public_key
            .compressed_lwe_public_key
            .decompress_into_lwe_public_key();

        Self {
            lwe_public_key: decompressed_public_key,
            parameters,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::boolean::prelude::{
        BinaryBooleanGates, BooleanParameters, ClientKey, CompressedPublicKey, ServerKey,
        DEFAULT_PARAMETERS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    };
    use crate::boolean::random_boolean;

    use super::PublicKey;
    const NB_TEST: usize = 32;

    #[test]
    fn test_public_key_default_parameters() {
        test_public_key(DEFAULT_PARAMETERS);
    }

    #[test]
    fn test_public_key_tfhe_lib_parameters() {
        test_public_key(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }

    fn test_public_key(parameters: BooleanParameters) {
        let cks = ClientKey::new(&parameters);
        let sks = ServerKey::new(&cks);
        let pks = PublicKey::new(&cks);

        for _ in 0..NB_TEST {
            let b1 = random_boolean();
            let b2 = random_boolean();
            let expected_result = !(b1 && b2);

            let ct1 = pks.encrypt(b1);
            let ct2 = pks.encrypt(b2);

            let ct_res = sks.nand(&ct1, &ct2);

            let dec_ct1 = cks.decrypt(&ct1);
            let dec_ct2 = cks.decrypt(&ct2);
            let dec_nand = cks.decrypt(&ct_res);

            assert_eq!(dec_ct1, b1);
            assert_eq!(dec_ct2, b2);
            assert_eq!(dec_nand, expected_result);
        }
    }

    #[test]
    fn test_decompressing_public_key_default_parameters() {
        test_public_key(DEFAULT_PARAMETERS);
    }

    #[test]
    fn test_decompressing_public_key_tfhe_lib_parameters() {
        test_decompressing_public_key(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }

    fn test_decompressing_public_key(parameters: BooleanParameters) {
        let cks = ClientKey::new(&parameters);
        let sks = ServerKey::new(&cks);
        let cpks = CompressedPublicKey::new(&cks);
        let pks = PublicKey::from(cpks);

        for _ in 0..NB_TEST {
            let b1 = random_boolean();
            let b2 = random_boolean();
            let expected_result = !(b1 && b2);

            let ct1 = pks.encrypt(b1);
            let ct2 = pks.encrypt(b2);

            let ct_res = sks.nand(&ct1, &ct2);

            let dec_ct1 = cks.decrypt(&ct1);
            let dec_ct2 = cks.decrypt(&ct2);
            let dec_nand = cks.decrypt(&ct_res);

            assert_eq!(dec_ct1, b1);
            assert_eq!(dec_ct2, b2);
            assert_eq!(dec_nand, expected_result);
        }
    }
}
