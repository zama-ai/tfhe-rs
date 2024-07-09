//! Module with the definition of the encryption PublicKey.

use super::compressed::CompressedPublicKey;
use crate::boolean::backward_compatibility::public_key::PublicKeyVersions;
use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::client_key::ClientKey;
use crate::boolean::engine::{BooleanEngine, WithThreadLocalEngine};
use crate::boolean::parameters::BooleanParameters;
use crate::core_crypto::entities::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// A structure containing a public key.
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(PublicKeyVersions)]
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
    /// assert!(!dec);
    /// ```
    pub fn encrypt(&self, message: bool) -> Ciphertext {
        BooleanEngine::with_thread_local_mut(|engine| engine.encrypt_with_public_key(message, self))
    }

    /// Allocate and generate a client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys();
    ///
    /// let pks = PublicKey::new(&cks);
    /// ```
    pub fn new(client_key: &ClientKey) -> Self {
        BooleanEngine::with_thread_local_mut(|engine| engine.create_public_key(client_key))
    }

    /// Deconstruct a [`PublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> (LwePublicKeyOwned<u32>, BooleanParameters) {
        let Self {
            lwe_public_key,
            parameters,
        } = self;

        (lwe_public_key, parameters)
    }

    /// Construct a [`PublicKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        lwe_public_key: LwePublicKeyOwned<u32>,
        parameters: BooleanParameters,
    ) -> Self {
        let ciphertext_lwe_dimension = match parameters.encryption_key_choice {
            crate::core_crypto::commons::parameters::EncryptionKeyChoice::Big => parameters
                .glwe_dimension
                .to_equivalent_lwe_dimension(parameters.polynomial_size),
            crate::core_crypto::commons::parameters::EncryptionKeyChoice::Small => {
                parameters.lwe_dimension
            }
        };

        assert_eq!(
            lwe_public_key.lwe_size().to_lwe_dimension(),
            ciphertext_lwe_dimension,
            "Mismatch between LwePublicKeyOwned LweDimension ({:?}) \
            and parameters LweDimension ({:?})",
            lwe_public_key.lwe_size().to_lwe_dimension(),
            ciphertext_lwe_dimension,
        );

        assert!(
            lwe_public_key.ciphertext_modulus().is_native_modulus(),
            "LwePublicKeyOwned CiphertextModulus needs to be the native modulus got ({:?})",
            lwe_public_key.ciphertext_modulus()
        );

        assert!(
            lwe_public_key.ciphertext_modulus().is_native_modulus(),
            "LwePublicKeyOwned CiphertextModulus needs to be the native modulus got ({:?})",
            lwe_public_key.ciphertext_modulus()
        );

        Self {
            lwe_public_key,
            parameters,
        }
    }
}

impl CompressedPublicKey {
    pub fn decompress(&self) -> PublicKey {
        let parameters = self.parameters;

        let decompressed_public_key = self
            .compressed_lwe_public_key
            .as_view()
            .par_decompress_into_lwe_public_key();

        PublicKey {
            lwe_public_key: decompressed_public_key,
            parameters,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::boolean::keycache::KEY_CACHE;
    use crate::boolean::prelude::{
        BinaryBooleanGates, BooleanParameters, CompressedPublicKey, DEFAULT_PARAMETERS,
        PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    };
    use crate::boolean::random_boolean;

    use super::PublicKey;
    #[cfg(not(tarpaulin))]
    const NB_TESTS: usize = 32;
    #[cfg(tarpaulin)]
    const NB_TESTS: usize = 1;

    #[test]
    fn test_public_key_default_parameters() {
        test_public_key(DEFAULT_PARAMETERS);
    }

    #[cfg(not(tarpaulin))]
    #[test]
    fn test_public_key_tfhe_lib_parameters() {
        test_public_key(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }

    fn test_public_key(parameters: BooleanParameters) {
        let keys = KEY_CACHE.get_from_param(parameters);
        let (cks, sks) = (keys.client_key(), keys.server_key());
        let pks = PublicKey::new(cks);

        for _ in 0..NB_TESTS {
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

    #[cfg(not(tarpaulin))]
    #[test]
    fn test_decompressing_public_key_tfhe_lib_parameters() {
        test_decompressing_public_key(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }

    fn test_decompressing_public_key(parameters: BooleanParameters) {
        let keys = KEY_CACHE.get_from_param(parameters);
        let (cks, sks) = (keys.client_key(), keys.server_key());
        let cpks = CompressedPublicKey::new(cks);
        let pks = cpks.decompress();

        for _ in 0..NB_TESTS {
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
