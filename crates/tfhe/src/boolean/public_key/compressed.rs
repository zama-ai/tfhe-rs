use crate::boolean::backward_compatibility::public_key::CompressedPublicKeyVersions;
use crate::boolean::engine::{BooleanEngine, WithThreadLocalEngine};
use crate::boolean::prelude::{BooleanParameters, Ciphertext, ClientKey};
use crate::core_crypto::prelude::SeededLwePublicKeyOwned;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// A structure containing a compressed public key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedPublicKeyVersions)]
pub struct CompressedPublicKey {
    pub(crate) compressed_lwe_public_key: SeededLwePublicKeyOwned<u32>,
    pub parameters: BooleanParameters,
}

impl CompressedPublicKey {
    /// Generates a new public key that is compressed
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys();
    ///
    /// let cpks = CompressedPublicKey::new(&cks);
    /// ```
    ///
    /// Decompressing the key
    ///
    /// ```rust
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys();
    ///
    /// let cpks = CompressedPublicKey::new(&cks);
    /// let pks = cpks.decompress();
    /// ```
    pub fn new(client_key: &ClientKey) -> Self {
        BooleanEngine::with_thread_local_mut(|engine| {
            engine.create_compressed_public_key(client_key)
        })
    }

    /// Deconstruct a [`CompressedPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> (SeededLwePublicKeyOwned<u32>, BooleanParameters) {
        let Self {
            compressed_lwe_public_key,
            parameters,
        } = self;

        (compressed_lwe_public_key, parameters)
    }

    /// Construct a [`CompressedPublicKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        compressed_lwe_public_key: SeededLwePublicKeyOwned<u32>,
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
            compressed_lwe_public_key.lwe_size().to_lwe_dimension(),
            ciphertext_lwe_dimension,
            "Mismatch between SeededLwePublicKeyOwned LweDimension ({:?}) \
            and parameters LweDimension ({:?})",
            compressed_lwe_public_key.lwe_size().to_lwe_dimension(),
            ciphertext_lwe_dimension,
        );

        assert!(
            compressed_lwe_public_key
                .ciphertext_modulus()
                .is_native_modulus(),
            "SeededLwePublicKeyOwned CiphertextModulus needs to be the native modulus got ({:?})",
            compressed_lwe_public_key.ciphertext_modulus()
        );

        Self {
            compressed_lwe_public_key,
            parameters,
        }
    }

    /// Encrypt a Boolean message using the compressed public key.
    ///
    /// # Note
    ///
    /// It is recommended to use the compressed
    /// public key to save on storage / tranfert
    /// and decompress it in the program before doing encryptions.
    ///
    /// This is because encrypting using the compressed public key
    /// will require to lazyly decompress parts of the key
    /// for each encryption.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys();
    ///
    /// let cpks = CompressedPublicKey::new(&cks);
    ///
    /// // Encryption of one message:
    /// let ct1 = cpks.encrypt(true);
    /// let ct2 = cpks.encrypt(false);
    /// let ct_res = sks.and(&ct1, &ct2);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct_res);
    /// assert!(!dec);
    /// ```
    pub fn encrypt(&self, message: bool) -> Ciphertext {
        BooleanEngine::with_thread_local_mut(|engine| {
            engine.encrypt_with_compressed_public_key(message, self)
        })
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
    #[cfg(not(tarpaulin))]
    const NB_TESTS: usize = 32;
    #[cfg(tarpaulin)]
    const NB_TESTS: usize = 1;

    #[test]
    fn test_compressed_public_key_default_parameters() {
        test_compressed_public_key(DEFAULT_PARAMETERS);
    }

    #[cfg(not(tarpaulin))]
    #[test]
    fn test_compressed_public_key_tfhe_lib_parameters() {
        test_compressed_public_key(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }

    fn test_compressed_public_key(parameters: BooleanParameters) {
        let keys = KEY_CACHE.get_from_param(parameters);
        let (cks, sks) = (keys.client_key(), keys.server_key());
        let cpks = CompressedPublicKey::new(cks);

        for _ in 0..NB_TESTS {
            let b1 = random_boolean();
            let b2 = random_boolean();
            let expected_result = !(b1 && b2);

            let ct1 = cpks.encrypt(b1);
            let ct2 = cpks.encrypt(b2);

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
