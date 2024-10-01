//! Module with the definition of the PublicKey.
use crate::core_crypto::entities::*;
use crate::shortint::backward_compatibility::public_key::PublicKeyVersions;
use crate::shortint::ciphertext::Ciphertext;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{MessageModulus, ShortintParameterSet};
use crate::shortint::{ClientKey, CompressedPublicKey, PBSOrder};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

/// A structure containing a public key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(PublicKeyVersions)]
pub struct PublicKey {
    pub(crate) lwe_public_key: LwePublicKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
    pub pbs_order: PBSOrder,
}

impl PublicKey {
    /// Generate a public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::public_key::PublicKey;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = PublicKey::new(&cks);
    /// ```
    pub fn new(client_key: &ClientKey) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| engine.new_public_key(client_key))
    }

    /// Deconstruct a [`PublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> (LwePublicKeyOwned<u64>, ShortintParameterSet, PBSOrder) {
        let Self {
            lwe_public_key,
            parameters,
            pbs_order,
        } = self;

        (lwe_public_key, parameters, pbs_order)
    }

    /// Construct a [`PublicKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        lwe_public_key: LwePublicKeyOwned<u64>,
        parameters: ShortintParameterSet,
        pbs_order: PBSOrder,
    ) -> Self {
        let expected_pbs_order: PBSOrder = parameters.encryption_key_choice().into();

        assert_eq!(
            pbs_order, expected_pbs_order,
            "Mismatch between expected PBSOrder ({expected_pbs_order:?}) and \
            provided PBSOrder ({pbs_order:?})"
        );

        let ciphertext_lwe_dimension = parameters.encryption_lwe_dimension();

        assert_eq!(
            (*lwe_public_key).lwe_size().to_lwe_dimension(),
            ciphertext_lwe_dimension,
            "Mismatch between the LwePublicKeyOwned LweDimension ({:?}) and \
            the provided parameters LweDimension ({:?})",
            (*lwe_public_key).lwe_size().to_lwe_dimension(),
            ciphertext_lwe_dimension,
        );

        assert_eq!(
            (*lwe_public_key).ciphertext_modulus(),
            parameters.ciphertext_modulus(),
            "Mismatch between the LwePublicKeyOwned CiphertextModulus ({:?}) and \
            the provided parameters CiphertextModulus ({:?})",
            (*lwe_public_key).ciphertext_modulus(),
            parameters.ciphertext_modulus(),
        );

        Self {
            lwe_public_key,
            parameters,
            pbs_order,
        }
    }

    /// Encrypt a small integer message using the client key.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{ClientKey, PublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn encrypt(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_with_public_key(self, message)
        })
    }

    /// Encrypt a small integer message using the client key with a specific message modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{MessageModulus, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
    /// use tfhe::shortint::{ClientKey, PublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
            engine.encrypt_with_message_modulus_and_public_key(self, message, message_modulus)
        })
    }

    /// Encrypt an integer without reducing the input message modulus the message space
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{ClientKey, PublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
            engine.unchecked_encrypt_with_public_key(self, message)
        })
    }

    /// Encrypt a small integer message using the client key without padding bit.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{ClientKey, PublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
            engine.encrypt_without_padding_with_public_key(self, message)
        })
    }

    /// Encrypt a small integer message using the client key without padding bit with some modulus.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{MessageModulus, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
    /// use tfhe::shortint::{ClientKey, PublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = PublicKey::new(&cks);
    ///
    /// let msg = 2;
    /// let modulus = MessageModulus(3);
    ///
    /// // Encryption of one message:
    /// let ct = pk.encrypt_native_crt(msg, modulus);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus.0);
    /// ```
    pub fn encrypt_native_crt(&self, message: u64, message_modulus: MessageModulus) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_native_crt_with_public_key(self, message, message_modulus)
        })
    }
}

impl CompressedPublicKey {
    pub fn decompress(&self) -> PublicKey {
        let parameters = self.parameters;

        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        let decompressed_public_key = self
            .lwe_public_key
            .as_view()
            .par_decompress_into_lwe_public_key();

        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        let decompressed_public_key = self
            .lwe_public_key
            .as_view()
            .decompress_into_lwe_public_key();

        PublicKey {
            lwe_public_key: decompressed_public_key,
            parameters,
            pbs_order: self.pbs_order,
        }
    }
}
