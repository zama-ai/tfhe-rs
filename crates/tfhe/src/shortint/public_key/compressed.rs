//! Module with the definition of the compressed PublicKey.
use crate::core_crypto::entities::*;
use crate::shortint::backward_compatibility::public_key::CompressedPublicKeyVersions;
use crate::shortint::ciphertext::{Ciphertext, PBSOrder};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{MessageModulus, ShortintParameterSet};
use crate::shortint::ClientKey;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use tfhe_versionable::Versionize;

/// A structure containing a compressed public key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedPublicKeyVersions)]
pub struct CompressedPublicKey {
    pub(crate) lwe_public_key: SeededLwePublicKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
    pub pbs_order: PBSOrder,
}

impl CompressedPublicKey {
    /// Generate a public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::public_key::CompressedPublicKey;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = CompressedPublicKey::new(&cks);
    /// ```
    pub fn new(client_key: &ClientKey) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| engine.new_compressed_public_key(client_key))
    }

    /// Deconstruct a [`CompressedPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> (SeededLwePublicKeyOwned<u64>, ShortintParameterSet, PBSOrder) {
        let Self {
            lwe_public_key,
            parameters,
            pbs_order,
        } = self;
        (lwe_public_key, parameters, pbs_order)
    }

    /// Construct a [`CompressedPublicKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        lwe_public_key: SeededLwePublicKeyOwned<u64>,
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
            "Mismatch between the SeededLwePublicKeyOwned LweDimension ({:?}) and \
            the provided parameters LweDimension ({:?})",
            (*lwe_public_key).lwe_size().to_lwe_dimension(),
            ciphertext_lwe_dimension,
        );

        assert_eq!(
            (*lwe_public_key).ciphertext_modulus(),
            parameters.ciphertext_modulus(),
            "Mismatch between the SeededLwePublicKeyOwned CiphertextModulus ({:?}) and \
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

    /// Encrypts a small integer message using the client key.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{ClientKey, CompressedPublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = CompressedPublicKey::new(&cks);
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
            engine.encrypt_with_compressed_public_key(self, message)
        })
    }

    /// [`Self::encrypt`] variant that can encrypt many messages efficiently at the same time.
    pub fn encrypt_many(&self, messages: impl Iterator<Item = u64>) -> Vec<Ciphertext> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_many_ciphertexts_with_compressed_public_key(self, messages)
        })
    }

    /// Encrypts a small integer message using the client key with a specific message modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{MessageModulus, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
    /// use tfhe::shortint::{ClientKey, CompressedPublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = CompressedPublicKey::new(&cks);
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
            engine.encrypt_with_message_modulus_and_compressed_public_key(
                self,
                message,
                message_modulus,
            )
        })
    }

    /// [`Self::encrypt_with_message_modulus`] variant that can encrypt a message under several
    /// moduli efficiently at the same time.
    pub fn encrypt_with_many_message_moduli(
        &self,
        message: u64,
        message_moduli: impl Iterator<Item = MessageModulus>,
    ) -> Vec<Ciphertext> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_with_many_message_moduli_and_compressed_public_key(
                self,
                message,
                message_moduli,
            )
        })
    }

    /// Encrypts an integer without reducing the input message modulus the message space
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{ClientKey, CompressedPublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = CompressedPublicKey::new(&cks);
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
            engine.unchecked_encrypt_with_compressed_public_key(self, message)
        })
    }

    /// Encrypts a small integer message using the client key without padding bit.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{ClientKey, CompressedPublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// // DISCLAIMER: Note that this parameter is not guaranteed to be secure
    /// let pk = CompressedPublicKey::new(&cks);
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
            engine.encrypt_without_padding_with_compressed_public_key(self, message)
        })
    }

    /// [`Self::encrypt_without_padding`] variant that can encrypt many messages efficiently at the
    /// same time.
    pub fn encrypt_many_without_padding(
        &self,
        messages: impl Iterator<Item = u64>,
    ) -> Vec<Ciphertext> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .encrypt_many_ciphertexts_without_padding_with_compressed_public_key(self, messages)
        })
    }

    /// Encrypts a small integer message using the client key without padding bit with some modulus.
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{MessageModulus, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
    /// use tfhe::shortint::{ClientKey, CompressedPublicKey};
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let pk = CompressedPublicKey::new(&cks);
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
            engine.encrypt_native_crt_with_compressed_public_key(self, message, message_modulus)
        })
    }

    /// [`Self::encrypt_native_crt`] variant that can encrypt a message under several moduli
    /// efficiently at the same time.
    pub fn encrypt_native_crt_with_many_message_moduli(
        &self,
        message: u64,
        message_modulus: impl Iterator<Item = MessageModulus>,
    ) -> Vec<Ciphertext> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_native_crt_with_many_message_moduli_and_compressed_public_key(
                self,
                message,
                message_modulus,
            )
        })
    }
}
