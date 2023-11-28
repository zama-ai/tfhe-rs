//! Module with the definition of the ClientKey.

use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::decrypt_lwe_ciphertext;
use crate::shortint::ciphertext::{Ciphertext, CompressedCiphertext};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{MessageModulus, ShortintParameterSet};
use crate::shortint::CarryModulus;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use super::PBSOrder;

/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs.
/// This secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
/// switching keys.
/// * `parameters` - the cryptographic parameter set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientKey {
    /// The LWE secret key equivalent to the GLWE secret key
    pub(crate) large_lwe_secret_key: LweSecretKeyOwned<u64>,
    pub(crate) glwe_secret_key: GlweSecretKeyOwned<u64>,
    /// Key used as the output of the keyswitch operation
    pub(crate) small_lwe_secret_key: LweSecretKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
}

impl ClientKey {
    /// Generate a client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// ```
    pub fn new<P>(parameters: P) -> Self
    where
        P: TryInto<ShortintParameterSet>,
        <P as TryInto<ShortintParameterSet>>::Error: Debug,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_client_key(parameters.try_into().unwrap())
        })
    }

    /// Encrypt a small integer message using the client key.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::ClientKey;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encryption of one message that is within the encrypted message modulus:
    /// let msg = 3;
    /// let ct = cks.encrypt(msg);
    ///
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// // Encryption of one message that is outside the encrypted message modulus:
    /// let msg = 5;
    /// let ct = cks.encrypt(msg);
    ///
    /// let dec = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn encrypt(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| engine.encrypt(self, message))
    }

    /// Encrypt a integer message using the client key returning a compressed ciphertext.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::ClientKey;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encryption of one message that is within the encrypted message modulus:
    /// let msg = 3;
    /// let ct = cks.encrypt_compressed(msg);
    ///
    /// let ct = ct.decompress();
    ///
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// // Encryption of one message that is outside the encrypted message modulus:
    /// let msg = 5;
    /// let ct = cks.encrypt_compressed(msg);
    ///
    /// let ct = ct.decompress();
    ///
    /// let dec = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn encrypt_compressed(&self, message: u64) -> CompressedCiphertext {
        ShortintEngine::with_thread_local_mut(|engine| engine.encrypt_compressed(self, message))
    }

    /// Encrypt a small integer message using the client key with a specific message modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{MessageModulus, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_with_message_modulus(msg, MessageModulus(6));
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
            engine.encrypt_with_message_modulus(self, message, message_modulus)
        })
    }

    /// Encrypt a small integer message using the client key with a specific message and carry
    /// moduli.
    ///
    /// # Warning
    /// Defining specific message AND carry moduli might lead to incorrect homomorphic
    /// computations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{MessageModulus, PARAM_MESSAGE_2_CARRY_2};
    /// use tfhe::shortint::{CarryModulus, ClientKey};
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message with MessageModulus = 2 and CarryModulus = 2
    /// // so that 6*2 < 2^(2 + 2) from the parameter set
    /// let ct = cks.encrypt_with_message_and_carry_modulus(msg, MessageModulus(6), CarryModulus(2));
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_with_message_and_carry_modulus(
        &self,
        message: u64,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_with_message_and_carry_modulus(
                self,
                message,
                message_modulus,
                carry_modulus,
            )
        })
    }

    /// Encrypt a small integer message using the client key with a specific message modulus
    /// returning a compressed ciphertext
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{MessageModulus, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_with_message_modulus_compressed(msg, MessageModulus(6));
    ///
    /// let ct = ct.decompress();
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_with_message_modulus_compressed(
        &self,
        message: u64,
        message_modulus: MessageModulus,
    ) -> CompressedCiphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_with_message_modulus_compressed(self, message, message_modulus)
        })
    }

    /// Encrypt an integer without reducing the input message modulus the message space
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 7;
    /// let ct = cks.unchecked_encrypt(msg);
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 1  |   1 1   |
    ///
    /// let dec = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn unchecked_encrypt(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| engine.unchecked_encrypt(self, message))
    }

    /// Decrypt a ciphertext encrypting an integer message and carries using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_message_and_carry(&self, ct: &Ciphertext) -> u64 {
        let lwe_decryption_key = match ct.pbs_order {
            PBSOrder::KeyswitchBootstrap => &self.large_lwe_secret_key,
            PBSOrder::BootstrapKeyswitch => &self.small_lwe_secret_key,
        };

        // decryption
        let decrypted_encoded = decrypt_lwe_ciphertext(lwe_decryption_key, &ct.ct);

        let decrypted_u64: u64 = decrypted_encoded.0;

        let delta = (1_u64 << 63)
            / (self.parameters.message_modulus().0 * self.parameters.carry_modulus().0) as u64;

        //The bit before the message
        let rounding_bit = delta >> 1;

        //compute the rounding bit
        let rounding = (decrypted_u64 & rounding_bit) << 1;

        (decrypted_u64.wrapping_add(rounding)) / delta
    }

    /// Decrypt a ciphertext encrypting a message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt(&self, ct: &Ciphertext) -> u64 {
        self.decrypt_message_and_carry(ct) % ct.message_modulus.0 as u64
    }

    /// Encrypt a small integer message using the client key without padding bit.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::ClientKey;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encryption of one message that is within the encrypted message modulus:
    /// let msg = 6;
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// let dec = cks.decrypt_message_and_carry_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_without_padding(&self, message: u64) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_without_padding(self, message)
        })
    }

    /// Encrypt a small integer message using the client key without padding bit returning a
    /// compressed message.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::ClientKey;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encryption of one message that is within the encrypted message modulus:
    /// let msg = 6;
    /// let ct = cks.encrypt_without_padding_compressed(msg);
    ///
    /// let ct = ct.decompress();
    ///
    /// let dec = cks.decrypt_message_and_carry_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_without_padding_compressed(&self, message: u64) -> CompressedCiphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_without_padding_compressed(self, message)
        })
    }

    /// Decrypt a ciphertext encrypting an integer message and carries using the client key,
    /// where the ciphertext is assumed to not have any padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_1_CARRY_1_PBS_KS,
    /// };
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_and_carry_without_padding(&ct);
    /// assert_eq!(msg, dec);
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_1_CARRY_1_PBS_KS);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_and_carry_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_message_and_carry_without_padding(&self, ct: &Ciphertext) -> u64 {
        let lwe_decryption_key = match ct.pbs_order {
            PBSOrder::KeyswitchBootstrap => &self.large_lwe_secret_key,
            PBSOrder::BootstrapKeyswitch => &self.small_lwe_secret_key,
        };

        // decryption
        let decrypted_encoded = decrypt_lwe_ciphertext(lwe_decryption_key, &ct.ct);

        let decrypted_u64: u64 = decrypted_encoded.0;

        let delta = ((1_u64 << 63)
            / (self.parameters.message_modulus().0 * self.parameters.carry_modulus().0) as u64)
            * 2;

        //The bit before the message
        let rounding_bit = delta >> 1;

        //compute the rounding bit
        let rounding = (decrypted_u64 & rounding_bit) << 1;

        (decrypted_u64.wrapping_add(rounding)) / delta
    }

    /// Decrypt a ciphertext encrypting an integer message using the client key,
    /// where the ciphertext is assumed to not have any padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 7;
    /// let modulus = 4;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_without_padding(&ct);
    /// assert_eq!(msg % modulus, dec);
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_without_padding(&ct);
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn decrypt_without_padding(&self, ct: &Ciphertext) -> u64 {
        self.decrypt_message_and_carry_without_padding(ct) % ct.message_modulus.0 as u64
    }

    /// Encrypt a small integer message using the client key without padding bit with some modulus.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2;
    /// let modulus = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt(msg, modulus);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus as u64);
    /// ```
    pub fn encrypt_native_crt(&self, message: u64, message_modulus: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_native_crt(self, message, message_modulus)
        })
    }

    /// Encrypt a small integer message using the client key without padding bit with some modulus
    /// returning a compressed ciphertext.
    ///
    /// The input message is reduced to the encrypted message space modulus
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2;
    /// let modulus = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt_compressed(msg, modulus);
    ///
    /// let ct = ct.decompress();
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus as u64);
    /// ```
    pub fn encrypt_native_crt_compressed(
        &self,
        message: u64,
        message_modulus: u8,
    ) -> CompressedCiphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.encrypt_native_crt_compressed(self, message, message_modulus)
        })
    }

    /// Decrypt a ciphertext encrypting an integer message using the client key,
    /// where the ciphertext is assumed to not have any padding bit and is related to some modulus.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1;
    /// let modulus = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt(msg, modulus);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus as u64);
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt(msg, modulus);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus as u64);
    /// ```
    pub fn decrypt_message_native_crt(&self, ct: &Ciphertext, basis: u8) -> u64 {
        let basis = basis as u64;

        let lwe_decryption_key = match ct.pbs_order {
            PBSOrder::KeyswitchBootstrap => &self.large_lwe_secret_key,
            PBSOrder::BootstrapKeyswitch => &self.small_lwe_secret_key,
        };

        // decryption
        let decrypted_encoded = decrypt_lwe_ciphertext(lwe_decryption_key, &ct.ct);

        let decrypted_u64: u64 = decrypted_encoded.0;

        let mut result = decrypted_u64 as u128 * basis as u128;
        result = result.wrapping_add((result & 1 << 63) << 1) / (1 << 64);

        result as u64 % basis
    }
}
