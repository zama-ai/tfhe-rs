//! Module with the definition of the ClientKey.

pub mod atomic_pattern;
pub(crate) mod secret_encryption_key;
use atomic_pattern::{
    AtomicPatternClientKey, EncryptionAtomicPattern, StandardAtomicPatternClientKey,
};
use tfhe_versionable::Versionize;

use super::parameters::ShortintKeySwitchingParameters;
use super::server_key::UnsupportedOperation;
use super::{AtomicPatternParameters, PaddingBit, ShortintEncoding};
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::decrypt_lwe_ciphertext;
use crate::shortint::backward_compatibility::client_key::GenericClientKeyVersions;
use crate::shortint::ciphertext::{Ciphertext, CompressedCiphertext};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{DynamicDistribution, MessageModulus, ShortintParameterSet};
use crate::shortint::CarryModulus;
use secret_encryption_key::SecretEncryptionKeyView;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};

/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs. This
///   secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
///   switching keys.
/// * `parameters` - the cryptographic parameter set.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(GenericClientKeyVersions)]
pub struct GenericClientKey<AP> {
    pub atomic_pattern: AP,
}

pub type ClientKey = GenericClientKey<AtomicPatternClientKey>;
pub type StandardClientKey = GenericClientKey<StandardAtomicPatternClientKey>;
pub type ClientKeyView<'key> = GenericClientKey<&'key AtomicPatternClientKey>;
pub type StandardClientKeyView<'key> = GenericClientKey<&'key StandardAtomicPatternClientKey>;

impl<'cks> From<&'cks ClientKey> for SecretEncryptionKeyView<'cks> {
    fn from(value: &'cks ClientKey) -> Self {
        Self {
            lwe_secret_key: value.encryption_key(),
            message_modulus: value.parameters().message_modulus(),
            carry_modulus: value.parameters().carry_modulus(),
        }
    }
}

impl<'key> TryFrom<ClientKeyView<'key>> for StandardClientKeyView<'key> {
    type Error = UnsupportedOperation;

    fn try_from(value: ClientKeyView<'key>) -> Result<Self, Self::Error> {
        let AtomicPatternClientKey::Standard(atomic_pattern) = value.atomic_pattern else {
            return Err(UnsupportedOperation);
        };

        Ok(Self { atomic_pattern })
    }
}

impl<AP> GenericClientKey<AP> {
    pub fn as_view(&self) -> GenericClientKey<&AP> {
        GenericClientKey {
            atomic_pattern: &self.atomic_pattern,
        }
    }
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
        ShortintEngine::with_thread_local_mut(|engine| engine.new_client_key(parameters))
    }

    pub fn try_from_lwe_encryption_key<P>(
        encryption_key: LweSecretKeyOwned<u64>,
        parameters: P,
    ) -> crate::Result<Self>
    where
        P: TryInto<AtomicPatternParameters>,
        <P as TryInto<AtomicPatternParameters>>::Error: Display,
    {
        let parameters = parameters
            .try_into()
            .map_err(|err| crate::Error::new(format!("{err}")))?;

        let atomic_pattern =
            AtomicPatternClientKey::try_from_lwe_encryption_key(encryption_key, parameters)?;

        Ok(Self { atomic_pattern })
    }
}

impl<AP: EncryptionAtomicPattern> GenericClientKey<AP> {
    pub fn parameters(&self) -> ShortintParameterSet {
        self.atomic_pattern.parameters()
    }

    /// Returns a view of the key used for encryption
    pub fn encryption_key(&self) -> LweSecretKeyView<'_, u64> {
        self.atomic_pattern.encryption_key()
    }

    /// Returns a view to the encryption key and the corresponding noise distribution.
    pub fn encryption_key_and_noise(
        &self,
    ) -> (LweSecretKeyView<'_, u64>, DynamicDistribution<u64>) {
        self.atomic_pattern.encryption_key_and_noise()
    }

    #[cfg(test)]
    pub fn create_trivial(&self, value: u64) -> Ciphertext {
        let modular_value = value % self.parameters().message_modulus().0;
        self.unchecked_create_trivial(modular_value)
    }

    #[cfg(test)]
    pub fn unchecked_create_trivial(&self, value: u64) -> Ciphertext {
        let params = self.parameters();

        let lwe_size = params.encryption_lwe_dimension().to_lwe_size();

        super::ciphertext::unchecked_create_trivial_with_lwe_size(
            Cleartext(value),
            lwe_size,
            params.message_modulus(),
            params.carry_modulus(),
            params.atomic_pattern(),
            params.ciphertext_modulus(),
        )
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
    /// let modulus = cks.parameters().message_modulus().0;
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
    /// let modulus = cks.parameters().message_modulus().0;
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
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
    /// ```
    pub fn decrypt_message_and_carry(&self, ct: &Ciphertext) -> u64 {
        let decrypted_u64 = self.decrypt_no_decode(ct);

        ShortintEncoding::from_parameters(self.parameters(), PaddingBit::Yes)
            .decode(decrypted_u64)
            .0
    }

    /// Decrypt a ciphertext encrypting a message using the client key.
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
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt(&self, ct: &Ciphertext) -> u64 {
        self.decrypt_message_and_carry(ct) % ct.message_modulus.0
    }

    /// Decrypt a ciphertext without decoding the message, using the client key.
    ///
    /// This can be used to extract noise values after doing some computations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the keys
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition to generate a carry
    /// let ct_res = sks.unchecked_add(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt_no_decode(&ct_res);
    /// let expected_res = 3 + 3;
    /// // Delta for params 2_2 with a padding bit
    /// let delta = (1u64 << (u64::BITS - 1 - 1)) / 16 * 2;
    /// let noise = res.0.wrapping_sub(expected_res * delta);
    ///
    /// assert!((noise as i64).abs() < delta as i64 / 2);
    /// ```
    pub fn decrypt_no_decode(&self, ct: &Ciphertext) -> Plaintext<u64> {
        let lwe_decryption_key = self.encryption_key();

        decrypt_lwe_ciphertext(&lwe_decryption_key, &ct.ct)
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_and_carry_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_message_and_carry_without_padding(&self, ct: &Ciphertext) -> u64 {
        let decrypted_u64 = self.decrypt_no_decode(ct);

        ShortintEncoding::from_parameters(self.parameters(), PaddingBit::No)
            .decode(decrypted_u64)
            .0
    }

    /// Decrypt a ciphertext encrypting an integer message using the client key,
    /// where the ciphertext is assumed to not have any padding bit.
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
    /// let modulus = 4;
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_without_padding(msg);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_without_padding(&ct);
    /// assert_eq!(msg % modulus, dec);
    /// ```
    pub fn decrypt_without_padding(&self, ct: &Ciphertext) -> u64 {
        self.decrypt_message_and_carry_without_padding(ct) % ct.message_modulus.0
    }

    /// Encrypt a small integer message using the client key without padding bit with some modulus.
    ///
    /// The input message is reduced to the encrypted message space modulus
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
    /// let msg = 2;
    /// let modulus = MessageModulus(3);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt(msg, modulus);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus.0);
    /// ```
    pub fn encrypt_native_crt(&self, message: u64, message_modulus: MessageModulus) -> Ciphertext {
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
    /// use tfhe::shortint::parameters::{MessageModulus, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2;
    /// let modulus = MessageModulus(3);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt_compressed(msg, modulus);
    ///
    /// let ct = ct.decompress();
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus.0);
    /// ```
    pub fn encrypt_native_crt_compressed(
        &self,
        message: u64,
        message_modulus: MessageModulus,
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
    /// use tfhe::shortint::parameters::{MessageModulus, PARAM_MESSAGE_2_CARRY_2_KS_PBS};
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1;
    /// let modulus = MessageModulus(3);
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_native_crt(msg, modulus);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_message_native_crt(&ct, modulus);
    /// assert_eq!(msg, dec % modulus.0);
    /// ```
    pub fn decrypt_message_native_crt(
        &self,
        ct: &Ciphertext,
        message_modulus: MessageModulus,
    ) -> u64 {
        let basis = message_modulus.0;

        let decrypted_u64: u64 = self.decrypt_no_decode(ct).0;

        let mut result = decrypted_u64 as u128 * basis as u128;
        result = result.wrapping_add((result & (1 << 63)) << 1) / (1 << 64);

        result as u64 % basis
    }
}

impl StandardClientKeyView<'_> {
    /// Returns a view to the encryption key used for a keyswitch operation and the corresponding
    /// noise distribution.
    pub fn keyswitch_encryption_key_and_noise(
        &self,
        params: ShortintKeySwitchingParameters,
    ) -> (LweSecretKeyView<'_, u64>, DynamicDistribution<u64>) {
        self.atomic_pattern
            .keyswitch_encryption_key_and_noise(params)
    }
}
