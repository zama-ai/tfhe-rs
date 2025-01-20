//! Module with the definition of the ClientKey.

pub(crate) mod secret_encryption_key;
use tfhe_versionable::Versionize;

use super::{PBSOrder, PaddingBit, ShortintEncoding};
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{
    allocate_and_generate_new_binary_glwe_secret_key,
    allocate_and_generate_new_binary_lwe_secret_key, decrypt_lwe_ciphertext,
};
use crate::shortint::backward_compatibility::client_key::ClientKeyVersions;
use crate::shortint::ciphertext::{Ciphertext, CompressedCiphertext};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{
    DynamicDistribution, EncryptionKeyChoice, MessageModulus, ShortintParameterSet,
};
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ClientKeyVersions)]
pub struct ClientKey {
    pub(crate) glwe_secret_key: GlweSecretKeyOwned<u64>,
    /// Key used as the output of the keyswitch operation
    pub(crate) lwe_secret_key: LweSecretKeyOwned<u64>,
    pub parameters: ShortintParameterSet,
}

impl<'cks> From<&'cks ClientKey> for SecretEncryptionKeyView<'cks> {
    fn from(value: &'cks ClientKey) -> Self {
        Self {
            lwe_secret_key: value.encryption_key_and_noise().0,
            message_modulus: value.parameters.message_modulus(),
            carry_modulus: value.parameters.carry_modulus(),
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
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_client_key(parameters.try_into().unwrap())
        })
    }

    /// Returns a view to the `glwe_secret_key` interpreted as an LWE secret key.
    pub(crate) fn large_lwe_secret_key(&self) -> LweSecretKeyView<'_, u64> {
        self.glwe_secret_key.as_lwe_secret_key()
    }

    /// Returns a view to the `lwe_secret_key`
    pub(crate) fn small_lwe_secret_key(&self) -> LweSecretKeyView<'_, u64> {
        self.lwe_secret_key.as_view()
    }

    /// Returns a view to the encryption key and the corresponding noise distribution.
    pub fn encryption_key_and_noise(
        &self,
    ) -> (LweSecretKeyView<'_, u64>, DynamicDistribution<u64>) {
        match self.parameters.encryption_key_choice() {
            EncryptionKeyChoice::Big => (
                self.glwe_secret_key.as_lwe_secret_key(),
                self.parameters.glwe_noise_distribution(),
            ),
            EncryptionKeyChoice::Small => (
                self.lwe_secret_key.as_view(),
                self.parameters.lwe_noise_distribution(),
            ),
        }
    }

    pub fn try_from_lwe_encryption_key<P>(
        encryption_key: LweSecretKeyOwned<u64>,
        parameters: P,
    ) -> crate::Result<Self>
    where
        P: TryInto<ShortintParameterSet>,
        <P as TryInto<ShortintParameterSet>>::Error: Display,
    {
        let parameters = parameters
            .try_into()
            .map_err(|err| crate::Error::new(format!("{err}")))?;

        let expected_lwe_dimension = parameters.encryption_lwe_dimension();
        if encryption_key.lwe_dimension() != expected_lwe_dimension {
            return Err(
                crate::Error::new(
                    format!(
                        "The given encryption key does not have the correct LweDimension, expected: {:?}, got: {:?}",
                        encryption_key.lwe_dimension(),
                        expected_lwe_dimension)));
        }

        // The key we got is the one used to encrypt,
        // we have to generate the other key
        match parameters.encryption_key_choice() {
            EncryptionKeyChoice::Big => {
                // We have to generate the small lwe key
                let small_key = ShortintEngine::with_thread_local_mut(|engine| {
                    allocate_and_generate_new_binary_lwe_secret_key(
                        parameters.lwe_dimension(),
                        &mut engine.secret_generator,
                    )
                });

                Ok(Self {
                    glwe_secret_key: GlweSecretKeyOwned::from_container(
                        encryption_key.into_container(),
                        parameters.polynomial_size(),
                    ),
                    lwe_secret_key: small_key,
                    parameters,
                })
            }
            EncryptionKeyChoice::Small => {
                // We have to generate the big lwe key
                let glwe_secret_key = ShortintEngine::with_thread_local_mut(|engine| {
                    allocate_and_generate_new_binary_glwe_secret_key(
                        parameters.glwe_dimension(),
                        parameters.polynomial_size(),
                        &mut engine.secret_generator,
                    )
                });

                Ok(Self {
                    glwe_secret_key,
                    lwe_secret_key: encryption_key,
                    parameters,
                })
            }
        }
    }

    /// Deconstruct a [`ClientKey`] into its constituents.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let (glwe_secret_key, lwe_secret_key, parameters) = cks.into_raw_parts();
    /// ```
    pub fn into_raw_parts(
        self,
    ) -> (
        GlweSecretKeyOwned<u64>,
        LweSecretKeyOwned<u64>,
        ShortintParameterSet,
    ) {
        let Self {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
        } = self;

        (glwe_secret_key, lwe_secret_key, parameters)
    }

    /// Construct a [`ClientKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the keys are not compatible with the parameters provided as raw parts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::client_key::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let (glwe_secret_key, lwe_secret_key, parameters) = cks.into_raw_parts();
    ///
    /// let cks = ClientKey::from_raw_parts(glwe_secret_key, lwe_secret_key, parameters);
    /// ```
    pub fn from_raw_parts(
        glwe_secret_key: GlweSecretKeyOwned<u64>,
        lwe_secret_key: LweSecretKeyOwned<u64>,
        parameters: ShortintParameterSet,
    ) -> Self {
        assert_eq!(
            lwe_secret_key.lwe_dimension(),
            parameters.lwe_dimension(),
            "Mismatch between the LweSecretKey LweDimension ({:?}) \
            and the parameters LweDimension ({:?})",
            lwe_secret_key.lwe_dimension(),
            parameters.lwe_dimension()
        );
        assert_eq!(
            glwe_secret_key.glwe_dimension(),
            parameters.glwe_dimension(),
            "Mismatch between the GlweSecretKey GlweDimension ({:?}) \
            and the parameters GlweDimension ({:?})",
            glwe_secret_key.glwe_dimension(),
            parameters.glwe_dimension()
        );
        assert_eq!(
            glwe_secret_key.polynomial_size(),
            parameters.polynomial_size(),
            "Mismatch between the GlweSecretKey PolynomialSize ({:?}) \
            and the parameters PolynomialSize ({:?})",
            glwe_secret_key.polynomial_size(),
            parameters.polynomial_size()
        );

        Self {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
        }
    }

    #[cfg(test)]
    pub fn create_trivial(&self, value: u64) -> Ciphertext {
        let modular_value = value % self.parameters.message_modulus().0;
        self.unchecked_create_trivial(modular_value)
    }

    #[cfg(test)]
    pub fn unchecked_create_trivial(&self, value: u64) -> Ciphertext {
        let params = self.parameters;

        let lwe_size = params.encryption_lwe_dimension().to_lwe_size();

        super::ciphertext::unchecked_create_trivial_with_lwe_size(
            Cleartext(value),
            lwe_size,
            params.message_modulus(),
            params.carry_modulus(),
            PBSOrder::from(params.encryption_key_choice()),
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
    /// let modulus = cks.parameters.message_modulus().0;
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
    /// let modulus = cks.parameters.message_modulus().0;
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
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
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
    /// let cks = ClientKey::new(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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

        ShortintEncoding::from_parameters(self.parameters, PaddingBit::Yes)
            .decode(decrypted_u64)
            .0
    }

    /// Decrypt a ciphertext encrypting a message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
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
    /// let cks = ClientKey::new(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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

    pub(crate) fn decrypt_no_decode(&self, ct: &Ciphertext) -> Plaintext<u64> {
        let lwe_decryption_key = match ct.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.large_lwe_secret_key(),
            PBSOrder::BootstrapKeyswitch => self.small_lwe_secret_key(),
        };
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
    /// use tfhe::shortint::parameters::{
    ///     V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    ///     V0_11_PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M64,
    /// };
    /// use tfhe::shortint::ClientKey;
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64);
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
    /// let cks = ClientKey::new(V0_11_PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M64);
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

        ShortintEncoding::from_parameters(self.parameters, PaddingBit::No)
            .decode(decrypted_u64)
            .0
    }

    /// Decrypt a ciphertext encrypting an integer message using the client key,
    /// where the ciphertext is assumed to not have any padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
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
    /// let cks = ClientKey::new(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
    /// use tfhe::shortint::parameters::{
    ///     MessageModulus, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    ///     V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
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
    ///
    /// // Generate the client key
    /// let cks = ClientKey::new(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
