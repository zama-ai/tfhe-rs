//! The secret key of the client.
//!
//! This module implements the generation of the client' secret keys, together with the
//! encryption and decryption methods.

use crate::boolean::ciphertext::{Ciphertext, CompressedCiphertext};
use crate::boolean::engine::{BooleanEngine, WithThreadLocalEngine};
use crate::boolean::parameters::{BooleanParameters, DynamicDistribution, EncryptionKeyChoice};
use crate::core_crypto::entities::*;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use tfhe_versionable::Versionize;

use super::backward_compatibility::client_key::ClientKeyVersions;

/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs. This
///   secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
///   switching keys.
/// * `parameters` - the cryptographic parameter set.
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(ClientKeyVersions)]
pub struct ClientKey {
    pub(crate) lwe_secret_key: LweSecretKeyOwned<u32>,
    pub(crate) glwe_secret_key: GlweSecretKeyOwned<u32>,
    pub(crate) parameters: BooleanParameters,
}

impl PartialEq for ClientKey {
    fn eq(&self, other: &Self) -> bool {
        self.parameters == other.parameters
            && self.lwe_secret_key == other.lwe_secret_key
            && self.glwe_secret_key == other.glwe_secret_key
    }
}

impl Debug for ClientKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientKey {{ ")?;
        write!(f, "lwe_secret_key: {:?}, ", self.lwe_secret_key)?;
        write!(f, "glwe_secret_key: {:?}, ", self.glwe_secret_key)?;
        write!(f, "parameters: {:?}, ", self.parameters)?;
        write!(f, "engine: CoreEngine, ")?;
        write!(f, "}}")?;
        Ok(())
    }
}

impl ClientKey {
    /// Returns a view to the encryption key and the corresponding noise distribution.
    pub fn encryption_key_and_noise(
        &self,
    ) -> (LweSecretKeyView<'_, u32>, DynamicDistribution<u32>) {
        match self.parameters.encryption_key_choice {
            EncryptionKeyChoice::Big => (
                self.glwe_secret_key.as_lwe_secret_key(),
                self.parameters.glwe_noise_distribution,
            ),
            EncryptionKeyChoice::Small => (
                self.lwe_secret_key.as_view(),
                self.parameters.lwe_noise_distribution,
            ),
        }
    }

    /// Encrypt a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert!(dec);
    /// ```
    pub fn encrypt(&self, message: bool) -> Ciphertext {
        BooleanEngine::with_thread_local_mut(|engine| engine.encrypt(message, self))
    }

    /// Encrypt a Boolean message using the client key returning a compressed ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt_compressed(true);
    ///
    /// let ct = ct.decompress();
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert!(dec);
    /// ```
    pub fn encrypt_compressed(&self, message: bool) -> CompressedCiphertext {
        BooleanEngine::with_thread_local_mut(|engine| engine.encrypt_compressed(message, self))
    }

    /// Decrypt a ciphertext encrypting a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert!(dec);
    /// ```
    pub fn decrypt(&self, ct: &Ciphertext) -> bool {
        BooleanEngine::with_thread_local_mut(|engine| engine.decrypt(ct, self))
    }

    /// Allocate and generate a client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::boolean::client_key::ClientKey;
    /// use tfhe::boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(&PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    /// ```
    pub fn new(parameter_set: &BooleanParameters) -> Self {
        BooleanEngine::with_thread_local_mut(|engine| engine.create_client_key(*parameter_set))
    }

    /// Deconstruct a [`ClientKey`] into its constituents.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::boolean::client_key::ClientKey;
    /// use tfhe::boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(&PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    /// let raw_parts = cks.into_raw_parts();
    /// ```
    pub fn into_raw_parts(
        self,
    ) -> (
        LweSecretKeyOwned<u32>,
        GlweSecretKeyOwned<u32>,
        BooleanParameters,
    ) {
        let Self {
            lwe_secret_key,
            glwe_secret_key,
            parameters,
        } = self;

        (lwe_secret_key, glwe_secret_key, parameters)
    }

    /// Construct a [`ClientKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the provided raw parts are not compatible with the provided parameters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::boolean::client_key::ClientKey;
    /// use tfhe::boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(&PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    /// let (lwe_secret_key, glwe_secret_key, parameters) = cks.into_raw_parts();
    /// let reconstructed_cks =
    ///     ClientKey::new_from_raw_parts(lwe_secret_key, glwe_secret_key, parameters);
    /// ```
    pub fn new_from_raw_parts(
        lwe_secret_key: LweSecretKeyOwned<u32>,
        glwe_secret_key: GlweSecretKeyOwned<u32>,
        parameters: BooleanParameters,
    ) -> Self {
        assert_eq!(
            lwe_secret_key.lwe_dimension(),
            parameters.lwe_dimension,
            "Mismatch between the LweSecretKey LweDimension ({:?}) \
            and the parameters LweDimension ({:?})",
            lwe_secret_key.lwe_dimension(),
            parameters.lwe_dimension
        );
        assert_eq!(
            glwe_secret_key.glwe_dimension(),
            parameters.glwe_dimension,
            "Mismatch between the GlweSecretKey GlweDimension ({:?}) \
            and the parameters GlweDimension ({:?})",
            glwe_secret_key.glwe_dimension(),
            parameters.glwe_dimension
        );

        assert_eq!(
            glwe_secret_key.polynomial_size(),
            parameters.polynomial_size,
            "Mismatch between the GlweSecretKey PolynomialSize ({:?}) \
            and the parameters PolynomialSize ({:?})",
            glwe_secret_key.polynomial_size(),
            parameters.polynomial_size
        );

        Self {
            lwe_secret_key,
            glwe_secret_key,
            parameters,
        }
    }
}
