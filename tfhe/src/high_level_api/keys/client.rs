//! This module defines ClientKey
//!
//! - [ClientKey] aggregates the keys used to encrypt/decrypt between normal and homomorphic types.

use super::{CompressedServerKey, ServerKey};
use crate::high_level_api::config::Config;
use crate::high_level_api::keys::IntegerClientKey;
use crate::shortint::MessageModulus;
use concrete_csprng::seeders::Seed;

/// Key of the client
///
/// This struct contains the keys that are of interest to the user
/// as they will allow to encrypt and decrypt data.
///
/// This key **MUST NOT** be sent to the server.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClientKey {
    pub(crate) key: IntegerClientKey,
}

impl ClientKey {
    /// Generates a new key from the given config.
    pub fn generate<C: Into<Config>>(config: C) -> Self {
        let config: Config = config.into();
        Self {
            key: IntegerClientKey::from(config.inner),
        }
    }

    /// Generates a key from a config and uses a seed.
    ///
    /// Using the same seed between generations allows to regenerate the same key.
    ///
    /// ```rust
    /// use bincode;
    /// use tfhe::{ClientKey, ConfigBuilder, Seed};
    ///
    /// let builder = ConfigBuilder::default();
    /// let config = builder.build();
    ///
    /// let cks1 = ClientKey::generate_with_seed(config.clone(), Seed(125));
    /// let cks2 = ClientKey::generate(config.clone());
    /// let cks3 = ClientKey::generate_with_seed(config.clone(), Seed(125));
    ///
    /// // The keys created with the same seed are equal
    /// assert_eq!(
    ///     bincode::serialize(&cks1).unwrap(),
    ///     bincode::serialize(&cks3).unwrap()
    /// );
    /// // Which is not the case for keys not created using the same seed
    /// assert_ne!(
    ///     bincode::serialize(&cks1).unwrap(),
    ///     bincode::serialize(&cks2).unwrap()
    /// );
    /// ```
    pub fn generate_with_seed<C: Into<Config>>(config: C, seed: Seed) -> Self {
        let config: Config = config.into();
        Self {
            key: IntegerClientKey::with_seed(config.inner, seed),
        }
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ClientKey,
        Option<crate::shortint::WopbsParameters>,
    ) {
        self.key.into_raw_parts()
    }

    pub fn from_raw_parts(
        key: crate::integer::ClientKey,
        wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
    ) -> Self {
        Self {
            key: IntegerClientKey::from_raw_parts(key, wopbs_block_parameters),
        }
    }

    /// Generates a new ServerKey
    ///
    /// The `ServerKey` generated is meant to be used to initialize the global state
    /// using [crate::high_level_api::set_server_key].
    pub fn generate_server_key(&self) -> ServerKey {
        ServerKey::new(self)
    }

    /// Generates a new CompressedServerKey
    pub fn generate_compressed_server_key(&self) -> CompressedServerKey {
        CompressedServerKey::new(self)
    }

    pub(crate) fn message_modulus(&self) -> MessageModulus {
        self.key.block_parameters().message_modulus()
    }
}

impl AsRef<crate::integer::ClientKey> for ClientKey {
    fn as_ref(&self) -> &crate::integer::ClientKey {
        &self.key.key
    }
}
