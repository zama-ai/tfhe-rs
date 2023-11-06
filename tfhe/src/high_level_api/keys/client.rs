//! This module defines ClientKey
//!
//! - [ClientKey] aggregates the keys used to encrypt/decrypt between normal and homomorphic types.

use concrete_csprng::seeders::Seed;

use crate::high_level_api::config::Config;
use crate::high_level_api::integers::IntegerClientKey;

use super::{CompressedServerKey, ServerKey};

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
    /// Generates a new keys.
    pub fn generate<C: Into<Config>>(config: C) -> Self {
        let config: Config = config.into();
        Self {
            key: IntegerClientKey::from(config.inner),
        }
    }

    pub fn generate_with_seed<C: Into<Config>>(config: C, seed: Seed) -> Self {
        let config: Config = config.into();
        Self {
            key: IntegerClientKey::with_seed(config.inner, seed),
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
}

impl AsRef<crate::integer::ClientKey> for ClientKey {
    fn as_ref(&self) -> &crate::integer::ClientKey {
        &self.key.key
    }
}
