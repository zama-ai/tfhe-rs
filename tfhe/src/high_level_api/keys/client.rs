//! This module defines ClientKey
//!
//! - [ClientKey] aggregates the keys used to encrypt/decrypt between normal and homomorphic types.

use super::{CompressedServerKey, ServerKey};
use crate::high_level_api::backward_compatibility::keys::ClientKeyVersions;
use crate::high_level_api::config::Config;
use crate::high_level_api::keys::{CompactPrivateKey, IntegerClientKey};
use crate::integer::compression_keys::CompressionPrivateKeys;
use crate::named::Named;
use crate::prelude::Tagged;
use crate::shortint::MessageModulus;
use crate::Tag;
use tfhe_csprng::seeders::Seed;
use tfhe_versionable::Versionize;

/// Key of the client
///
/// This struct contains the keys that are of interest to the user
/// as they will allow to encrypt and decrypt data.
///
/// This key **MUST NOT** be sent to the server.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(ClientKeyVersions)]
pub struct ClientKey {
    pub(crate) key: IntegerClientKey,
    pub(crate) tag: Tag,
}

impl ClientKey {
    /// Generates a new key from the given config.
    pub fn generate<C: Into<Config>>(config: C) -> Self {
        let config: Config = config.into();
        Self {
            key: IntegerClientKey::from(config.inner),
            tag: Tag::default(),
        }
    }

    /// Generates a key from a config and uses a seed.
    ///
    /// Using the same seed between generations allows to regenerate the same key.
    ///
    /// ```rust
    /// use tfhe::{ClientKey, ConfigBuilder, Seed};
    ///
    /// let builder = ConfigBuilder::default();
    /// let config = builder.build();
    ///
    /// let cks1 = ClientKey::generate_with_seed(config, Seed(125));
    /// let cks2 = ClientKey::generate(config);
    /// let cks3 = ClientKey::generate_with_seed(config, Seed(125));
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
            tag: Tag::default(),
        }
    }

    pub fn computation_parameters(&self) -> crate::shortint::PBSParameters {
        self.key.block_parameters()
    }

    pub fn into_raw_parts(
        self,
    ) -> (
        crate::integer::ClientKey,
        Option<CompactPrivateKey>,
        Option<CompressionPrivateKeys>,
        Tag,
    ) {
        let (cks, cpk, cppk) = self.key.into_raw_parts();
        (cks, cpk, cppk, self.tag)
    }

    pub fn from_raw_parts(
        key: crate::integer::ClientKey,
        dedicated_compact_private_key: Option<(
            crate::integer::CompactPrivateKey<Vec<u64>>,
            crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters,
        )>,
        compression_key: Option<CompressionPrivateKeys>,
        tag: Tag,
    ) -> Self {
        Self {
            key: IntegerClientKey::from_raw_parts(
                key,
                dedicated_compact_private_key,
                compression_key,
            ),
            tag,
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

impl Tagged for ClientKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

impl AsRef<crate::integer::ClientKey> for ClientKey {
    fn as_ref(&self) -> &crate::integer::ClientKey {
        &self.key.key
    }
}

impl Named for ClientKey {
    const NAME: &'static str = "high_level_api::ClientKey";
}
