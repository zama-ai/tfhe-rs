//! This module defines PublicKey types.
//!
//! Public keys are keys that can only be used to encrypt data,
//! they are meant to be shared publicly.
//!
//! There are currently 2 types of public key:
//! - [PublicKey], Classical public key, works for any parameters, but its size can get large very
//!   rapidly.
//! - [CompactPublicKey], This key uses significantly less memory/disk space. It it however, not
//!   compatible with all parameters.
//!
//! Each of these two keys have a compressed variant that allows to reduce
//! transfer sizes.
//! - [CompressedPublicKey]
//! - [CompressedCompactPublicKey]
use super::ClientKey;
use crate::high_level_api::keys::{IntegerCompactPublicKey, IntegerCompressedCompactPublicKey};
use crate::integer::encryption::KnowsMessageModulus;
use crate::shortint::MessageModulus;

/// Classical public key.
///
/// Works for any parameters, but uses a lot of memory / disk space
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    pub(in crate::high_level_api) key: crate::integer::PublicKey,
}

impl PublicKey {
    /// Creates a PublicKey, derived from the given client key
    pub fn new(client_key: &ClientKey) -> Self {
        let base_integer_key = crate::integer::PublicKey::new(&client_key.key.key);
        Self {
            key: base_integer_key,
        }
    }

    pub fn into_raw_parts(self) -> crate::integer::PublicKey {
        self.key
    }

    pub fn from_raw_parts(key: crate::integer::PublicKey) -> Self {
        Self { key }
    }

    pub(crate) fn message_modulus(&self) -> MessageModulus {
        self.key.parameters().message_modulus()
    }
}

/// Compressed classical public key.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CompressedPublicKey {
    pub(in crate::high_level_api) key: crate::integer::CompressedPublicKey,
}

impl CompressedPublicKey {
    pub fn new(client_key: &ClientKey) -> Self {
        let base_integer_key = crate::integer::CompressedPublicKey::new(&client_key.key.key);
        Self {
            key: base_integer_key,
        }
    }

    pub fn into_raw_parts(self) -> crate::integer::CompressedPublicKey {
        self.key
    }

    pub fn from_raw_parts(key: crate::integer::CompressedPublicKey) -> Self {
        Self { key }
    }

    pub fn decompress(&self) -> PublicKey {
        PublicKey {
            key: self.key.decompress(),
        }
    }

    pub(crate) fn message_modulus(&self) -> MessageModulus {
        self.key.parameters().message_modulus()
    }
}

/// A more compact public key
///
/// Compared to the  [PublicKey], this one is much smaller
/// however it supports less parameters.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CompactPublicKey {
    pub(in crate::high_level_api) key: IntegerCompactPublicKey,
}

impl CompactPublicKey {
    /// Creates a CompactPublicKey, derived from the given client key
    ///
    /// # Panic
    ///
    /// This will panic if parameters are not compatible
    pub fn new(client_key: &ClientKey) -> Self {
        Self {
            key: IntegerCompactPublicKey::new(&client_key.key),
        }
    }

    pub fn try_new(client_key: &ClientKey) -> Option<Self> {
        IntegerCompactPublicKey::try_new(&client_key.key).map(|key| Self { key })
    }

    pub fn into_raw_parts(self) -> crate::integer::public_key::CompactPublicKey {
        self.key.into_raw_parts()
    }

    pub fn from_raw_parts(key: crate::integer::public_key::CompactPublicKey) -> Self {
        Self {
            key: IntegerCompactPublicKey::from_raw_parts(key),
        }
    }

    pub(crate) fn message_modulus(&self) -> MessageModulus {
        self.key.key.key.message_modulus()
    }
}

/// Compressed variant of [CompactPublicKey]
///
/// The compression of [CompactPublicKey] allows to save disk space
/// an reduce transfer sizes.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CompressedCompactPublicKey {
    pub(in crate::high_level_api) key: IntegerCompressedCompactPublicKey,
}

impl CompressedCompactPublicKey {
    /// Creates a CompressedCompactPublicKey
    ///
    /// # Panic
    ///
    /// This will panic if parameters are not compatible
    pub fn new(client_key: &ClientKey) -> Self {
        Self {
            key: IntegerCompressedCompactPublicKey::new(&client_key.key),
        }
    }

    /// Deconstruct a [`CompressedCompactPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> crate::integer::CompressedCompactPublicKey {
        self.key.into_raw_parts()
    }

    /// Construct a [`CompressedCompactPublicKey`] from its constituents.
    pub fn from_raw_parts(key: crate::integer::CompressedCompactPublicKey) -> Self {
        Self {
            key: IntegerCompressedCompactPublicKey::from_raw_parts(key),
        }
    }

    /// Decompresses the key
    pub fn decompress(&self) -> CompactPublicKey {
        CompactPublicKey {
            key: self.key.decompress(),
        }
    }
}
