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
use crate::high_level_api::integers::{IntegerCompactPublicKey, IntegerCompressedCompactPublicKey};

use super::ClientKey;

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

    pub fn decompress(self) -> PublicKey {
        PublicKey {
            key: crate::integer::PublicKey::from(self.key),
        }
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
        Some(Self {
            key: IntegerCompactPublicKey::try_new(&client_key.key)?,
        })
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

    /// Decompresses the key
    pub fn decompress(self) -> CompactPublicKey {
        CompactPublicKey {
            key: self.key.decompress(),
        }
    }
}
