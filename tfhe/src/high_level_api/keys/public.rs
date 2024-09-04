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
use tfhe_versionable::Versionize;

use super::ClientKey;
use crate::backward_compatibility::keys::{
    CompactPublicKeyVersions, CompressedCompactPublicKeyVersions, CompressedPublicKeyVersions,
    PublicKeyVersions,
};
use crate::high_level_api::keys::{IntegerCompactPublicKey, IntegerCompressedCompactPublicKey};
use crate::prelude::Tagged;
use crate::shortint::MessageModulus;
use crate::{Error, Tag};

/// Classical public key.
///
/// Works for any parameters, but uses a lot of memory / disk space
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(PublicKeyVersions)]
pub struct PublicKey {
    pub(in crate::high_level_api) key: crate::integer::PublicKey,
    pub(crate) tag: Tag,
}

impl PublicKey {
    /// Creates a PublicKey, derived from the given client key
    pub fn new(client_key: &ClientKey) -> Self {
        let base_integer_key = crate::integer::PublicKey::new(&client_key.key.key);
        Self {
            key: base_integer_key,
            tag: client_key.tag.clone(),
        }
    }

    pub fn into_raw_parts(self) -> (crate::integer::PublicKey, Tag) {
        (self.key, self.tag)
    }

    pub fn from_raw_parts(key: crate::integer::PublicKey, tag: Tag) -> Self {
        Self { key, tag }
    }

    pub(crate) fn message_modulus(&self) -> MessageModulus {
        self.key.parameters().message_modulus()
    }
}

impl Tagged for PublicKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

/// Compressed classical public key.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedPublicKeyVersions)]
pub struct CompressedPublicKey {
    pub(in crate::high_level_api) key: crate::integer::CompressedPublicKey,
    pub(crate) tag: Tag,
}

impl CompressedPublicKey {
    pub fn new(client_key: &ClientKey) -> Self {
        let base_integer_key = crate::integer::CompressedPublicKey::new(&client_key.key.key);
        Self {
            key: base_integer_key,
            tag: client_key.tag.clone(),
        }
    }

    pub fn into_raw_parts(self) -> (crate::integer::CompressedPublicKey, Tag) {
        (self.key, self.tag)
    }

    pub fn from_raw_parts(key: crate::integer::CompressedPublicKey, tag: Tag) -> Self {
        Self { key, tag }
    }

    pub fn decompress(&self) -> PublicKey {
        PublicKey {
            key: self.key.decompress(),
            tag: self.tag.clone(),
        }
    }

    pub(crate) fn message_modulus(&self) -> MessageModulus {
        self.key.parameters().message_modulus()
    }
}

impl Tagged for CompressedPublicKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

/// A more compact public key
///
/// Compared to the  [PublicKey], this one is much smaller
/// however it supports less parameters.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompactPublicKeyVersions)]
pub struct CompactPublicKey {
    pub(in crate::high_level_api) key: IntegerCompactPublicKey,
    pub(crate) tag: Tag,
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
            tag: client_key.tag.clone(),
        }
    }

    pub fn try_new(client_key: &ClientKey) -> Result<Self, Error> {
        IntegerCompactPublicKey::try_new(&client_key.key).map(|key| Self {
            key,
            tag: client_key.tag.clone(),
        })
    }

    pub fn into_raw_parts(self) -> (crate::integer::public_key::CompactPublicKey, Tag) {
        (self.key.into_raw_parts(), self.tag)
    }

    pub fn from_raw_parts(key: crate::integer::public_key::CompactPublicKey, tag: Tag) -> Self {
        Self {
            key: IntegerCompactPublicKey::from_raw_parts(key),
            tag,
        }
    }
}

impl Tagged for CompactPublicKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}

/// Compressed variant of [CompactPublicKey]
///
/// The compression of [CompactPublicKey] allows to save disk space
/// an reduce transfer sizes.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedCompactPublicKeyVersions)]
pub struct CompressedCompactPublicKey {
    pub(in crate::high_level_api) key: IntegerCompressedCompactPublicKey,
    pub(crate) tag: Tag,
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
            tag: client_key.tag.clone(),
        }
    }

    /// Deconstruct a [`CompressedCompactPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> (crate::integer::CompressedCompactPublicKey, Tag) {
        (self.key.into_raw_parts(), self.tag)
    }

    /// Construct a [`CompressedCompactPublicKey`] from its constituents.
    pub fn from_raw_parts(key: crate::integer::CompressedCompactPublicKey, tag: Tag) -> Self {
        Self {
            key: IntegerCompressedCompactPublicKey::from_raw_parts(key),
            tag,
        }
    }

    /// Decompresses the key
    pub fn decompress(&self) -> CompactPublicKey {
        CompactPublicKey {
            key: self.key.decompress(),
            tag: self.tag.clone(),
        }
    }
}

impl Tagged for CompressedCompactPublicKey {
    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn tag_mut(&mut self) -> &mut Tag {
        &mut self.tag
    }
}
