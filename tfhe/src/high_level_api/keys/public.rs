//! This module defines PublicKey
//!
//! - [PublicKey] aggregates a key that can be made public, and that allows to encrypt (only)

#[cfg(feature = "boolean")]
use crate::high_level_api::booleans::{BooleanCompressedPublicKey, BooleanPublicKey};
use crate::high_level_api::errors::{UninitializedPublicKey, UnwrapResultExt};
#[cfg(feature = "shortint")]
use crate::high_level_api::shortints::{ShortIntCompressedPublicKey, ShortIntPublicKey};

use super::ClientKey;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_key: BooleanPublicKey,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_key: ShortIntPublicKey,
    #[cfg(feature = "integer")]
    pub(in crate::high_level_api) base_integer_key:
        Option<crate::high_level_api::integers::PublicKeyDyn>,
}

impl PublicKey {
    pub fn new(client_key: &ClientKey) -> Self {
        // Silence warning about unused variable when none of these feature is used
        #[cfg(not(any(feature = "boolean", feature = "shortint", feature = "integer")))]
        let _ = client_key;

        Self {
            #[cfg(feature = "boolean")]
            boolean_key: BooleanPublicKey::new(&client_key.boolean_key),
            #[cfg(feature = "shortint")]
            shortint_key: ShortIntPublicKey::new(&client_key.shortint_key),
            #[cfg(feature = "integer")]
            base_integer_key: {
                client_key.integer_key.key.as_ref().map(|key| {
                    match client_key.integer_key.encryption_type() {
                        crate::shortint::EncryptionKeyChoice::Big => {
                            crate::high_level_api::integers::PublicKeyDyn::Big(
                                crate::integer::PublicKeyBig::new(key),
                            )
                        }
                        crate::shortint::EncryptionKeyChoice::Small => {
                            crate::high_level_api::integers::PublicKeyDyn::Small(
                                crate::integer::PublicKeySmall::new(key),
                            )
                        }
                    }
                })
            },
        }
    }
}

/// Trait to be implemented on the public key types that have a corresponding member
/// in the `PublicKey`.
///
/// This is to allow the writing of generic functions.
pub trait RefKeyFromPublicKeyChain: Sized {
    type Key;

    /// The method to implement, shall return a ref to the key or an error if
    /// the key member in the key was not initialized
    fn ref_key(self, keys: &PublicKey) -> Result<&Self::Key, UninitializedPublicKey>;

    /// Returns a mutable ref to the key member of the key
    ///
    /// # Panic
    ///
    /// This will panic if the key was not initialized
    #[track_caller]
    fn unwrapped_ref_key(self, keys: &PublicKey) -> &Self::Key {
        self.ref_key(keys).unwrap_display()
    }
}

#[cfg(any(feature = "integer", feature = "shortint", feature = "boolean"))]
macro_rules! impl_ref_key_from_public_keychain {
    (
        for $implementor:ty {
            key_type: $key_type:ty,
            keychain_member: $($member:ident).*,
            type_variant: $enum_variant:expr,
        }
    ) => {
        impl crate::high_level_api::keys::RefKeyFromPublicKeyChain for $implementor {
            type Key = $key_type;

            fn ref_key(self, keys: &crate::high_level_api::keys::PublicKey) -> Result<&Self::Key, crate::high_level_api::errors::UninitializedPublicKey> {
                keys$(.$member)*
                    .as_ref()
                    .ok_or(crate::high_level_api::errors::UninitializedPublicKey($enum_variant))
            }
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CompressedPublicKey {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_key: BooleanCompressedPublicKey,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_key: ShortIntCompressedPublicKey,
    #[cfg(feature = "integer")]
    pub(in crate::high_level_api) base_integer_key:
        Option<crate::high_level_api::integers::CompressedPublicKeyDyn>,
}

impl CompressedPublicKey {
    pub fn new(client_key: &ClientKey) -> Self {
        // Silence warning about unused variable when none of these feature is used
        #[cfg(not(any(feature = "boolean", feature = "shortint", feature = "integer")))]
        let _ = client_key;

        Self {
            #[cfg(feature = "boolean")]
            boolean_key: BooleanCompressedPublicKey::new(&client_key.boolean_key),
            #[cfg(feature = "shortint")]
            shortint_key: ShortIntCompressedPublicKey::new(&client_key.shortint_key),
            #[cfg(feature = "integer")]
            base_integer_key: {
                client_key.integer_key.key.as_ref().map(|key| {
                    match client_key.integer_key.encryption_type() {
                        crate::shortint::EncryptionKeyChoice::Big => {
                            crate::high_level_api::integers::CompressedPublicKeyDyn::Big(
                                crate::integer::CompressedPublicKeyBig::new(key),
                            )
                        }
                        crate::shortint::EncryptionKeyChoice::Small => {
                            crate::high_level_api::integers::CompressedPublicKeyDyn::Small(
                                crate::integer::CompressedPublicKeySmall::new(key),
                            )
                        }
                    }
                })
            },
        }
    }

    pub fn decompress(self) -> PublicKey {
        PublicKey {
            #[cfg(feature = "boolean")]
            boolean_key: self.boolean_key.decompress(),
            #[cfg(feature = "shortint")]
            shortint_key: self.shortint_key.decompress(),
            #[cfg(feature = "integer")]
            base_integer_key: self.base_integer_key.map(|key| key.decompress()),
        }
    }
}

pub trait RefKeyFromCompressedPublicKeyChain: Sized {
    type Key;

    /// The method to implement, shall return a ref to the key or an error if
    /// the key member in the key was not initialized
    fn ref_key(self, keys: &CompressedPublicKey) -> Result<&Self::Key, UninitializedPublicKey>;

    /// Returns a mutable ref to the key member of the key
    ///
    /// # Panic
    ///
    /// This will panic if the key was not initialized
    #[track_caller]
    fn unwrapped_ref_key(self, keys: &CompressedPublicKey) -> &Self::Key {
        self.ref_key(keys).unwrap_display()
    }
}

#[cfg(any(feature = "integer", feature = "shortint"))]
macro_rules! impl_ref_key_from_compressed_public_keychain {
    (
        for $implementor:ty {
            key_type: $key_type:ty,
            keychain_member: $($member:ident).*,
            type_variant: $enum_variant:expr,
        }
    ) => {
        impl crate::high_level_api::keys::RefKeyFromCompressedPublicKeyChain for $implementor {
            type Key = $key_type;

            fn ref_key(self, keys: &crate::high_level_api::keys::CompressedPublicKey)
                -> Result<&Self::Key, crate::high_level_api::errors::UninitializedPublicKey>
            {
                keys$(.$member)*
                    .as_ref()
                    .ok_or(crate::high_level_api::errors::UninitializedPublicKey($enum_variant))
            }
        }
    }
}
