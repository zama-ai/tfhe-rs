//! This module defines ClientKey
//!
//! - [ClientKey] aggregates the keys used to encrypt/decrypt between normal and homomorphic types.

#[cfg(feature = "boolean")]
use crate::high_level_api::booleans::BooleanClientKey;
use crate::high_level_api::config::Config;
use crate::high_level_api::errors::{UninitializedClientKey, UnwrapResultExt};
#[cfg(feature = "integer")]
use crate::high_level_api::integers::IntegerClientKey;
#[cfg(feature = "shortint")]
use crate::high_level_api::shortints::ShortIntClientKey;

use super::ServerKey;

/// Key of the client
///
/// This struct contains the keys that are of interest to the user
/// as they will allow to encrypt and decrypt data.
///
/// This key **MUST NOT** be sent to the server.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClientKey {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_key: BooleanClientKey,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_key: ShortIntClientKey,
    #[cfg(feature = "integer")]
    pub(crate) integer_key: IntegerClientKey,
}

impl ClientKey {
    /// Generates a new keys.
    pub fn generate<C: Into<Config>>(config: C) -> ClientKey {
        #[allow(unused_variables)]
        let config: Config = config.into();
        ClientKey {
            #[cfg(feature = "boolean")]
            boolean_key: BooleanClientKey::from(config.boolean_config),
            #[cfg(feature = "shortint")]
            shortint_key: ShortIntClientKey::from(config.shortint_config),
            #[cfg(feature = "integer")]
            integer_key: IntegerClientKey::from(config.integer_config),
        }
    }

    /// Generates a new ServerKeyChain
    ///
    /// The `ServerKeyChain` generated is meant to be used to initialize the global state
    /// using [crate::high_level_api::set_server_key].
    pub fn generate_server_key(&self) -> ServerKey {
        ServerKey::new(self)
    }
}

/// Trait to be implemented on the client key types that have a corresponding member
/// in the `ClientKeyChain`.
///
/// This is to allow the writing of generic functions.
pub trait RefKeyFromKeyChain: Sized {
    type Key;

    /// The method to implement, shall return a ref to the key or an error if
    /// the key member in the key was not initialized
    fn ref_key(self, keys: &ClientKey) -> Result<&Self::Key, UninitializedClientKey>;

    /// Returns a mutable ref to the key member of the key
    ///
    /// # Panic
    ///
    /// This will panic if the key was not initialized
    #[track_caller]
    fn unwrapped_ref_key(self, keys: &ClientKey) -> &Self::Key {
        self.ref_key(keys).unwrap_display()
    }
}

/// Helper macro to help reduce boiler plate
/// needed to implement `RefKeyFromKeyChain` since for
/// our keys, the implementation is the same, only a few things change.
///
/// It expects:
/// - The implementor type
/// - The  `name` of the key type for which the trait will be implemented.
/// - The identifier (or identifier chain) that points to the member in the `ClientKey` that holds
///   the key for which the trait is implemented.
/// - Type Variant used to identify the type at runtime (see `error.rs`)
#[cfg(any(feature = "integer", feature = "shortint", feature = "boolean"))]
macro_rules! impl_ref_key_from_keychain {
    (
        for $implementor:ty {
            key_type: $key_type:ty,
            keychain_member: $($member:ident).*,
            type_variant: $enum_variant:expr,
        }
    ) => {
        impl crate::high_level_api::keys::RefKeyFromKeyChain for $implementor {
            type Key = $key_type;

            fn ref_key(self, keys: &crate::high_level_api::keys::ClientKey) -> Result<&Self::Key, crate::high_level_api::errors::UninitializedClientKey> {
                keys$(.$member)*
                    .as_ref()
                    .ok_or(crate::high_level_api::errors::UninitializedClientKey($enum_variant))
            }
        }
    }
}
