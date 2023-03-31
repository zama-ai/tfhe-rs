//! This module defines PublicKey
//!
//! - [PublicKey] aggregates a key that can be made public, and that allows to encrypt (only)

#[cfg(feature = "boolean")]
use crate::typed_api::booleans::BooleanPublicKey;
use crate::typed_api::errors::{UninitializedPublicKey, UnwrapResultExt};
#[cfg(feature = "integer")]
use crate::typed_api::integers::IntegerPublicKey;
#[cfg(feature = "shortint")]
use crate::typed_api::shortints::ShortIntPublicKey;

use super::ClientKey;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_key: BooleanPublicKey,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_key: ShortIntPublicKey,
    #[cfg(feature = "integer")]
    pub(crate) integer_key: IntegerPublicKey,
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
            integer_key: IntegerPublicKey::new(&client_key.integer_key),
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
        impl crate::typed_api::keys::RefKeyFromPublicKeyChain for $implementor {
            type Key = $key_type;

            fn ref_key(self, keys: &crate::typed_api::keys::PublicKey) -> Result<&Self::Key, crate::typed_api::errors::UninitializedPublicKey> {
                keys$(.$member)*
                    .as_ref()
                    .ok_or(crate::typed_api::errors::UninitializedPublicKey($enum_variant))
            }
        }
    }
}
