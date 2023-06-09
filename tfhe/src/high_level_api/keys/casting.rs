use crate::{ClientKey, ServerKey};

use crate::errors::UninitializedCastingKey;
use crate::high_level_api::errors::UnwrapResultExt;

#[cfg(feature = "integer")]
use crate::high_level_api::integers::IntegerCastingKey;
#[cfg(feature = "shortint")]
use crate::high_level_api::shortints::ShortIntCastingKey;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CastingKey {
    // #[cfg(feature = "boolean")]
    // pub(crate) boolean_key: BooleanClientKey,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_key: ShortIntCastingKey,
    #[cfg(feature = "integer")]
    pub(crate) integer_key: IntegerCastingKey,
}

impl CastingKey {
    pub fn new(key_pair_1: (&ClientKey, &ServerKey), key_pair_2: (&ClientKey, &ServerKey)) -> Self {
        Self {
            // #[cfg(feature = "boolean")]
            // boolean_key: Arc::new(BooleanServerKey::new(&keys.boolean_key)),
            #[cfg(feature = "shortint")]
            shortint_key: ShortIntCastingKey::new(
                (&key_pair_1.0.shortint_key, &key_pair_1.1.shortint_key),
                (&key_pair_2.0.shortint_key, &key_pair_2.1.shortint_key),
            ),
            #[cfg(feature = "integer")]
            integer_key: IntegerCastingKey::new(
                (&key_pair_1.0.integer_key, &key_pair_1.1.integer_key),
                (&key_pair_2.0.integer_key, &key_pair_2.1.integer_key),
            ),
        }
    }
}

/// Trait to be implemented on the casting key types that have a corresponding member
/// in the `CastingKeyChain`.
///
/// This is to allow the writing of generic functions.
pub trait RefKeyFromCastingKeyChain: Sized {
    type Key;

    /// The method to implement, shall return a ref to the key or an error if
    /// the key member in the key was not initialized
    fn ref_key(self, keys: &CastingKey) -> Result<&Self::Key, UninitializedCastingKey>;

    /// Returns a ref to the key member of the key
    ///
    /// # Panic
    ///
    /// This will panic if the key was not initialized
    #[track_caller]
    fn unwrapped_ref_key(self, keys: &CastingKey) -> &Self::Key {
        self.ref_key(keys).unwrap_display()
    }
}

/// Helper macro to help reduce boiler plate
/// needed to implement `RefCastingKeyFromKeyChain` since for
/// our keys, the implementation is the same, only a few things change.
///
/// It expects:
/// - The implementor type
/// - The  `name` of the key type for which the trait will be implemented.
/// - The identifier (or identifier chain) that points to the member in the `ClientKey` that holds
///   the key for which the trait is implemented.
/// - Type Variant used to identify the type at runtime (see `error.rs`)
#[cfg(any(feature = "integer", feature = "shortint", feature = "boolean"))]
macro_rules! impl_ref_key_from_casting_keychain {
    (
        for $implementor:ty {
            key_type: $key_type:ty,
            keychain_member: $($member:ident).*,
            type_variant: $enum_variant:expr,
        }
    ) => {
        impl crate::high_level_api::keys::RefKeyFromCastingKeyChain for $implementor {
            type Key = $key_type;

            fn ref_key(self, keys: &crate::high_level_api::keys::CastingKey) -> Result<&Self::Key, crate::high_level_api::errors::UninitializedCastingKey> {
                keys$(.$member)*
                    .as_ref()
                    .ok_or(crate::high_level_api::errors::UninitializedCastingKey($enum_variant))
            }
        }
    }
}
