use crate::{ClientKey, ServerKey};

use crate::errors::UninitializedKeySwitchingKey;
use crate::high_level_api::errors::UnwrapResultExt;

#[cfg(feature = "boolean")]
use crate::high_level_api::booleans::{BooleanKeySwitchingKey, BooleanKeySwitchingParameters};
#[cfg(feature = "integer")]
use crate::high_level_api::integers::{IntegerKeySwitchingKey, IntegerKeySwitchingParameters};
#[cfg(feature = "shortint")]
use crate::high_level_api::shortints::{ShortIntKeySwitchingKey, ShortIntKeySwitchingParameters};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct KeySwitchingParameters {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_params: BooleanKeySwitchingParameters,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_params: ShortIntKeySwitchingParameters,
    #[cfg(feature = "integer")]
    pub(crate) integer_params: IntegerKeySwitchingParameters,
}

impl KeySwitchingParameters {
    #[cfg(feature = "boolean")]
    pub fn with_boolean_parameters(
        &mut self,
        params: crate::boolean::parameters::BooleanKeySwitchingParameters,
    ) -> &mut Self {
        self.boolean_params.bool_params = Some(params.into());
        self
    }

    #[cfg(feature = "shortint")]
    pub fn with_uint2_parameters(
        &mut self,
        params: crate::shortint::parameters::ShortintKeySwitchingParameters,
    ) -> &mut Self {
        self.shortint_params.uint2_params = Some(params.into());
        self
    }

    #[cfg(feature = "shortint")]
    pub fn with_uint3_parameters(
        &mut self,
        params: crate::shortint::parameters::ShortintKeySwitchingParameters,
    ) -> &mut Self {
        self.shortint_params.uint3_params = Some(params.into());
        self
    }

    #[cfg(feature = "shortint")]
    pub fn with_uint4_parameters(
        &mut self,
        params: crate::shortint::parameters::ShortintKeySwitchingParameters,
    ) -> &mut Self {
        self.shortint_params.uint4_params = Some(params.into());
        self
    }

    #[cfg(feature = "integer")]
    pub fn with_integer_parameters(
        &mut self,
        params: crate::shortint::parameters::ShortintKeySwitchingParameters,
    ) -> &mut Self {
        self.integer_params = IntegerKeySwitchingParameters::from(params);
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySwitchingKey {
    #[cfg(feature = "boolean")]
    pub(crate) boolean_key: BooleanKeySwitchingKey,
    #[cfg(feature = "shortint")]
    pub(crate) shortint_key: ShortIntKeySwitchingKey,
    #[cfg(feature = "integer")]
    pub(crate) integer_key: IntegerKeySwitchingKey,
}

impl KeySwitchingKey {
    /// Creates a key switching key that is able to key switch
    /// ciphertext between two client keys, using the provided parameters.
    pub fn new(
        key_pair_1: (&ClientKey, &ServerKey),
        key_pair_2: (&ClientKey, &ServerKey),
        parameters: KeySwitchingParameters,
    ) -> Self {
        Self {
            #[cfg(feature = "boolean")]
            boolean_key: BooleanKeySwitchingKey::new(
                (&key_pair_1.0.boolean_key, &key_pair_1.1.boolean_key),
                (&key_pair_2.0.boolean_key, &key_pair_2.1.boolean_key),
                parameters.boolean_params,
            ),
            #[cfg(feature = "shortint")]
            shortint_key: ShortIntKeySwitchingKey::new(
                (&key_pair_1.0.shortint_key, &key_pair_1.1.shortint_key),
                (&key_pair_2.0.shortint_key, &key_pair_2.1.shortint_key),
                parameters.shortint_params,
            ),
            #[cfg(feature = "integer")]
            integer_key: IntegerKeySwitchingKey::new(
                (&key_pair_1.0.integer_key, &key_pair_1.1.integer_key),
                (&key_pair_2.0.integer_key, &key_pair_2.1.integer_key),
                parameters.integer_params,
            ),
        }
    }

    /// Creates a key switching key that is able to key switch
    /// ciphertext between two client keys that were created using the same parameters
    pub fn for_same_parameters(
        key_pair_1: (&ClientKey, &ServerKey),
        key_pair_2: (&ClientKey, &ServerKey),
    ) -> Option<Self> {
        Some(Self {
            #[cfg(feature = "boolean")]
            boolean_key: BooleanKeySwitchingKey::for_same_parameters(
                (&key_pair_1.0.boolean_key, &key_pair_1.1.boolean_key),
                (&key_pair_2.0.boolean_key, &key_pair_2.1.boolean_key),
            )?,
            #[cfg(feature = "shortint")]
            shortint_key: ShortIntKeySwitchingKey::for_same_parameters(
                (&key_pair_1.0.shortint_key, &key_pair_1.1.shortint_key),
                (&key_pair_2.0.shortint_key, &key_pair_2.1.shortint_key),
            )?,
            #[cfg(feature = "integer")]
            integer_key: IntegerKeySwitchingKey::for_same_parameters(
                (&key_pair_1.0.integer_key, &key_pair_1.1.integer_key),
                (&key_pair_2.0.integer_key, &key_pair_2.1.integer_key),
            )?,
        })
    }
}

/// Trait to be implemented on the key switching key types that have a corresponding member
/// in the `KeySwitchingKeyChain`.
///
/// This is to allow the writing of generic functions.
pub trait RefKeyFromKeySwitchingKeyChain: Sized {
    type Key;

    /// The method to implement, shall return a ref to the key or an error if
    /// the key member in the key was not initialized
    fn ref_key(self, keys: &KeySwitchingKey) -> Result<&Self::Key, UninitializedKeySwitchingKey>;

    /// Returns a ref to the key member of the key
    ///
    /// # Panic
    ///
    /// This will panic if the key was not initialized
    #[track_caller]
    fn unwrapped_ref_key(self, keys: &KeySwitchingKey) -> &Self::Key {
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
macro_rules! impl_ref_key_from_key_switching_keychain {
    (
        for $implementor:ty {
            key_type: $key_type:ty,
            keychain_member: $($member:ident).*,
            type_variant: $enum_variant:expr,
        }
    ) => {
        impl crate::high_level_api::keys::RefKeyFromKeySwitchingKeyChain for $implementor {
            type Key = $key_type;

            fn ref_key(self, keys: &crate::high_level_api::keys::KeySwitchingKey) -> Result<&Self::Key, crate::high_level_api::errors::UninitializedKeySwitchingKey> {
                keys$(.$member)*
                    .as_ref()
                    .ok_or(crate::high_level_api::errors::UninitializedKeySwitchingKey($enum_variant))
            }
        }
    }
}
