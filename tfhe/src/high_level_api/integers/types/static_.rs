use serde::{Deserialize, Serialize};

use super::base::GenericInteger;
use crate::high_level_api::integers::parameters::{EvaluationIntegerKey, IntegerParameter};
use crate::high_level_api::integers::types::compressed::CompressedGenericInteger;
use crate::high_level_api::internal_traits::{ParameterType, TypeIdentifier};
#[cfg(feature = "internal-keycache")]
use crate::integer::keycache::{KEY_CACHE, KEY_CACHE_WOPBS};
use crate::integer::wopbs::WopbsKey;
use paste::paste;

macro_rules! define_static_integer_parameters {
    (
        Radix {
            num_bits: $num_bits:literal,
            num_block: $num_block:literal,
        }
    ) => {
        paste! {
            #[doc = concat!("Id for the [FheUint", stringify!($num_bits), "] data type.")]
            #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
            pub struct [<FheUint $num_bits Id>];

            #[doc = concat!("Parameters for the [FheUint", stringify!($num_bits), "] data type.")]
            #[derive(Copy, Clone, Debug, Serialize, Deserialize)]
            pub struct [<FheUint $num_bits Parameters>];

            impl ParameterType for [<FheUint $num_bits Parameters>] {
                type Id = [<FheUint $num_bits Id>];
            }

            impl IntegerParameter for [<FheUint $num_bits Parameters>] {
                fn num_blocks() -> usize {
                    $num_block
                }
            }

            impl TypeIdentifier for [<FheUint $num_bits Id>] {
                fn type_variant(&self) -> $crate::high_level_api::errors::Type {
                    $crate::high_level_api::errors::Type::[<FheUint $num_bits>]
                }
            }
        }
    };
}

macro_rules! static_int_type {
    // This rule generates the types specialization
    // as well as call the macros
    // that implement necessary traits for the ClientKey and ServerKey
    //
    // This is not meant to be used directly, instead see the other rules below
    (
        @impl_types_and_key_traits,
        $(#[$outer:meta])*
        $name:ident {
            num_bits: $num_bits:literal,
            keychain_member: $($member:ident).*,
        }
    ) => {
         paste! {
            #[doc = concat!("An unsigned integer type with", stringify!($num_bits), "bits")]
            $(#[$outer])*
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type $name = GenericInteger<[<$name Parameters>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compressed $name>] = CompressedGenericInteger<[<$name Parameters>]>;


            impl $crate::high_level_api::keys::RefKeyFromKeyChain for [<FheUint $num_bits Id>] {
                type Key = crate::integer::ClientKey;

                fn ref_key(self, keys: &crate::high_level_api::ClientKey)
                    -> Result<&Self::Key, $crate::high_level_api::errors::UninitializedClientKey> {
                    keys
                        .integer_key
                        .key
                        .as_ref()
                        .ok_or($crate::high_level_api::errors::UninitializedClientKey(self.type_variant()))
                }
            }

            impl $crate::high_level_api::global_state::WithGlobalKey for [<FheUint $num_bits Id>] {
                type Key = crate::high_level_api::integers::IntegerServerKey;

                fn with_global<R, F>(self, func: F) -> Result<R, $crate::high_level_api::errors::UninitializedServerKey>
                where
                    F: FnOnce(&Self::Key) -> R {
                    $crate::high_level_api::global_state::with_internal_keys(|keys| {
                            Ok(func(&keys.integer_key))
                        })
                    }
            }
        }
    };

    // Defines a static integer type that uses
    // the `Radix` representation
    (
        $(#[$outer:meta])*
        {
            num_bits: $num_bits:literal,
            keychain_member: $($member:ident).*,
            parameters: Radix {
                num_block: $num_block:literal,
            },
        }
    ) => {
        define_static_integer_parameters!(
            Radix {
                num_bits: $num_bits,
                num_block: $num_block,
            }
        );

        ::paste::paste!{
            static_int_type!(
                @impl_types_and_key_traits,
                $(#[$outer])*
                [<FheUint $num_bits>] {
                    num_bits: $num_bits,
                    keychain_member: $($member).*,
                }
            );
        }
    };
}

impl<C> EvaluationIntegerKey<C> for crate::integer::ServerKey
where
    C: AsRef<crate::integer::ClientKey>,
{
    fn new(client_key: &C) -> Self {
        #[cfg(feature = "internal-keycache")]
        {
            KEY_CACHE
                .get_from_params(client_key.as_ref().parameters())
                .1
        }
        #[cfg(not(feature = "internal-keycache"))]
        {
            crate::integer::ServerKey::new(client_key)
        }
    }

    fn new_wopbs_key(
        client_key: &C,
        server_key: &Self,
        wopbs_block_parameters: crate::shortint::WopbsParameters,
    ) -> WopbsKey {
        #[cfg(not(feature = "internal-keycache"))]
        {
            WopbsKey::new_wopbs_key(client_key.as_ref(), server_key, &wopbs_block_parameters)
        }
        #[cfg(feature = "internal-keycache")]
        {
            let _ = &server_key; // silence warning
            KEY_CACHE_WOPBS
                .get_from_params((client_key.as_ref().parameters(), wopbs_block_parameters))
        }
    }
}

static_int_type! {
    {
        num_bits: 8,
        keychain_member: integer_key.uint8_key,
        parameters: Radix {
            num_block: 4,
        },
    }
}

static_int_type! {
    {
        num_bits: 10,
        keychain_member: integer_key.uint10_key,
        parameters: Radix {
            num_block: 5,
        },
    }
}

static_int_type! {
    {
        num_bits: 12,
        keychain_member: integer_key.uint12_key,
        parameters: Radix {
            num_block: 6,
        },
    }
}

static_int_type! {
    {
        num_bits: 14,
        keychain_member: integer_key.uint14_key,
        parameters: Radix {
            num_block: 7,
        },
    }
}

static_int_type! {
    {
        num_bits: 16,
        keychain_member: integer_key.uint16_key,
        parameters: Radix {
            num_block: 8,
        },
    }
}

static_int_type! {
    {
        num_bits: 32,
        keychain_member: integer_key.uint32_key,
        parameters: Radix {
            num_block: 16,
        },
    }
}

static_int_type! {
    {
        num_bits: 64,
        keychain_member: integer_key.uint64_key,
        parameters: Radix {
            num_block: 32,
        },
    }
}

static_int_type! {
    {
        num_bits: 128,
        keychain_member: integer_key.uint128_key,
        parameters: Radix {
            num_block: 64,
        },
    }
}

static_int_type! {
    {
        num_bits: 256,
        keychain_member: integer_key.uint256_key,
        parameters: Radix {
            num_block: 128,
        },
    }
}
