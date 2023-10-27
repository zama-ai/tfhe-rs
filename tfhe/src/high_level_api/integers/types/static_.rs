use serde::{Deserialize, Serialize};

use super::base::GenericInteger;
use crate::high_level_api::integers::parameters::{EvaluationIntegerKey, IntegerId};
use crate::high_level_api::integers::types::compact::{
    GenericCompactInteger, GenericCompactIntegerList,
};
use crate::high_level_api::integers::types::compressed::CompressedGenericInteger;
use crate::high_level_api::internal_traits::TypeIdentifier;
#[cfg(feature = "internal-keycache")]
use crate::integer::keycache::{KEY_CACHE, KEY_CACHE_WOPBS};
use crate::integer::wopbs::WopbsKey;
use paste::paste;

macro_rules! define_static_integer_parameters {
    (
        UnsignedRadix {
            num_bits: $num_bits:literal,
            num_block: $num_block:literal,
        }
    ) => {
        paste! {
            #[doc = concat!("Id for the [FheUint", stringify!($num_bits), "] data type.")]
            #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
            pub struct [<FheUint $num_bits Id>];

            impl IntegerId for [<FheUint $num_bits Id>] {
                type InnerCiphertext = crate::integer::RadixCiphertext;
                type InnerCompressedCiphertext = crate::integer::ciphertext::CompressedRadixCiphertext;

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
    (
        SignedRadix {
            num_bits: $num_bits:literal,
            num_block: $num_block:literal,
        }
    ) => {
        paste! {
            #[doc = concat!("Id for the [FheInt", stringify!($num_bits), "] data type.")]
            #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
            pub struct [<FheInt $num_bits Id>];

            impl IntegerId for [<FheInt $num_bits Id>] {
                type InnerCiphertext = crate::integer::SignedRadixCiphertext;
                type InnerCompressedCiphertext = crate::integer::ciphertext::CompressedSignedRadixCiphertext;

                fn num_blocks() -> usize {
                    $num_block
                }
            }

            impl TypeIdentifier for [<FheInt $num_bits Id>] {
                fn type_variant(&self) -> $crate::high_level_api::errors::Type {
                    $crate::high_level_api::errors::Type::[<FheInt $num_bits>]
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
        }
    ) => {
         paste! {
            #[doc = concat!("An unsigned integer type with", stringify!($num_bits), "bits")]
            $(#[$outer])*
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type $name = GenericInteger<[<$name Id>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compressed $name>] = CompressedGenericInteger<[<$name Id>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compact $name>] = GenericCompactInteger<[<$name Id>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compact $name List>] = GenericCompactIntegerList<[<$name Id>]>;

            impl $crate::high_level_api::global_state::WithGlobalKey for [<$name Id>] {
                type Key = crate::high_level_api::integers::IntegerServerKey;

                fn with_unwrapped_global<R, F>(self, func: F) -> R
                where
                    F: FnOnce(&Self::Key) -> R {
                    $crate::high_level_api::global_state::with_internal_keys(|keys| {
                            func(&keys.integer_key)
                        })
                    }
            }
        }
    };

    // Defines a static integer type that uses
    // the `Radix` representation
    (
        $(#[$outer:meta])*
        Unsigned {
            num_bits: $num_bits:literal,
            parameters: Radix {
                num_block: $num_block:literal,
            },
        }
    ) => {
        define_static_integer_parameters!(
            UnsignedRadix {
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
                }
            );
        }
    };

    // Defines a static integer type that uses
    // the `Radix` representation
    (
        $(#[$outer:meta])*
        Signed {
            num_bits: $num_bits:literal,
            parameters: Radix {
                num_block: $num_block:literal,
            },
        }
    ) => {
        define_static_integer_parameters!(
            SignedRadix {
                num_bits: $num_bits,
                num_block: $num_block,
            }
        );

        ::paste::paste!{
            static_int_type!(
                @impl_types_and_key_traits,
                $(#[$outer])*
                [<FheInt $num_bits>] {
                    num_bits: $num_bits,
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
                .get_from_params(
                    client_key.as_ref().parameters(),
                    crate::integer::IntegerKeyKind::Radix,
                )
                .1
        }
        #[cfg(not(feature = "internal-keycache"))]
        {
            Self::new_radix_server_key(client_key)
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
    Unsigned {
        num_bits: 8,
        parameters: Radix {
            num_block: 4,
        },
    }
}

static_int_type! {
    Unsigned {
        num_bits: 10,
        parameters: Radix {
            num_block: 5,
        },
    }
}

static_int_type! {
    Unsigned {
        num_bits: 12,
        parameters: Radix {
            num_block: 6,
        },
    }
}

static_int_type! {
    Unsigned {
        num_bits: 14,
        parameters: Radix {
            num_block: 7,
        },
    }
}

static_int_type! {
    Unsigned {
        num_bits: 16,
        parameters: Radix {
            num_block: 8,
        },
    }
}

static_int_type! {
    Unsigned {
        num_bits: 32,
        parameters: Radix {
            num_block: 16,
        },
    }
}

static_int_type! {
    Unsigned {
        num_bits: 64,
        parameters: Radix {
            num_block: 32,
        },
    }
}

static_int_type! {
    Unsigned {
        num_bits: 128,
        parameters: Radix {
            num_block: 64,
        },
    }
}

static_int_type! {
    Unsigned {
        num_bits: 256,
        parameters: Radix {
            num_block: 128,
        },
    }
}

static_int_type! {
   Signed {
        num_bits: 8,
        parameters: Radix {
            num_block: 4,
        },
    }
}

static_int_type! {
   Signed {
        num_bits: 16,
        parameters: Radix {
            num_block: 8,
        },
    }
}

static_int_type! {
   Signed {
        num_bits: 32,
        parameters: Radix {
            num_block: 16,
        },
    }
}

static_int_type! {
   Signed {
        num_bits: 64,
        parameters: Radix {
            num_block: 32,
        },
    }
}

static_int_type! {
   Signed {
        num_bits: 128,
        parameters: Radix {
            num_block: 64,
        },
    }
}

static_int_type! {
   Signed {
        num_bits: 256,
        parameters: Radix {
            num_block: 128,
        },
    }
}
