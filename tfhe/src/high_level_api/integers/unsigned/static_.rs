use crate::high_level_api::integers::unsigned::base::{
    FheUint, FheUintConformanceParams, FheUintId,
};
use crate::high_level_api::integers::unsigned::compressed::CompressedFheUint;
use crate::high_level_api::integers::{FheId, IntegerId};
use serde::{Deserialize, Serialize};
use tfhe_versionable::NotVersioned;

macro_rules! static_int_type {
    // Defines a static integer type that uses
    // the `Radix` representation
    (
        $(#[$outer:meta])*
        Unsigned {
            num_bits: $num_bits:literal,
        }
    ) => {
        // Define the Id of the FheUint concrete/specialized type
        ::paste::paste! {
            #[doc = concat!("Id for the [FheUint", stringify!($num_bits), "] data type.")]
            #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize, NotVersioned)]
            pub struct [<FheUint $num_bits Id>];

            impl IntegerId for [<FheUint $num_bits Id>] {
                fn num_bits() -> usize {
                    $num_bits
                }
            }

            impl FheId for [<FheUint $num_bits Id>] { }

            impl FheUintId for [<FheUint $num_bits Id>] { }
        }

        // Define all specialization of all the necessary types
        ::paste::paste! {
            #[doc = concat!("An unsigned integer type with ", stringify!($num_bits), " bits")]
            #[doc = ""]
            #[doc = "See [FheUint]"]
            $(#[$outer])*
            pub type [<FheUint $num_bits>] = FheUint<[<FheUint $num_bits Id>]>;

            pub type [<Compressed FheUint $num_bits>] = CompressedFheUint<[<FheUint $num_bits Id>]>;

            // Conformance Params
            pub type [<FheUint $num_bits ConformanceParams>] = FheUintConformanceParams<[<FheUint $num_bits Id>]>;
        }
    };
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 2,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 4,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 6,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 8,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 10,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 12,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 14,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 16,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 24,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 32,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 40,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 48,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 56,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 64,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 72,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 80,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 88,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 96,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 104,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 112,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 120,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 128,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 136,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 144,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 152,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 160,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 168,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 176,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 184,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 192,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 200,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 208,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 216,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 224,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 232,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 240,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 248,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 256,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 512,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 1024,
    }
}

#[cfg(feature = "extended-types")]
static_int_type! {
    Unsigned {
        num_bits: 2048,
    }
}
