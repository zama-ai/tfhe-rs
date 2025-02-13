use crate::high_level_api::integers::signed::base::{FheInt, FheIntConformanceParams, FheIntId};
use crate::high_level_api::integers::signed::compressed::CompressedFheInt;
use crate::high_level_api::{FheId, IntegerId};
use serde::{Deserialize, Serialize};
use tfhe_versionable::NotVersioned;

macro_rules! static_int_type {
    // Defines a static integer type that uses
    // the `Radix` representation
    (
        $(#[$outer:meta])*
        Signed {
            num_bits: $num_bits:literal,
        }
    ) => {
        // Define the Id of the FheInt concrete/specialized type
        ::paste::paste! {
            #[doc = concat!("Id for the [FheInt", stringify!($num_bits), "] data type.")]
            #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize, NotVersioned)]
            pub struct [<FheInt $num_bits Id>];

            impl IntegerId for [<FheInt $num_bits Id>] {
                fn num_bits() -> usize {
                    $num_bits
                }
            }

            impl FheId for [<FheInt $num_bits Id>] { }

            impl FheIntId for [<FheInt $num_bits Id>] { }
        }

        // Define all specialization of all the necessary types
        ::paste::paste! {
            #[doc = concat!("A signed integer type with ", stringify!($num_bits), " bits")]
            #[doc = ""]
            #[doc = "See [FheInt]"]
            $(#[$outer])*
            pub type [<FheInt $num_bits>] = FheInt<[<FheInt $num_bits Id>]>;

            #[doc = concat!("A compressed signed integer type with ", stringify!($num_bits), " bits")]
            pub type [<Compressed FheInt $num_bits>] = CompressedFheInt<[<FheInt $num_bits Id>]>;

            // Conformance Params
            pub type [<FheInt $num_bits ConformanceParams>] = FheIntConformanceParams<[<FheInt $num_bits Id>]>;
        }
    };
}

static_int_type! {
    Signed {
        num_bits: 8,
    }
}

static_int_type! {
    Signed {
        num_bits: 16,
    }
}

static_int_type! {
    Signed {
        num_bits: 32,
    }
}

static_int_type! {
    Signed {
        num_bits: 64,
    }
}

static_int_type! {
    Signed {
        num_bits: 128,
    }
}

#[cfg(feature = "extended-types")]
pub use extended::*;

#[cfg(feature = "extended-types")]
mod extended {
    use super::*;

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 2,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 4,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 6,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 10,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 12,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 14,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 24,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 40,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 48,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 56,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 72,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 80,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 88,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 96,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 104,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 112,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 120,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 136,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 144,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 152,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 160,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 168,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 176,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 184,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 192,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 200,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 208,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 216,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 224,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 232,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 240,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 248,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 256,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 512,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 1024,
        }
    }

    #[cfg(feature = "extended-types")]
    static_int_type! {
        Signed {
            num_bits: 2048,
        }
    }
}
