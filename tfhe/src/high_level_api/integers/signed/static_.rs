#[cfg(feature = "zk-pok-experimental")]
use super::zk::{ProvenCompactFheInt, ProvenCompactFheIntList};
use crate::high_level_api::integers::signed::base::{FheInt, FheIntConformanceParams, FheIntId};
use crate::high_level_api::integers::signed::compact::{
    CompactFheInt, CompactFheIntList, CompactFheIntListConformanceParams,
};
use crate::high_level_api::integers::signed::compressed::CompressedFheInt;
use crate::high_level_api::IntegerId;
use serde::{Deserialize, Serialize};

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
            #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
            pub struct [<FheInt $num_bits Id>];

            impl IntegerId for [<FheInt $num_bits Id>] {
                fn num_bits() -> usize {
                    $num_bits
                }
            }

            impl FheIntId for [<FheInt $num_bits Id>] { }
        }

        // Define all specialization of all the necessary types
        ::paste::paste! {
            #[doc = concat!("A signed integer type with ", stringify!($num_bits), " bits")]
            #[doc = ""]
            #[doc = "See [FheInt]"]
            $(#[$outer])*
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<FheInt $num_bits>] = FheInt<[<FheInt $num_bits Id>]>;

            #[doc = concat!("A compressed signed integer type with ", stringify!($num_bits), " bits")]
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compressed FheInt $num_bits>] = CompressedFheInt<[<FheInt $num_bits Id>]>;

            #[doc = concat!("A compact signed integer type with ", stringify!($num_bits), " bits")]
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compact FheInt $num_bits>] = CompactFheInt<[<FheInt $num_bits Id>]>;

            #[doc = concat!("A compact list of signed integer type with ", stringify!($num_bits), " bits")]
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compact FheInt $num_bits List>] = CompactFheIntList<[<FheInt $num_bits Id>]>;

            // Conformance Params
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<FheInt $num_bits ConformanceParams>] = FheIntConformanceParams<[<FheInt $num_bits Id>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compact FheInt $num_bits ListConformanceParams>] = CompactFheIntListConformanceParams<[<FheInt $num_bits Id>]>;

            // Zero-knowledge Stuff
            #[cfg(feature = "zk-pok-experimental")]
            pub type [<ProvenCompactFheInt $num_bits>] = ProvenCompactFheInt<[<FheInt $num_bits Id>]>;

            #[cfg(feature = "zk-pok-experimental")]
            pub type [<ProvenCompactFheInt $num_bits List>] = ProvenCompactFheIntList<[<FheInt $num_bits Id>]>;
        }
    };
}

static_int_type! {
    Signed {
        num_bits: 2,
    }
}

static_int_type! {
    Signed {
        num_bits: 4,
    }
}

static_int_type! {
    Signed {
        num_bits: 6,
    }
}

static_int_type! {
    Signed {
        num_bits: 8,
    }
}

static_int_type! {
    Signed {
        num_bits: 10,
    }
}

static_int_type! {
    Signed {
        num_bits: 12,
    }
}

static_int_type! {
    Signed {
        num_bits: 14,
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

static_int_type! {
    Signed {
        num_bits: 160,
    }
}

static_int_type! {
    Signed {
        num_bits: 256,
    }
}
