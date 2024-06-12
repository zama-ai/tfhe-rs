#[cfg(feature = "zk-pok-experimental")]
use super::zk::{ProvenCompactFheUint, ProvenCompactFheUintList};
use crate::high_level_api::backward_compatibility::integers::*;
use crate::high_level_api::integers::unsigned::base::{
    FheUint, FheUintConformanceParams, FheUintId,
};
use crate::high_level_api::integers::unsigned::compact::{
    CompactFheUint, CompactFheUintList, CompactFheUintListConformanceParams,
};
use crate::high_level_api::integers::unsigned::compressed::CompressedFheUint;
use crate::high_level_api::integers::IntegerId;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

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
            #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize, Versionize)]
            #[versionize([<FheUint $num_bits IdVersions>])]
            pub struct [<FheUint $num_bits Id>];

            impl IntegerId for [<FheUint $num_bits Id>] {
                fn num_bits() -> usize {
                    $num_bits
                }
            }

            impl FheUintId for [<FheUint $num_bits Id>] { }
        }

        // Define all specialization of all the necessary types
        ::paste::paste! {
            #[doc = concat!("An unsigned integer type with ", stringify!($num_bits), " bits")]
            #[doc = ""]
            #[doc = "See [FheUint]"]
            $(#[$outer])*
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<FheUint $num_bits>] = FheUint<[<FheUint $num_bits Id>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compressed FheUint $num_bits>] = CompressedFheUint<[<FheUint $num_bits Id>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compact FheUint $num_bits>] = CompactFheUint<[<FheUint $num_bits Id>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compact FheUint $num_bits List>] = CompactFheUintList<[<FheUint $num_bits Id>]>;

            // Conformance Params
            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<FheUint $num_bits ConformanceParams>] = FheUintConformanceParams<[<FheUint $num_bits Id>]>;

            #[cfg_attr(all(doc, not(doctest)), cfg(feature = "integer"))]
            pub type [<Compact FheUint $num_bits ListConformanceParams>] = CompactFheUintListConformanceParams<[<FheUint $num_bits Id>]>;

            #[cfg(feature = "zk-pok-experimental")]
            pub type [<ProvenCompactFheUint $num_bits>] = ProvenCompactFheUint<[<FheUint $num_bits Id>]>;

            #[cfg(feature = "zk-pok-experimental")]
            pub type [<ProvenCompactFheUint $num_bits List>] = ProvenCompactFheUintList<[<FheUint $num_bits Id>]>;
        }
    };
}

static_int_type! {
    Unsigned {
        num_bits: 2,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 4,
    }
}

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

static_int_type! {
    Unsigned {
        num_bits: 10,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 12,
    }
}

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

static_int_type! {
    Unsigned {
        num_bits: 32,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 64,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 128,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 160,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 256,
    }
}
