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
                type InnerCpu = crate::integer::RadixCiphertext;

                #[cfg(not(feature = "gpu"))]
                type InnerGpu = ();
                #[cfg(feature = "gpu")]
                type InnerGpu = crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;

                #[cfg(not(feature = "hpu"))]
                type InnerHpu = ();
                #[cfg(feature = "hpu")]
                type InnerHpu = crate::integer::hpu::ciphertext::HpuRadixCiphertext;

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

static_int_type! {
    Unsigned {
        num_bits: 512,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 1024,
    }
}

static_int_type! {
    Unsigned {
        num_bits: 2048,
    }
}

#[cfg(feature = "extended-types")]
pub use extended::*;

#[cfg(feature = "extended-types")]
mod extended {
    use super::*;

    static_int_type! {
        Unsigned {
            num_bits: 24,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 40,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 48,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 56,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 72,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 80,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 88,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 96,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 104,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 112,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 120,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 136,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 144,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 152,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 168,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 176,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 184,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 192,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 200,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 208,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 216,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 224,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 232,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 240,
        }
    }

    static_int_type! {
        Unsigned {
            num_bits: 248,
        }
    }
}
