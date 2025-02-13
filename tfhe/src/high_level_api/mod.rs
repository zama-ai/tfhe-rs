#![allow(unused_doc_comments)]

// internal helper macro to make it easier to `pub use`
// all necessary stuff tied to a FheUint/FheInt from the given `module_path`.
#[allow(unused)]
macro_rules! expand_pub_use_fhe_type(
    (
        pub use $module_path:path { $($fhe_type_name:ident),* $(,)? };
    )=> {

        ::paste::paste! {
            pub use $module_path::{
                $(
                    $fhe_type_name,
                    [<Compressed $fhe_type_name>],
                    [<$fhe_type_name Id>],

                    // ConformanceParams
                    [<$fhe_type_name ConformanceParams>],
                )*
            };
        }
    }
);

macro_rules! export_concrete_array_types {
    (
        pub use $module_path:path { $($fhe_type_name:ident),* $(,)? };

    ) => {
          ::paste::paste! {
            pub use $module_path::{
                $(
                    // DynBackend
                    [<$fhe_type_name Array>],
                    [<$fhe_type_name Slice>],
                    [<$fhe_type_name SliceMut>],

                    // CpuBackend
                    [<Cpu $fhe_type_name Array>],
                    [<Cpu $fhe_type_name Slice>],
                    [<Cpu $fhe_type_name SliceMut>],
                )*
            };
        }
    };
}

pub use crate::core_crypto::commons::math::random::Seed;
pub use crate::integer::server_key::MatchValues;
pub use config::{Config, ConfigBuilder};
#[cfg(feature = "gpu")]
pub use global_state::CudaGpuChoice;
pub use global_state::{set_server_key, unset_server_key, with_server_key_as_context};

pub use integers::{CompressedFheInt, CompressedFheUint, FheInt, FheUint, IntegerId};
#[cfg(feature = "gpu")]
pub use keys::CudaServerKey;
pub use keys::{
    generate_keys, ClientKey, CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey,
    CompressedServerKey, KeySwitchingKey, PublicKey, ServerKey,
};

#[cfg(test)]
mod tests;

pub use crate::high_level_api::booleans::{CompressedFheBool, FheBool, FheBoolConformanceParams};

#[cfg(feature = "extended-types")]
expand_pub_use_fhe_type!(
    pub use crate::high_level_api::integers{
        FheUint2, FheUint4, FheUint6, FheUint10, FheUint12, FheUint14, FheUint24, FheUint40,
        FheUint48, FheUint56, FheUint72, FheUint80,FheUint88, FheUint96, FheUint104,
        FheUint112, FheUint120, FheUint136, FheUint144, FheUint152, FheUint160, FheUint168,
        FheUint176, FheUint184, FheUint192, FheUint200, FheUint208, FheUint216, FheUint224,
        FheUint232, FheUint240, FheUint248, FheUint256, FheUint512, FheUint1024, FheUint2048,

        FheInt2, FheInt4, FheInt6, FheInt10, FheInt12, FheInt14, FheInt24, FheInt40,
        FheInt48, FheInt56, FheInt72, FheInt80,FheInt88, FheInt96, FheInt104,
        FheInt112, FheInt120, FheInt136, FheInt144, FheInt152, FheInt160, FheInt168,
        FheInt176, FheInt184, FheInt192, FheInt200, FheInt208, FheInt216, FheInt224,
        FheInt232, FheInt240, FheInt248, FheInt256, FheInt512, FheInt1024, FheInt2048,
    };
);

expand_pub_use_fhe_type!(
    pub use crate::high_level_api::integers{
        FheUint8, FheUint16, FheUint32, FheUint64, FheUint128,
        FheInt8, FheInt16, FheInt32, FheInt64, FheInt128,
    };
);
pub use array::{
    ClearArray, CpuFheIntArray, CpuFheIntSlice, CpuFheIntSliceMut, CpuFheUintArray,
    CpuFheUintSlice, CpuFheUintSliceMut, FheBoolId, FheIntArray, FheIntSlice, FheIntSliceMut,
    FheUintArray, FheUintSlice, FheUintSliceMut,
};
export_concrete_array_types!(
    pub use array{
        FheBool,
        FheUint8, FheUint16, FheUint32, FheUint64, FheUint128,
        FheInt8, FheInt16, FheInt32, FheInt64, FheInt128,
    };
);
#[cfg(feature = "extended-types")]
export_concrete_array_types!(
    pub use array{
        FheUint2, FheUint4, FheUint256,
        FheInt2, FheInt4, FheInt256,
    };
);

pub use crate::integer::parameters::CompactCiphertextListConformanceParams;
pub use crate::safe_serialization::{DeserializationConfig, SerializationConfig};
#[cfg(feature = "strings")]
pub use crate::strings::ciphertext::ClearString;

#[cfg(feature = "zk-pok")]
pub use compact_list::ProvenCompactCiphertextList;
pub use compact_list::{
    CompactCiphertextList, CompactCiphertextListBuilder, CompactCiphertextListExpander,
};
pub use compressed_ciphertext_list::{
    CompressedCiphertextList, CompressedCiphertextListBuilder, HlCompressible, HlExpandable,
};
#[cfg(feature = "strings")]
pub use strings::ascii::{EncryptableString, FheAsciiString, FheStringIsEmpty, FheStringLen};
pub use tag::Tag;
pub use traits::FheId;

mod booleans;
mod compressed_ciphertext_list;
mod config;
mod errors;
mod global_state;
mod integers;
mod keys;
#[cfg(feature = "strings")]
mod strings;
mod traits;
mod utils;

pub mod array;
pub mod backward_compatibility;
mod compact_list;
mod tag;

#[cfg(feature = "gpu")]
pub use crate::core_crypto::gpu::vec::GpuIndex;

pub(in crate::high_level_api) mod details;
/// The tfhe prelude.
pub mod prelude;
#[cfg(feature = "zk-pok")]
mod zk;

/// Devices supported by tfhe-rs
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Device {
    Cpu,
    #[cfg(feature = "gpu")]
    CudaGpu,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum FheTypes {
    Bool = 0,
    // Classical unsigned types
    Uint4 = 1,
    Uint8 = 2,
    Uint16 = 3,
    Uint32 = 4,
    Uint64 = 5,
    Uint128 = 6,
    Uint160 = 7,
    Uint256 = 8,
    Uint512 = 9,
    Uint1024 = 10,
    Uint2048 = 11,
    Uint2 = 12,
    Uint6 = 13,
    Uint10 = 14,
    Uint12 = 15,
    Uint14 = 16,

    // Classical signed types
    Int2 = 17,
    Int4 = 18,
    Int6 = 19,
    Int8 = 20,
    Int10 = 21,
    Int12 = 22,
    Int14 = 23,
    Int16 = 24,
    Int32 = 25,
    Int64 = 26,
    Int128 = 27,
    Int160 = 28,
    Int256 = 29,
    Int512 = 30,
    Int1024 = 31,
    Int2048 = 32,

    // Extended unsigned types
    Uint24 = 33,
    Uint40 = 34,
    Uint48 = 35,
    Uint56 = 36,
    Uint72 = 37,
    Uint80 = 38,
    Uint88 = 39,
    Uint96 = 40,
    Uint104 = 41,
    Uint112 = 42,
    Uint120 = 43,
    Uint136 = 44,
    Uint144 = 45,
    Uint152 = 46,
    Uint168 = 47,
    Uint176 = 48,
    Uint184 = 49,
    Uint192 = 50,
    Uint200 = 51,
    Uint208 = 52,
    Uint216 = 53,
    Uint224 = 54,
    Uint232 = 55,
    Uint240 = 56,
    Uint248 = 57,

    // Extended signed types
    Int24 = 58,
    Int40 = 59,
    Int48 = 60,
    Int56 = 61,
    Int72 = 62,
    Int80 = 63,
    Int88 = 64,
    Int96 = 65,
    Int104 = 66,
    Int112 = 67,
    Int120 = 68,
    Int136 = 69,
    Int144 = 70,
    Int152 = 71,
    Int168 = 72,
    Int176 = 73,
    Int184 = 74,
    Int192 = 75,
    Int200 = 76,
    Int208 = 77,
    Int216 = 78,
    Int224 = 79,
    Int232 = 80,
    Int240 = 81,
    Int248 = 82,
}
