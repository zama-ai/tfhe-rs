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
                    [<Compressed $fhe_type_name ConformanceParams>],
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

pub use crate::core_crypto::commons::math::random::{Seed, Seeder, XofSeed};
pub use crate::high_level_api::integers::oprf::RangeForRandom;
pub use crate::high_level_api::integers::shuffle::{
    bitonic_shuffle, re_randomized_keys_bitonic_shuffle, BitonicShuffleKeySize,
};
pub use crate::integer::server_key::MatchValues;
pub use crate::shortint::OprfSeed;
use crate::{error, Error, Versionize};
use backward_compatibility::compressed_ciphertext_list::SquashedNoiseCiphertextStateVersions;
pub use config::{Config, ConfigBuilder};
#[cfg(feature = "gpu")]
pub use global_state::clear_gpu_thread_locals;
#[cfg(feature = "gpu")]
pub use global_state::CudaGpuChoice;
#[cfg(feature = "gpu")]
pub use global_state::CustomMultiGpuIndexes;
pub use global_state::{set_server_key, unset_server_key, with_server_key_as_context};

pub use integers::{
    CompressedFheInt, CompressedFheUint, FheInt, FheIntId, FheIntegerType, FheUint, FheUintId,
    IntegerId, SquashedNoiseFheInt, SquashedNoiseFheUint,
};
#[cfg(feature = "gpu")]
pub use keys::CudaServerKey;
pub use keys::{
    generate_keys, ClientKey, CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey,
    CompressedReRandomizationKey, CompressedReRandomizationKeySwitchingKey, CompressedServerKey,
    KeySwitchingKey, PublicKey, ReRandomizationKey, ReRandomizationKeySwitchingKey, ServerKey,
};
use strum::FromRepr;

#[cfg(test)]
mod tests;

pub use crate::high_level_api::booleans::{
    CompressedFheBool, CompressedFheBoolConformanceParams, FheBool, FheBoolConformanceParams,
    SquashedNoiseFheBool,
};

#[cfg(feature = "extended-types")]
expand_pub_use_fhe_type!(
    pub use crate::high_level_api::integers{
        FheUint24, FheUint40, FheUint48, FheUint56, FheUint72, FheUint80,FheUint88, FheUint96,
        FheUint104, FheUint112, FheUint120, FheUint136, FheUint144, FheUint152, FheUint168,
        FheUint176, FheUint184, FheUint192, FheUint200, FheUint208, FheUint216, FheUint224,
        FheUint232, FheUint240, FheUint248,

        FheInt24, FheInt40, FheInt48, FheInt56, FheInt72, FheInt80,FheInt88, FheInt96, FheInt104,
        FheInt112, FheInt120, FheInt136, FheInt144, FheInt152, FheInt168, FheInt176, FheInt184,
        FheInt192, FheInt200, FheInt208, FheInt216, FheInt224, FheInt232, FheInt240, FheInt248,
    };
);

expand_pub_use_fhe_type!(
    pub use crate::high_level_api::integers{
        FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16,
        FheUint32, FheUint64, FheUint128, FheUint160, FheUint256, FheUint512, FheUint1024,
        FheUint2048,

        FheInt2, FheInt4, FheInt6, FheInt8, FheInt10, FheInt12, FheInt14, FheInt16, FheInt32,
        FheInt64, FheInt128, FheInt160, FheInt256, FheInt512, FheInt1024, FheInt2048,
    };
);
pub use array::{
    fhe_array_contains, ClearArray, CpuFheIntArray, CpuFheIntSlice, CpuFheIntSliceMut,
    CpuFheUintArray, CpuFheUintSlice, CpuFheUintSliceMut, FheBoolId, FheIntArray, FheIntSlice,
    FheIntSliceMut, FheUintArray, FheUintSlice, FheUintSliceMut,
};
export_concrete_array_types!(
    pub use array{
        FheBool,
        FheUint2, FheUint4, FheUint8, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
        FheInt2, FheInt4, FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256,
    };
);

pub use crate::integer::parameters::CompactCiphertextListConformanceParams;
pub use crate::integer::transciphering::IntegerStreamCiphertextConformanceParams;
pub use crate::safe_serialization::{DeserializationConfig, SerializationConfig};
#[cfg(feature = "strings")]
pub use crate::strings::ciphertext::ClearString;

#[cfg(feature = "zk-pok")]
pub use compact_list::ProvenCompactCiphertextList;
pub use compact_list::{
    CompactCiphertextList, CompactCiphertextListBuilder, CompactCiphertextListExpander,
    HlCompactable,
};
pub use compressed_ciphertext_list::{
    CompressedCiphertextList, CompressedCiphertextListBuilder, HlCompressible, HlExpandable,
};
pub use compressed_noise_squashed_ciphertext_list::{
    CompressedSquashedNoiseCiphertextList, CompressedSquashedNoiseCiphertextListBuilder,
    HlSquashedNoiseCompressible, HlSquashedNoiseExpandable,
};
pub use re_randomization::{
    PrfReRandomizationContext, ReRandomizationContext, ReRandomizationHashAlgo,
    ReRandomizationMetadata, ReRandomizationMode, ReRandomizationSeedGen, ReRandomizationSupport,
};
#[cfg(feature = "strings")]
pub use strings::ascii::{EncryptableString, FheAsciiString, FheStringIsEmpty, FheStringLen};
pub use tag::Tag;
pub use traits::FheId;
pub use transciphering::{
    AesFheKey, HlStreamCipher, HlStreamDecryptable, HlStreamEncryptable, HlTranscipherer,
    KreyviumFheKey, OneTimePadFheSecretMask, StreamCiphertext, TranscipherSession,
};
pub mod xof_key_set;

pub use kv_store::{CompressedKVStore, KVStore};

mod booleans;
mod compressed_ciphertext_list;
mod config;
mod errors;
mod global_state;
mod integers;
pub(crate) mod keys;
pub mod nist_submission;
mod re_randomization;
#[cfg(feature = "strings")]
mod strings;
mod traits;
mod transciphering;
mod utils;

#[cfg(feature = "gpu")]
mod gpu_utils;

pub mod array;
pub mod backward_compatibility;
pub(crate) mod compact_list;
mod kv_store;
mod tag;

#[cfg(feature = "gpu")]
pub use crate::core_crypto::gpu::vec::GpuIndex;

mod compressed_noise_squashed_ciphertext_list;
pub(in crate::high_level_api) mod details;
/// The tfhe prelude.
pub mod prelude;
pub mod upgrade;
#[cfg(feature = "zk-pok")]
mod zk;

/// Devices supported by tfhe-rs
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Device {
    Cpu,
    #[cfg(feature = "gpu")]
    CudaGpu,
    #[cfg(feature = "hpu")]
    Hpu,
}

#[derive(FromRepr, Copy, Clone, PartialEq, Eq, Debug)]
#[repr(i32)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum FheTypes {
    Bool = 0,

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
    AsciiString = 30,

    Int512 = 31,
    Int1024 = 32,
    Int2048 = 33,

    Uint24 = 34,
    Uint40 = 35,
    Uint48 = 36,
    Uint56 = 37,
    Uint72 = 38,
    Uint80 = 39,
    Uint88 = 40,
    Uint96 = 41,
    Uint104 = 42,
    Uint112 = 43,
    Uint120 = 44,
    Uint136 = 45,
    Uint144 = 46,
    Uint152 = 47,
    Uint168 = 48,
    Uint176 = 49,
    Uint184 = 50,
    Uint192 = 51,
    Uint200 = 52,
    Uint208 = 53,
    Uint216 = 54,
    Uint224 = 55,
    Uint232 = 56,
    Uint240 = 57,
    Uint248 = 58,

    Int24 = 59,
    Int40 = 60,
    Int48 = 61,
    Int56 = 62,
    Int72 = 63,
    Int80 = 64,
    Int88 = 65,
    Int96 = 66,
    Int104 = 67,
    Int112 = 68,
    Int120 = 69,
    Int136 = 70,
    Int144 = 71,
    Int152 = 72,
    Int168 = 73,
    Int176 = 74,
    Int184 = 75,
    Int192 = 76,
    Int200 = 77,
    Int208 = 78,
    Int216 = 79,
    Int224 = 80,
    Int232 = 81,
    Int240 = 82,
    Int248 = 83,
}

/// Intrinsic shape of a [`FheTypes`]: how many bits it holds and how they are interpreted.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FheTypeShape {
    Bool,
    Unsigned(u32),
    Signed(u32),
    /// The type has no fixed bit width, like [`FheTypes::AsciiString`].
    Variable,
}

impl From<FheTypes> for FheTypeShape {
    fn from(value: FheTypes) -> Self {
        match value {
            FheTypes::Bool => Self::Bool,
            FheTypes::Uint4 => Self::Unsigned(4),
            FheTypes::Uint8 => Self::Unsigned(8),
            FheTypes::Uint16 => Self::Unsigned(16),
            FheTypes::Uint32 => Self::Unsigned(32),
            FheTypes::Uint64 => Self::Unsigned(64),
            FheTypes::Uint128 => Self::Unsigned(128),
            FheTypes::Uint160 => Self::Unsigned(160),
            FheTypes::Uint256 => Self::Unsigned(256),
            FheTypes::Uint512 => Self::Unsigned(512),
            FheTypes::Uint1024 => Self::Unsigned(1024),
            FheTypes::Uint2048 => Self::Unsigned(2048),
            FheTypes::Uint2 => Self::Unsigned(2),
            FheTypes::Uint6 => Self::Unsigned(6),
            FheTypes::Uint10 => Self::Unsigned(10),
            FheTypes::Uint12 => Self::Unsigned(12),
            FheTypes::Uint14 => Self::Unsigned(14),
            FheTypes::Int2 => Self::Signed(2),
            FheTypes::Int4 => Self::Signed(4),
            FheTypes::Int6 => Self::Signed(6),
            FheTypes::Int8 => Self::Signed(8),
            FheTypes::Int10 => Self::Signed(10),
            FheTypes::Int12 => Self::Signed(12),
            FheTypes::Int14 => Self::Signed(14),
            FheTypes::Int16 => Self::Signed(16),
            FheTypes::Int32 => Self::Signed(32),
            FheTypes::Int64 => Self::Signed(64),
            FheTypes::Int128 => Self::Signed(128),
            FheTypes::Int160 => Self::Signed(160),
            FheTypes::Int256 => Self::Signed(256),
            FheTypes::AsciiString => Self::Variable,
            FheTypes::Int512 => Self::Signed(512),
            FheTypes::Int1024 => Self::Signed(1024),
            FheTypes::Int2048 => Self::Signed(2048),
            FheTypes::Uint24 => Self::Unsigned(24),
            FheTypes::Uint40 => Self::Unsigned(40),
            FheTypes::Uint48 => Self::Unsigned(48),
            FheTypes::Uint56 => Self::Unsigned(56),
            FheTypes::Uint72 => Self::Unsigned(72),
            FheTypes::Uint80 => Self::Unsigned(80),
            FheTypes::Uint88 => Self::Unsigned(88),
            FheTypes::Uint96 => Self::Unsigned(96),
            FheTypes::Uint104 => Self::Unsigned(104),
            FheTypes::Uint112 => Self::Unsigned(112),
            FheTypes::Uint120 => Self::Unsigned(120),
            FheTypes::Uint136 => Self::Unsigned(136),
            FheTypes::Uint144 => Self::Unsigned(144),
            FheTypes::Uint152 => Self::Unsigned(152),
            FheTypes::Uint168 => Self::Unsigned(168),
            FheTypes::Uint176 => Self::Unsigned(176),
            FheTypes::Uint184 => Self::Unsigned(184),
            FheTypes::Uint192 => Self::Unsigned(192),
            FheTypes::Uint200 => Self::Unsigned(200),
            FheTypes::Uint208 => Self::Unsigned(208),
            FheTypes::Uint216 => Self::Unsigned(216),
            FheTypes::Uint224 => Self::Unsigned(224),
            FheTypes::Uint232 => Self::Unsigned(232),
            FheTypes::Uint240 => Self::Unsigned(240),
            FheTypes::Uint248 => Self::Unsigned(248),
            FheTypes::Int24 => Self::Signed(24),
            FheTypes::Int40 => Self::Signed(40),
            FheTypes::Int48 => Self::Signed(48),
            FheTypes::Int56 => Self::Signed(56),
            FheTypes::Int72 => Self::Signed(72),
            FheTypes::Int80 => Self::Signed(80),
            FheTypes::Int88 => Self::Signed(88),
            FheTypes::Int96 => Self::Signed(96),
            FheTypes::Int104 => Self::Signed(104),
            FheTypes::Int112 => Self::Signed(112),
            FheTypes::Int120 => Self::Signed(120),
            FheTypes::Int136 => Self::Signed(136),
            FheTypes::Int144 => Self::Signed(144),
            FheTypes::Int152 => Self::Signed(152),
            FheTypes::Int168 => Self::Signed(168),
            FheTypes::Int176 => Self::Signed(176),
            FheTypes::Int184 => Self::Signed(184),
            FheTypes::Int192 => Self::Signed(192),
            FheTypes::Int200 => Self::Signed(200),
            FheTypes::Int208 => Self::Signed(208),
            FheTypes::Int216 => Self::Signed(216),
            FheTypes::Int224 => Self::Signed(224),
            FheTypes::Int232 => Self::Signed(232),
            FheTypes::Int240 => Self::Signed(240),
            FheTypes::Int248 => Self::Signed(248),
        }
    }
}

impl TryFrom<i32> for FheTypes {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::from_repr(value).ok_or_else(|| error!("Invalid value for FheTypes: {}", value))
    }
}

#[derive(serde::Serialize, serde::Deserialize, Copy, Clone, Versionize)]
#[versionize(SquashedNoiseCiphertextStateVersions)]
pub(crate) enum SquashedNoiseCiphertextState {
    Normal,
    PostDecompression,
}
