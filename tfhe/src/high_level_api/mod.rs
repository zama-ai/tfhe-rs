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
use serde::{Deserialize, Serialize};

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
expand_pub_use_fhe_type!(
    pub use crate::high_level_api::integers{
        FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16,
        FheUint32, FheUint64, FheUint128, FheUint160, FheUint256, FheUint512, FheUint1024, FheUint2048,

        FheInt2, FheInt4, FheInt6, FheInt8, FheInt10, FheInt12, FheInt14, FheInt16,
        FheInt32, FheInt64, FheInt128, FheInt160, FheInt256
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
        FheUint2, FheUint4, FheUint8, FheUint16, FheUint32, FheUint64, FheUint128, FheUint256,
        FheInt2, FheInt4, FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256,
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

use crate::integer::ciphertext::DataKind;
use crate::shortint::MessageModulus;
use crate::Versionize;
pub use tag::Tag;
use tfhe_versionable::VersionsDispatch;
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
}

impl TryFrom<SerializedKind> for FheTypes {
    type Error = crate::Error;

    fn try_from(kind: SerializedKind) -> crate::Result<Self> {
        match kind {
            SerializedKind::Bool => Ok(Self::Bool),
            SerializedKind::Uint { num_bits } => match num_bits {
                2 => Ok(Self::Uint2),
                4 => Ok(Self::Uint4),
                6 => Ok(Self::Uint6),
                8 => Ok(Self::Uint8),
                10 => Ok(Self::Uint10),
                12 => Ok(Self::Uint12),
                14 => Ok(Self::Uint14),
                16 => Ok(Self::Uint16),
                32 => Ok(Self::Uint32),
                64 => Ok(Self::Uint64),
                128 => Ok(Self::Uint128),
                256 => Ok(Self::Uint256),
                512 => Ok(Self::Uint512),
                1024 => Ok(Self::Uint1024),
                2048 => Ok(Self::Uint2048),
                n => Err(crate::Error::new(format!(
                    "No unsigned type with {n} bits exits"
                ))),
            },
            SerializedKind::Int { num_bits } => match num_bits {
                2 => Ok(Self::Int2),
                4 => Ok(Self::Int4),
                6 => Ok(Self::Int6),
                8 => Ok(Self::Int8),
                10 => Ok(Self::Int10),
                12 => Ok(Self::Int12),
                14 => Ok(Self::Int14),
                16 => Ok(Self::Int16),
                32 => Ok(Self::Int32),
                64 => Ok(Self::Int64),
                128 => Ok(Self::Int128),
                256 => Ok(Self::Int256),
                n => Err(crate::Error::new(format!(
                    "No signed type with {n} bits exits"
                ))),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Versionize)]
#[versionize(SerializedKindVersions)]
pub enum SerializedKind {
    Bool,
    Uint { num_bits: u32 },
    Int { num_bits: u32 },
}

impl SerializedKind {
    fn from_data_kind(value: DataKind, msg_modulus: MessageModulus) -> Self {
        match value {
            DataKind::Unsigned(n) => Self::Uint {
                num_bits: n as u32 * msg_modulus.0.ilog2(),
            },
            DataKind::Signed(n) => Self::Int {
                num_bits: n as u32 * msg_modulus.0.ilog2(),
            },
            DataKind::Boolean => Self::Bool,
        }
    }

    pub(crate) fn num_blocks(self, message_modulus: MessageModulus) -> u32 {
        match self {
            Self::Bool => 1,
            Self::Uint { num_bits } => num_bits / message_modulus.0.ilog2(),
            Self::Int { num_bits } => num_bits / message_modulus.0.ilog2(),
        }
    }
}

#[derive(VersionsDispatch)]
pub enum SerializedKindVersions {
    V0(SerializedKind),
}
