mod array;
#[cfg(feature = "boolean")]
pub mod booleans;
mod compact_list;
pub mod config;
pub mod i128;
pub mod i256;
pub mod integers;
pub mod keys;
mod threading;
pub mod u1024;
pub mod u128;
pub mod u2048;
pub mod u256;
pub mod u512;
mod utils;
#[cfg(feature = "zk-pok-experimental")]
mod zk;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub enum FheTypes {
    Type_FheBool,
    Type_FheUint2,
    Type_FheUint4,
    Type_FheUint6,
    Type_FheUint8,
    Type_FheUint10,
    Type_FheUint12,
    Type_FheUint14,
    Type_FheUint16,
    Type_FheUint32,
    Type_FheUint64,
    Type_FheUint128,
    Type_FheUint160,
    Type_FheUint256,
    Type_FheInt2,
    Type_FheInt4,
    Type_FheInt6,
    Type_FheInt8,
    Type_FheInt10,
    Type_FheInt12,
    Type_FheInt14,
    Type_FheInt16,
    Type_FheInt32,
    Type_FheInt64,
    Type_FheInt128,
    Type_FheInt160,
    Type_FheInt256,
}

impl From<crate::FheTypes> for FheTypes {
    fn from(value: crate::FheTypes) -> Self {
        match value {
            crate::FheTypes::Bool => Self::Type_FheBool,
            crate::FheTypes::Uint2 => Self::Type_FheUint2,
            crate::FheTypes::Uint4 => Self::Type_FheUint4,
            crate::FheTypes::Uint6 => Self::Type_FheUint6,
            crate::FheTypes::Uint8 => Self::Type_FheUint8,
            crate::FheTypes::Uint10 => Self::Type_FheUint10,
            crate::FheTypes::Uint12 => Self::Type_FheUint12,
            crate::FheTypes::Uint14 => Self::Type_FheUint14,
            crate::FheTypes::Uint16 => Self::Type_FheUint16,
            crate::FheTypes::Uint32 => Self::Type_FheUint32,
            crate::FheTypes::Uint64 => Self::Type_FheUint64,
            crate::FheTypes::Uint128 => Self::Type_FheUint128,
            crate::FheTypes::Uint160 => Self::Type_FheUint160,
            crate::FheTypes::Uint256 => Self::Type_FheUint256,
            crate::FheTypes::Int2 => Self::Type_FheInt2,
            crate::FheTypes::Int4 => Self::Type_FheInt4,
            crate::FheTypes::Int6 => Self::Type_FheInt6,
            crate::FheTypes::Int8 => Self::Type_FheInt8,
            crate::FheTypes::Int10 => Self::Type_FheInt10,
            crate::FheTypes::Int12 => Self::Type_FheInt12,
            crate::FheTypes::Int14 => Self::Type_FheInt14,
            crate::FheTypes::Int16 => Self::Type_FheInt16,
            crate::FheTypes::Int32 => Self::Type_FheInt32,
            crate::FheTypes::Int64 => Self::Type_FheInt64,
            crate::FheTypes::Int128 => Self::Type_FheInt128,
            crate::FheTypes::Int160 => Self::Type_FheInt160,
            crate::FheTypes::Int256 => Self::Type_FheInt256,
        }
    }
}
