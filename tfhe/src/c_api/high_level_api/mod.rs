mod array;
#[cfg(feature = "boolean")]
pub mod booleans;
mod compact_list;
pub mod compressed_ciphertext_list;
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
#[cfg(feature = "zk-pok")]
mod zk;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub enum FheTypes {
    Type_FheBool = 0,
    Type_FheUint4 = 1,
    Type_FheUint8 = 2,
    Type_FheUint16 = 3,
    Type_FheUint32 = 4,
    Type_FheUint64 = 5,
    Type_FheUint128 = 6,
    Type_FheUint160 = 7,
    Type_FheUint256 = 8,
    Type_FheUint512 = 9,
    Type_FheUint1024 = 10,
    Type_FheUint2048 = 11,
    Type_FheUint2 = 12,
    Type_FheUint6 = 13,
    Type_FheUint10 = 14,
    Type_FheUint12 = 15,
    Type_FheUint14 = 16,
    Type_FheInt2 = 17,
    Type_FheInt4 = 18,
    Type_FheInt6 = 19,
    Type_FheInt8 = 20,
    Type_FheInt10 = 21,
    Type_FheInt12 = 22,
    Type_FheInt14 = 23,
    Type_FheInt16 = 24,
    Type_FheInt32 = 25,
    Type_FheInt64 = 26,
    Type_FheInt128 = 27,
    Type_FheInt160 = 28,
    Type_FheInt256 = 29,
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
            crate::FheTypes::Uint512 => Self::Type_FheUint512,
            crate::FheTypes::Uint1024 => Self::Type_FheUint1024,
            crate::FheTypes::Uint2048 => Self::Type_FheUint2048,
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

#[test]
fn fhe_types_enum_to_int_compatible() {
    use strum::IntoEnumIterator;

    for rust_value in crate::FheTypes::iter() {
        let c_value = FheTypes::from(rust_value);

        assert_eq!(rust_value as i32, c_value as i32)
    }
}
