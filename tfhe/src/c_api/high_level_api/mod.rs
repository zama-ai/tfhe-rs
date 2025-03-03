mod array;
#[cfg(feature = "boolean")]
pub mod booleans;
mod compact_list;
pub mod compressed_ciphertext_list;
pub mod config;
pub mod i1024;
pub mod i128;
pub mod i2048;
pub mod i256;
pub mod i512;
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

    Type_FheAsciiString = 30,

    Type_FheInt512 = 31,
    Type_FheInt1024 = 32,
    Type_FheInt2048 = 33,

    // Extended types
    Type_FheUint24 = 34,
    Type_FheUint40 = 35,
    Type_FheUint48 = 36,
    Type_FheUint56 = 37,
    Type_FheUint72 = 38,
    Type_FheUint80 = 39,
    Type_FheUint88 = 40,
    Type_FheUint96 = 41,
    Type_FheUint104 = 42,
    Type_FheUint112 = 43,
    Type_FheUint120 = 44,
    Type_FheUint136 = 45,
    Type_FheUint144 = 46,
    Type_FheUint152 = 47,
    Type_FheUint168 = 48,
    Type_FheUint176 = 49,
    Type_FheUint184 = 50,
    Type_FheUint192 = 51,
    Type_FheUint200 = 52,
    Type_FheUint208 = 53,
    Type_FheUint216 = 54,
    Type_FheUint224 = 55,
    Type_FheUint232 = 56,
    Type_FheUint240 = 57,
    Type_FheUint248 = 58,

    Type_FheInt24 = 59,
    Type_FheInt40 = 60,
    Type_FheInt48 = 61,
    Type_FheInt56 = 62,
    Type_FheInt72 = 63,
    Type_FheInt80 = 64,
    Type_FheInt88 = 65,
    Type_FheInt96 = 66,
    Type_FheInt104 = 67,
    Type_FheInt112 = 68,
    Type_FheInt120 = 69,
    Type_FheInt136 = 70,
    Type_FheInt144 = 71,
    Type_FheInt152 = 72,
    Type_FheInt168 = 73,
    Type_FheInt176 = 74,
    Type_FheInt184 = 75,
    Type_FheInt192 = 76,
    Type_FheInt200 = 77,
    Type_FheInt208 = 78,
    Type_FheInt216 = 79,
    Type_FheInt224 = 80,
    Type_FheInt232 = 81,
    Type_FheInt240 = 82,
    Type_FheInt248 = 83,
}

impl From<crate::FheTypes> for FheTypes {
    fn from(value: crate::FheTypes) -> Self {
        match value {
            crate::FheTypes::Bool => Self::Type_FheBool,
            crate::FheTypes::Uint4 => Self::Type_FheUint4,
            crate::FheTypes::Uint8 => Self::Type_FheUint8,
            crate::FheTypes::Uint16 => Self::Type_FheUint16,
            crate::FheTypes::Uint32 => Self::Type_FheUint32,
            crate::FheTypes::Uint64 => Self::Type_FheUint64,
            crate::FheTypes::Uint128 => Self::Type_FheUint128,
            crate::FheTypes::Uint160 => Self::Type_FheUint160,
            crate::FheTypes::Uint256 => Self::Type_FheUint256,
            crate::FheTypes::Uint512 => Self::Type_FheUint512,
            crate::FheTypes::Uint1024 => Self::Type_FheUint1024,
            crate::FheTypes::Uint2048 => Self::Type_FheUint2048,
            crate::FheTypes::Uint2 => Self::Type_FheUint2,
            crate::FheTypes::Uint6 => Self::Type_FheUint6,
            crate::FheTypes::Uint10 => Self::Type_FheUint10,
            crate::FheTypes::Uint12 => Self::Type_FheUint12,
            crate::FheTypes::Uint14 => Self::Type_FheUint14,
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
            crate::FheTypes::AsciiString => Self::Type_FheAsciiString,
            crate::FheTypes::Int512 => Self::Type_FheInt512,
            crate::FheTypes::Int1024 => Self::Type_FheInt1024,
            crate::FheTypes::Int2048 => Self::Type_FheInt2048,
            crate::FheTypes::Uint24 => Self::Type_FheUint24,
            crate::FheTypes::Uint40 => Self::Type_FheUint40,
            crate::FheTypes::Uint48 => Self::Type_FheUint48,
            crate::FheTypes::Uint56 => Self::Type_FheUint56,
            crate::FheTypes::Uint72 => Self::Type_FheUint72,
            crate::FheTypes::Uint80 => Self::Type_FheUint80,
            crate::FheTypes::Uint88 => Self::Type_FheUint88,
            crate::FheTypes::Uint96 => Self::Type_FheUint96,
            crate::FheTypes::Uint104 => Self::Type_FheUint104,
            crate::FheTypes::Uint112 => Self::Type_FheUint112,
            crate::FheTypes::Uint120 => Self::Type_FheUint120,
            crate::FheTypes::Uint136 => Self::Type_FheUint136,
            crate::FheTypes::Uint144 => Self::Type_FheUint144,
            crate::FheTypes::Uint152 => Self::Type_FheUint152,
            crate::FheTypes::Uint168 => Self::Type_FheUint168,
            crate::FheTypes::Uint176 => Self::Type_FheUint176,
            crate::FheTypes::Uint184 => Self::Type_FheUint184,
            crate::FheTypes::Uint192 => Self::Type_FheUint192,
            crate::FheTypes::Uint200 => Self::Type_FheUint200,
            crate::FheTypes::Uint208 => Self::Type_FheUint208,
            crate::FheTypes::Uint216 => Self::Type_FheUint216,
            crate::FheTypes::Uint224 => Self::Type_FheUint224,
            crate::FheTypes::Uint232 => Self::Type_FheUint232,
            crate::FheTypes::Uint240 => Self::Type_FheUint240,
            crate::FheTypes::Uint248 => Self::Type_FheUint248,
            crate::FheTypes::Int24 => Self::Type_FheInt24,
            crate::FheTypes::Int40 => Self::Type_FheInt40,
            crate::FheTypes::Int48 => Self::Type_FheInt48,
            crate::FheTypes::Int56 => Self::Type_FheInt56,
            crate::FheTypes::Int72 => Self::Type_FheInt72,
            crate::FheTypes::Int80 => Self::Type_FheInt80,
            crate::FheTypes::Int88 => Self::Type_FheInt88,
            crate::FheTypes::Int96 => Self::Type_FheInt96,
            crate::FheTypes::Int104 => Self::Type_FheInt104,
            crate::FheTypes::Int112 => Self::Type_FheInt112,
            crate::FheTypes::Int120 => Self::Type_FheInt120,
            crate::FheTypes::Int136 => Self::Type_FheInt136,
            crate::FheTypes::Int144 => Self::Type_FheInt144,
            crate::FheTypes::Int152 => Self::Type_FheInt152,
            crate::FheTypes::Int168 => Self::Type_FheInt168,
            crate::FheTypes::Int176 => Self::Type_FheInt176,
            crate::FheTypes::Int184 => Self::Type_FheInt184,
            crate::FheTypes::Int192 => Self::Type_FheInt192,
            crate::FheTypes::Int200 => Self::Type_FheInt200,
            crate::FheTypes::Int208 => Self::Type_FheInt208,
            crate::FheTypes::Int216 => Self::Type_FheInt216,
            crate::FheTypes::Int224 => Self::Type_FheInt224,
            crate::FheTypes::Int232 => Self::Type_FheInt232,
            crate::FheTypes::Int240 => Self::Type_FheInt240,
            crate::FheTypes::Int248 => Self::Type_FheInt248,
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
