use strum::FromRepr;

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

#[derive(FromRepr, Copy, Clone, PartialEq, Eq, Debug)]
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

#[allow(clippy::fallible_impl_from)] // This is not actually fallible
impl From<crate::FheTypes> for FheTypes {
    fn from(value: crate::FheTypes) -> Self {
        // First unwrap cannot fail because the values are all positive
        // Second unwrap cannot fail as long as the enums are in sync, and this is checked by the
        // test below
        Self::from_repr((value as i32).try_into().unwrap()).unwrap()
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
