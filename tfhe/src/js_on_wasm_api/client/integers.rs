use crate::integer::bigint::{
    StaticSignedBigInt, StaticUnsignedBigInt, I1024, I2048, I512, U1024, U2048, U512,
};
use crate::integer::{I256, U256};
use crate::js_on_wasm_api::{
    catch_panic, catch_panic_result, generic_safe_deserialize, generic_safe_serialize,
    into_js_error,
};
use js_sys::BigInt;
use wasm_bindgen::prelude::*;

use super::TfheCompactPublicKey;
#[cfg(feature = "zk-pok")]
use super::{CompactPkeCrs, ZkComputeLoad};

impl<const N: usize> From<StaticUnsignedBigInt<N>> for JsValue {
    fn from(value: StaticUnsignedBigInt<N>) -> Self {
        if N == 0 {
            return Self::from(0);
        }

        let shift = BigInt::from(64u64);
        let mut js_value = BigInt::from(0);

        for v in value.0.iter().copied().rev() {
            js_value = js_value << &shift;
            js_value = js_value | BigInt::from(v);
        }

        js_value.into()
    }
}

impl<const N: usize> TryFrom<JsValue> for StaticUnsignedBigInt<N> {
    type Error = JsError;

    fn try_from(js_value: JsValue) -> Result<Self, Self::Error> {
        let mut js_bigint = BigInt::new(&js_value).map_err(|err| {
            JsError::new(&format!("Failed to convert the value: {}", err.to_string()))
        })?;
        let mask = BigInt::from(u64::MAX);
        let shift = BigInt::from(u64::BITS);

        let mut data = [0u64; N];
        for word in data.iter_mut() {
            // Since we masked the low value it will fit in u64
            *word = (&js_bigint & &mask).try_into().unwrap();
            js_bigint = js_bigint >> &shift;
        }

        if js_bigint == 0 {
            Ok(Self(data))
        } else {
            Err(JsError::new(&format!(
                "Value is out of range for U{}",
                N * u64::BITS as usize
            )))
        }
    }
}

impl<const N: usize> TryFrom<JsValue> for StaticSignedBigInt<N> {
    type Error = JsError;

    fn try_from(mut js_value: JsValue) -> Result<Self, Self::Error> {
        let was_neg = if js_value.lt(&JsValue::from(0)) {
            js_value = -js_value;
            true
        } else {
            false
        };

        let mut js_bigint = BigInt::new(&js_value).map_err(|err| {
            JsError::new(&format!("Failed to convert the value: {}", err.to_string()))
        })?;
        let mask = BigInt::from(u64::MAX);
        let shift = BigInt::from(u64::BITS);

        let mut data = [0u64; N];
        for word in data.iter_mut() {
            // Since we masked the low value it will fit in u64
            *word = (&js_bigint & &mask).try_into().unwrap();
            js_bigint = js_bigint >> &shift;
        }

        if js_bigint == 0 {
            let rs_value = Self(data);
            Ok(if was_neg { -rs_value } else { rs_value })
        } else {
            Err(JsError::new(&format!(
                "Value is out of range for U{}",
                N * u64::BITS as usize
            )))
        }
    }
}

impl<const N: usize> From<StaticSignedBigInt<N>> for JsValue {
    fn from(mut value: StaticSignedBigInt<N>) -> Self {
        if N == 0 {
            return Self::from(0);
        }

        let was_neg = if value < StaticSignedBigInt::ZERO {
            value = -value;
            true
        } else {
            false
        };

        let shift = BigInt::from(64u64);
        let mut js_value = BigInt::from(0);

        for v in value.0.iter().copied().rev() {
            js_value = js_value << &shift;
            js_value = js_value | BigInt::from(v);
        }

        if was_neg {
            -Self::from(js_value)
        } else {
            Self::from(js_value)
        }
    }
}

#[wasm_bindgen]
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

impl From<crate::FheTypes> for FheTypes {
    fn from(value: crate::FheTypes) -> Self {
        match value {
            crate::FheTypes::Bool => Self::Bool,
            crate::FheTypes::Uint2 => Self::Uint2,
            crate::FheTypes::Uint4 => Self::Uint4,
            crate::FheTypes::Uint6 => Self::Uint6,
            crate::FheTypes::Uint8 => Self::Uint8,
            crate::FheTypes::Uint10 => Self::Uint10,
            crate::FheTypes::Uint12 => Self::Uint12,
            crate::FheTypes::Uint14 => Self::Uint14,
            crate::FheTypes::Uint16 => Self::Uint16,
            crate::FheTypes::Uint24 => Self::Uint24,
            crate::FheTypes::Uint32 => Self::Uint32,
            crate::FheTypes::Uint40 => Self::Uint40,
            crate::FheTypes::Uint48 => Self::Uint48,
            crate::FheTypes::Uint56 => Self::Uint56,
            crate::FheTypes::Uint64 => Self::Uint64,
            crate::FheTypes::Uint72 => Self::Uint72,
            crate::FheTypes::Uint80 => Self::Uint80,
            crate::FheTypes::Uint88 => Self::Uint88,
            crate::FheTypes::Uint96 => Self::Uint96,
            crate::FheTypes::Uint104 => Self::Uint104,
            crate::FheTypes::Uint112 => Self::Uint112,
            crate::FheTypes::Uint120 => Self::Uint120,
            crate::FheTypes::Uint128 => Self::Uint128,
            crate::FheTypes::Uint136 => Self::Uint136,
            crate::FheTypes::Uint144 => Self::Uint144,
            crate::FheTypes::Uint152 => Self::Uint152,
            crate::FheTypes::Uint160 => Self::Uint160,
            crate::FheTypes::Uint168 => Self::Uint168,
            crate::FheTypes::Uint176 => Self::Uint176,
            crate::FheTypes::Uint184 => Self::Uint184,
            crate::FheTypes::Uint192 => Self::Uint192,
            crate::FheTypes::Uint200 => Self::Uint200,
            crate::FheTypes::Uint208 => Self::Uint208,
            crate::FheTypes::Uint216 => Self::Uint216,
            crate::FheTypes::Uint224 => Self::Uint224,
            crate::FheTypes::Uint232 => Self::Uint232,
            crate::FheTypes::Uint240 => Self::Uint240,
            crate::FheTypes::Uint248 => Self::Uint248,
            crate::FheTypes::Uint256 => Self::Uint256,
            crate::FheTypes::Uint512 => Self::Uint512,
            crate::FheTypes::Uint1024 => Self::Uint1024,
            crate::FheTypes::Uint2048 => Self::Uint2048,
            crate::FheTypes::Int2 => Self::Int2,
            crate::FheTypes::Int4 => Self::Int4,
            crate::FheTypes::Int6 => Self::Int6,
            crate::FheTypes::Int8 => Self::Int8,
            crate::FheTypes::Int10 => Self::Int10,
            crate::FheTypes::Int12 => Self::Int12,
            crate::FheTypes::Int14 => Self::Int14,
            crate::FheTypes::Int16 => Self::Int16,
            crate::FheTypes::Int24 => Self::Int24,
            crate::FheTypes::Int32 => Self::Int32,
            crate::FheTypes::Int40 => Self::Int40,
            crate::FheTypes::Int48 => Self::Int48,
            crate::FheTypes::Int56 => Self::Int56,
            crate::FheTypes::Int64 => Self::Int64,
            crate::FheTypes::Int72 => Self::Int72,
            crate::FheTypes::Int80 => Self::Int80,
            crate::FheTypes::Int88 => Self::Int88,
            crate::FheTypes::Int96 => Self::Int96,
            crate::FheTypes::Int104 => Self::Int104,
            crate::FheTypes::Int112 => Self::Int112,
            crate::FheTypes::Int120 => Self::Int120,
            crate::FheTypes::Int128 => Self::Int128,
            crate::FheTypes::Int136 => Self::Int136,
            crate::FheTypes::Int144 => Self::Int144,
            crate::FheTypes::Int152 => Self::Int152,
            crate::FheTypes::Int160 => Self::Int160,
            crate::FheTypes::Int168 => Self::Int168,
            crate::FheTypes::Int176 => Self::Int176,
            crate::FheTypes::Int184 => Self::Int184,
            crate::FheTypes::Int192 => Self::Int192,
            crate::FheTypes::Int200 => Self::Int200,
            crate::FheTypes::Int208 => Self::Int208,
            crate::FheTypes::Int216 => Self::Int216,
            crate::FheTypes::Int224 => Self::Int224,
            crate::FheTypes::Int232 => Self::Int232,
            crate::FheTypes::Int240 => Self::Int240,
            crate::FheTypes::Int248 => Self::Int248,
            crate::FheTypes::Int256 => Self::Int256,
            crate::FheTypes::Int512 => Self::Int512,
            crate::FheTypes::Int1024 => Self::Int1024,
            crate::FheTypes::Int2048 => Self::Int2048,
            crate::FheTypes::AsciiString => Self::AsciiString,
        }
    }
}

#[wasm_bindgen]
pub struct CompactCiphertextListExpander(
    pub(crate) crate::high_level_api::CompactCiphertextListExpander,
);

#[wasm_bindgen]
pub struct CompactCiphertextList(pub(crate) crate::high_level_api::CompactCiphertextList);

#[wasm_bindgen]
impl CompactCiphertextList {
    #[wasm_bindgen]
    pub fn builder(
        public_key: &TfheCompactPublicKey,
    ) -> Result<CompactCiphertextListBuilder, JsError> {
        catch_panic(|| {
            let inner = crate::high_level_api::CompactCiphertextList::builder(&public_key.0);
            CompactCiphertextListBuilder(inner)
        })
    }

    #[wasm_bindgen]
    pub fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(feature = "zk-pok")]
#[wasm_bindgen]
pub struct ProvenCompactCiphertextList(
    pub(crate) crate::high_level_api::ProvenCompactCiphertextList,
);

#[cfg(feature = "zk-pok")]
#[wasm_bindgen]
impl ProvenCompactCiphertextList {
    #[wasm_bindgen]
    pub fn builder(
        public_key: &TfheCompactPublicKey,
    ) -> Result<CompactCiphertextListBuilder, JsError> {
        catch_panic(|| {
            let inner = crate::high_level_api::ProvenCompactCiphertextList::builder(&public_key.0);
            CompactCiphertextListBuilder(inner)
        })
    }

    #[wasm_bindgen]
    pub fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    #[wasm_bindgen]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[wasm_bindgen]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[wasm_bindgen]
    pub fn get_kind_of(&self, index: usize) -> Option<FheTypes> {
        self.0.get_kind_of(index).map(Into::into)
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        generic_safe_serialize(&self.0, serialized_size_limit)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<Self, JsError> {
        generic_safe_deserialize(buffer, serialized_size_limit).map(ProvenCompactCiphertextList)
    }
}

#[wasm_bindgen]
pub struct CompactCiphertextListBuilder(
    pub(crate) crate::high_level_api::CompactCiphertextListBuilder,
);

/// Helper macro to define push methods for the builder
///
/// The js_type must be a type that is "native" between rust and wasm_bindgen
macro_rules! define_builder_push_method {
    (
        unsigned: {
            $($num_bits:literal <= $js_type:ty),*
            $(,)?
        }
    ) => {
        ::paste::paste!{
            #[wasm_bindgen]
            impl CompactCiphertextListBuilder {
                $(
                    #[wasm_bindgen]
                    pub fn [<push_u $num_bits>] (&mut self, value: $js_type) -> Result<(), JsError> {
                        catch_panic(|| {
                            self.0.push_with_num_bits(value, $num_bits).unwrap();
                        })
                    }
                )*
            }
        }
    };
    (
        signed: {
            $($num_bits:literal <= $js_type:ty),*
            $(,)?
        }
    ) => {
        ::paste::paste!{
            #[wasm_bindgen]
            impl CompactCiphertextListBuilder {
                $(
                    #[wasm_bindgen]
                    pub fn [<push_i $num_bits>] (&mut self, value: $js_type) -> Result<(), JsError> {
                        catch_panic(|| {
                            self.0.push_with_num_bits(value, $num_bits).unwrap();
                        })
                    }
                )*
            }
        }
    };
}

define_builder_push_method!(unsigned: {
    2 <= u8,
    4 <= u8,
    6 <= u8,
    8 <= u8,
    10 <= u16,
    12 <= u16,
    14 <= u16,
    16 <= u16,
    32 <= u32,
    64 <= u64,
});

define_builder_push_method!(signed: {
    2 <= i8,
    4 <= i8,
    6 <= i8,
    8 <= i8,
    10 <= i16,
    12 <= i16,
    14 <= i16,
    16 <= i16,
    32 <= i32,
    64 <= i64,
});

#[wasm_bindgen]
impl CompactCiphertextListBuilder {
    #[wasm_bindgen]
    pub fn push_u128(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u160(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 160)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u256(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u512(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U512::try_from(value)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u1024(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U1024::try_from(value)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u2048(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U2048::try_from(value)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i128(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i160(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 160)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i256(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i512(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I512::try_from(value)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i1024(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I1024::try_from(value)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i2048(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I2048::try_from(value)?;
            self.0.push(value);
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_boolean(&mut self, value: bool) -> Result<(), JsError> {
        catch_panic(|| {
            self.0.push(value);
        })
    }

    #[wasm_bindgen]
    pub fn build(&self) -> Result<CompactCiphertextList, JsError> {
        catch_panic(|| {
            let inner = self.0.build();
            CompactCiphertextList(inner)
        })
    }

    #[wasm_bindgen]
    pub fn build_packed(&self) -> Result<CompactCiphertextList, JsError> {
        catch_panic(|| {
            let inner = self.0.build_packed();
            CompactCiphertextList(inner)
        })
    }

    #[wasm_bindgen]
    pub fn build_packed_seeded(&self, seed: &[u8]) -> Result<CompactCiphertextList, JsError> {
        catch_panic_result(|| {
            let inner = self.0.build_packed_seeded(seed).map_err(into_js_error)?;
            Ok(CompactCiphertextList(inner))
        })
    }

    #[cfg(feature = "zk-pok")]
    #[wasm_bindgen]
    pub fn build_with_proof_packed(
        &self,
        crs: &CompactPkeCrs,
        metadata: &[u8],
        compute_load: ZkComputeLoad,
    ) -> Result<ProvenCompactCiphertextList, JsError> {
        catch_panic_result(|| {
            self.0
                .build_with_proof_packed(&crs.0, metadata, compute_load.into())
                .map_err(into_js_error)
                .map(ProvenCompactCiphertextList)
        })
    }

    #[cfg(feature = "zk-pok")]
    pub fn build_with_proof_packed_seeded(
        &self,
        crs: &CompactPkeCrs,
        metadata: &[u8],
        compute_load: ZkComputeLoad,
        seed: &[u8],
    ) -> Result<ProvenCompactCiphertextList, JsError> {
        catch_panic_result(|| {
            self.0
                .build_with_proof_packed_seeded(&crs.0, metadata, compute_load.into(), seed)
                .map_err(into_js_error)
                .map(ProvenCompactCiphertextList)
        })
    }
}
