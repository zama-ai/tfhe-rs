#![allow(clippy::use_self)]
use crate::high_level_api::prelude::*;
use crate::integer::bigint::{
    StaticSignedBigInt, StaticUnsignedBigInt, I1024, I2048, I512, U1024, U2048, U512,
};
use crate::integer::{I256, U256};
use crate::js_on_wasm_api::js_high_level_api::keys::TfheCompactPublicKey;
#[cfg(feature = "zk-pok")]
use crate::js_on_wasm_api::js_high_level_api::zk::{CompactPkeCrs, ZkComputeLoad};
use crate::js_on_wasm_api::js_high_level_api::{catch_panic, catch_panic_result, into_js_error};
use js_sys::BigInt;
use wasm_bindgen::prelude::*;

const U128_MAX_AS_STR: &str = "340282366920938463463374607431768211455";

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

// We use this macro to define wasm wrapper for
// FheUint types which maps to a type that is not native
// to wasm-bindgen such as u128 (rust native) and our U256
// and requires conversions using TryFrom
macro_rules! create_wrapper_type_non_native_type (
    (
        {
            type_name: $type_name:ident,
            compressed_type_name: $compressed_type_name:ident,
            proven_type: $proven_type:ident,
            rust_type: $rust_type:ty $(,)?
        }
    ) => {
        #[wasm_bindgen]
        pub struct $type_name(pub(crate) crate::high_level_api::$type_name);

        #[wasm_bindgen]
        impl $type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_client_key(
                value: JsValue,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$type_name::try_encrypt(value, &client_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn encrypt_with_public_key(
                value: JsValue,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfhePublicKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$type_name::try_encrypt(value, &public_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn encrypt_with_compressed_public_key(
                value: JsValue,
                compressed_public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompressedPublicKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$type_name::try_encrypt(value, &compressed_public_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn decrypt(
                &self,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<JsValue, JsError> {
                catch_panic_result(|| {
                    let value: $rust_type = self.0.decrypt(&client_key.0);

                    JsValue::try_from(value)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                    .serialize_into(&self.0, &mut buffer)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                        .disable_conformance()
                        .deserialize_from(buffer)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }
        }

        #[wasm_bindgen]
        pub struct $compressed_type_name(pub(crate) crate::high_level_api::$compressed_type_name);

        #[wasm_bindgen]
        impl $compressed_type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_client_key(
                value: JsValue,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    let value = <$rust_type>::try_from(value)
                        .map_err(|_| JsError::new(&format!("Failed to convert the value to a {}", stringify!($rust_type))))?;
                    crate::high_level_api::$compressed_type_name::try_encrypt(value, &client_key.0)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn decompress(
                &self,
            ) -> Result<$type_name, JsError> {
                catch_panic(||{
                    $type_name(self.0.decompress())
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                    .serialize_into(&self.0, &mut buffer)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                        .disable_conformance()
                        .deserialize_from(buffer)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }
        }
    };

    (
        $(
            {
                type_name: $type_name:ident,
                compressed_type_name: $compressed_type_name:ident,
                proven_type: $proven_type:ident,
                rust_type: $rust_type:ty $(,)?
            }
        ),*
        $(,)?
    ) => {
        $(
            create_wrapper_type_non_native_type!(
                {
                    type_name: $type_name,
                    compressed_type_name: $compressed_type_name,
                    proven_type: $proven_type,
                    rust_type: $rust_type
                }
            );
        )*
    }
);

create_wrapper_type_non_native_type!(
    {
        type_name: FheUint128,
        compressed_type_name: CompressedFheUint128,
        proven_type: ProvenFheUint128,
        rust_type: u128,
    },
    {
        type_name: FheUint160,
        compressed_type_name: CompressedFheUint160,
        proven_type: ProvenFheUint160,
        rust_type: U256,
    },
    {
        type_name: FheUint256,
        compressed_type_name: CompressedFheUint256,
        proven_type: ProvenFheUint256,
        rust_type: U256,
    },
    {
        type_name: FheUint512,
        compressed_type_name: CompressedFheUint512,
        proven_type: ProvenFheUint512,
        rust_type: U512,
    },
    {
        type_name: FheUint1024,
        compressed_type_name: CompressedFheUint1024,
        proven_type: ProvenFheUint1024,
        rust_type: U1024,
    },
    {
        type_name: FheUint2048,
        compressed_type_name: CompressedFheUint2048,
        proven_type: ProvenFheUint2048,
        rust_type: U2048,
    },
    {
        type_name: FheInt128,
        compressed_type_name: CompressedFheInt128,
        proven_type: ProvenFheInt128,
        rust_type: i128,
    },
    {
        type_name: FheInt160,
        compressed_type_name: CompressedFheInt160,
        proven_type: ProvenFheInt160,
        rust_type: I256,
    },
    {
        type_name: FheInt256,
        compressed_type_name: CompressedFheInt256,
        proven_type: ProvenFheInt256,
        rust_type: I256,
    },
    {
        type_name: FheInt512,
        compressed_type_name: CompressedFheInt512,
        proven_type: ProvenFheInt512,
        rust_type: I512,
    },
    {
        type_name: FheInt1024,
        compressed_type_name: CompressedFheInt1024,
        proven_type: ProvenFheInt1024,
        rust_type: I1024,
    },
    {
        type_name: FheInt2048,
        compressed_type_name: CompressedFheInt2048,
        proven_type: ProvenFheInt2048,
        rust_type: I2048,
    },
);

#[cfg(feature = "extended-types")]
create_wrapper_type_non_native_type!(
    {
        type_name: FheUint72,
        compressed_type_name: CompressedFheUint72,
        proven_type: ProvenFheUint72,
        rust_type: u128,
    },
    {
        type_name: FheUint80,
        compressed_type_name: CompressedFheUint80,
        proven_type: ProvenFheUint80,
        rust_type: u128,
    },
    {
        type_name: FheUint88,
        compressed_type_name: CompressedFheUint88,
        proven_type: ProvenFheUint88,
        rust_type: u128,
    },
    {
        type_name: FheUint96,
        compressed_type_name: CompressedFheUint96,
        proven_type: ProvenFheUint96,
        rust_type: u128,
    },
    {
        type_name: FheUint104,
        compressed_type_name: CompressedFheUint104,
        proven_type: ProvenFheUint104,
        rust_type: u128,
    },
    {
        type_name: FheUint112,
        compressed_type_name: CompressedFheUint112,
        proven_type: ProvenFheUint112,
        rust_type: u128,
    },
    {
        type_name: FheUint120,
        compressed_type_name: CompressedFheUint120,
        proven_type: ProvenFheUint120,
        rust_type: u128,
    },
    {
        type_name: FheUint136,
        compressed_type_name: CompressedFheUint136,
        proven_type: ProvenFheUint136,
        rust_type: U256,
    },
    {
        type_name: FheUint144,
        compressed_type_name: CompressedFheUint144,
        proven_type: ProvenFheUint144,
        rust_type: U256,
    },
    {
        type_name: FheUint152,
        compressed_type_name: CompressedFheUint152,
        proven_type: ProvenFheUint152,
        rust_type: U256,
    },
    {
        type_name: FheUint168,
        compressed_type_name: CompressedFheUint168,
        proven_type: ProvenFheUint168,
        rust_type: U256,
    },
    {
        type_name: FheUint176,
        compressed_type_name: CompressedFheUint176,
        proven_type: ProvenFheUint176,
        rust_type: U256,
    },
    {
        type_name: FheUint184,
        compressed_type_name: CompressedFheUint184,
        proven_type: ProvenFheUint184,
        rust_type: U256,
    },
    {
        type_name: FheUint192,
        compressed_type_name: CompressedFheUint192,
        proven_type: ProvenFheUint192,
        rust_type: U256,
    },
    {
        type_name: FheUint200,
        compressed_type_name: CompressedFheUint200,
        proven_type: ProvenFheUint200,
        rust_type: U256,
    },
    {
        type_name: FheUint208,
        compressed_type_name: CompressedFheUint208,
        proven_type: ProvenFheUint208,
        rust_type: U256,
    },
    {
        type_name: FheUint216,
        compressed_type_name: CompressedFheUint216,
        proven_type: ProvenFheUint216,
        rust_type: U256,
    },
    {
        type_name: FheUint224,
        compressed_type_name: CompressedFheUint224,
        proven_type: ProvenFheUint224,
        rust_type: U256,
    },
    {
        type_name: FheUint232,
        compressed_type_name: CompressedFheUint232,
        proven_type: ProvenFheUint232,
        rust_type: U256,
    },
    {
        type_name: FheUint240,
        compressed_type_name: CompressedFheUint240,
        proven_type: ProvenFheUint240,
        rust_type: U256,
    },
    {
        type_name: FheUint248,
        compressed_type_name: CompressedFheUint248,
        proven_type: ProvenFheUint248,
        rust_type: U256,
    },
    // Signed
    {
        type_name: FheInt72,
        compressed_type_name: CompressedFheInt72,
        proven_type: ProvenFheInt72,
        rust_type: i128,
    },
    {
        type_name: FheInt80,
        compressed_type_name: CompressedFheInt80,
        proven_type: ProvenFheInt80,
        rust_type: i128,
    },
    {
        type_name: FheInt88,
        compressed_type_name: CompressedFheInt88,
        proven_type: ProvenFheInt88,
        rust_type: i128,
    },
    {
        type_name: FheInt96,
        compressed_type_name: CompressedFheInt96,
        proven_type: ProvenFheInt96,
        rust_type: i128,
    },
    {
        type_name: FheInt104,
        compressed_type_name: CompressedFheInt104,
        proven_type: ProvenFheInt104,
        rust_type: i128,
    },
    {
        type_name: FheInt112,
        compressed_type_name: CompressedFheInt112,
        proven_type: ProvenFheInt112,
        rust_type: i128,
    },
    {
        type_name: FheInt120,
        compressed_type_name: CompressedFheInt120,
        proven_type: ProvenFheInt120,
        rust_type: i128,
    },
    {
        type_name: FheInt136,
        compressed_type_name: CompressedFheInt136,
        proven_type: ProvenFheInt136,
        rust_type: I256,
    },
    {
        type_name: FheInt144,
        compressed_type_name: CompressedFheInt144,
        proven_type: ProvenFheInt144,
        rust_type: I256,
    },
    {
        type_name: FheInt152,
        compressed_type_name: CompressedFheInt152,
        proven_type: ProvenFheInt152,
        rust_type: I256,
    },
    {
        type_name: FheInt168,
        compressed_type_name: CompressedFheInt168,
        proven_type: ProvenFheInt168,
        rust_type: I256,
    },
    {
        type_name: FheInt176,
        compressed_type_name: CompressedFheInt176,
        proven_type: ProvenFheInt176,
        rust_type: I256,
    },
    {
        type_name: FheInt184,
        compressed_type_name: CompressedFheInt184,
        proven_type: ProvenFheInt184,
        rust_type: I256,
    },
    {
        type_name: FheInt192,
        compressed_type_name: CompressedFheInt192,
        proven_type: ProvenFheInt192,
        rust_type: I256,
    },
    {
        type_name: FheInt200,
        compressed_type_name: CompressedFheInt200,
        proven_type: ProvenFheInt200,
        rust_type: I256,
    },
    {
        type_name: FheInt208,
        compressed_type_name: CompressedFheInt208,
        proven_type: ProvenFheInt208,
        rust_type: I256,
    },
    {
        type_name: FheInt216,
        compressed_type_name: CompressedFheInt216,
        proven_type: ProvenFheInt216,
        rust_type: I256,
    },
    {
        type_name: FheInt224,
        compressed_type_name: CompressedFheInt224,
        proven_type: ProvenFheInt224,
        rust_type: I256,
    },
    {
        type_name: FheInt232,
        compressed_type_name: CompressedFheInt232,
        proven_type: ProvenFheInt232,
        rust_type: I256,
    },
    {
        type_name: FheInt240,
        compressed_type_name: CompressedFheInt240,
        proven_type: ProvenFheInt240,
        rust_type: I256,
    },
    {
        type_name: FheInt248,
        compressed_type_name: CompressedFheInt248,
        proven_type: ProvenFheInt248,
        rust_type: I256,
    },
);

// We use this macro to define wasm wrapper for
// FheUint types which maps to an unsigned integer type
// that is natively compatible to wasm (u8, u16, etc)
macro_rules! create_wrapper_type_that_has_native_type (
    (
        {
            type_name: $type_name:ident,
            compressed_type_name: $compressed_type_name:ident,
            proven_type: $proven_type:ident,
            native_type: $native_type:ty $(,)?
        }
    ) => {
        #[wasm_bindgen]
        pub struct $type_name(pub(crate) crate::high_level_api::$type_name);

        #[wasm_bindgen]
        impl $type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_client_key(
                value: $native_type,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$type_name::try_encrypt(value, &client_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn encrypt_with_public_key(
                value: $native_type,
                public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfhePublicKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$type_name::try_encrypt(value, &public_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn encrypt_with_compressed_public_key(
                value: $native_type,
                compressed_public_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheCompressedPublicKey,
            ) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$type_name::try_encrypt(value, &compressed_public_key.0)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn decrypt(
                &self,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<$native_type, JsError> {
                catch_panic(|| self.0.decrypt(&client_key.0))
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                    .serialize_into(&self.0, &mut buffer)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                        .disable_conformance()
                        .deserialize_from(buffer)
                        .map(Self)
                        .map_err(into_js_error)
                })
            }
        }
        #[wasm_bindgen]
        pub struct $compressed_type_name(pub(crate) crate::high_level_api::$compressed_type_name);

        #[wasm_bindgen]
        impl $compressed_type_name {
            #[wasm_bindgen]
            pub fn encrypt_with_client_key(
                value: $native_type,
                client_key: &crate::js_on_wasm_api::js_high_level_api::keys::TfheClientKey,
            ) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    crate::high_level_api::$compressed_type_name::try_encrypt(value, &client_key.0)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn decompress(
                &self,
            ) -> Result<$type_name, JsError> {
                catch_panic(||{
                    $type_name(self.0.decompress())
                })
            }

            #[wasm_bindgen]
            pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
                catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
            }

            #[wasm_bindgen]
            pub fn deserialize(buffer: &[u8]) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    bincode::deserialize(buffer)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }

            #[wasm_bindgen]
            pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
                let mut buffer = vec![];
                catch_panic_result(|| crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                    .serialize_into(&self.0, &mut buffer)
                    .map_err(into_js_error))?;

                Ok(buffer)
            }

            #[wasm_bindgen]
            pub fn safe_deserialize(buffer: &[u8], serialized_size_limit: u64) -> Result<$compressed_type_name, JsError> {
                catch_panic_result(|| {
                    crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                        .disable_conformance()
                        .deserialize_from(buffer)
                        .map($compressed_type_name)
                        .map_err(into_js_error)
                })
            }
        }
    };
    (
        $(
            {
                type_name: $type_name:ident,
                compressed_type_name: $compressed_type_name:ident,
                proven_type: $proven_type:ident,
                native_type: $native_type:ty $(,)?
            }
        ),*
        $(,)?
    ) => {
        $(
            create_wrapper_type_that_has_native_type!(
                {
                    type_name: $type_name,
                    compressed_type_name: $compressed_type_name,
                    proven_type: $proven_type,
                    native_type: $native_type
                }
            );
        )*
    }
);

#[cfg(feature = "extended-types")]
create_wrapper_type_that_has_native_type!(
    {
        type_name: FheUint24,
        compressed_type_name: CompressedFheUint24,
        proven_type: ProvenFheUint24,
        native_type: u32,
    },
    {
        type_name: FheUint40,
        compressed_type_name: CompressedFheUint40,
        proven_type: ProvenFheUint40,
        native_type: u64,
    },
    {
        type_name: FheUint48,
        compressed_type_name: CompressedFheUint48,
        proven_type: ProvenFheUint48,
        native_type: u64,
    },
    {
        type_name: FheUint56,
        compressed_type_name: CompressedFheUint56,
        proven_type: ProvenFheUint56,
        native_type: u64,
    },
    {
        type_name: FheInt24,
        compressed_type_name: CompressedFheInt24,
        proven_type: ProvenFheInt24,
        native_type: i32,
    },
    {
        type_name: FheInt40,
        compressed_type_name: CompressedFheInt40,
        proven_type: ProvenFheInt40,
        native_type: i64,
    },
    {
        type_name: FheInt48,
        compressed_type_name: CompressedFheInt48,
        proven_type: ProvenFheInt48,
        native_type: i64,
    },
    {
        type_name: FheInt56,
        compressed_type_name: CompressedFheInt56,
        proven_type: ProvenFheInt56,
        native_type: i64,
    },
);

create_wrapper_type_that_has_native_type!(
    {
        type_name: FheBool,
        compressed_type_name: CompressedFheBool,
        proven_type: ProvenFheBool,
        native_type: bool,
    },
    {
        type_name: FheUint2,
        compressed_type_name: CompressedFheUint2,
        proven_type: ProvenFheUint2,
        native_type: u8,
    },
    {
        type_name: FheUint4,
        compressed_type_name: CompressedFheUint4,
        proven_type: ProvenFheUint4,
        native_type: u8,
    },
    {
        type_name: FheUint6,
        compressed_type_name: CompressedFheUint6,
        proven_type: ProvenFheUint6,
        native_type: u8,
    },
    {
        type_name: FheUint8,
        compressed_type_name: CompressedFheUint8,
        proven_type: ProvenFheUint8,
        native_type: u8,
    },
    {
        type_name: FheUint10,
        compressed_type_name: CompressedFheUint10,
        proven_type: ProvenFheUint10,
        native_type: u16,
    },
    {
        type_name: FheUint12,
        compressed_type_name: CompressedFheUint12,
        proven_type: ProvenFheUint12,
        native_type: u16,
    },
    {
        type_name: FheUint14,
        compressed_type_name: CompressedFheUint14,
        proven_type: ProvenFheUint14,
        native_type: u16,
    },
    {
        type_name: FheUint16,
        compressed_type_name: CompressedFheUint16,
        proven_type: ProvenFheUint16,
        native_type: u16,
    },
    {
        type_name: FheUint32,
        compressed_type_name: CompressedFheUint32,
        proven_type: ProvenFheUint32,
        native_type: u32,
    },
    {
        type_name: FheUint64,
        compressed_type_name: CompressedFheUint64,
        proven_type: ProvenFheUint64,
        native_type: u64,
    },
    {
        type_name: FheInt2,
        compressed_type_name: CompressedFheInt2,
        proven_type: ProvenFheInt2,
        native_type: i8,
    },
    {
        type_name: FheInt4,
        compressed_type_name: CompressedFheInt4,
        proven_type: ProvenFheInt4,
        native_type: i8,
    },
    {
        type_name: FheInt6,
        compressed_type_name: CompressedFheInt6,
        proven_type: ProvenFheInt6,
        native_type: i8,
    },
    {
        type_name: FheInt8,
        compressed_type_name: CompressedFheInt8,
        proven_type: ProvenFheInt8,
        native_type: i8,
    },
    {
        type_name: FheInt10,
        compressed_type_name: CompressedFheInt10,
        proven_type: ProvenFheInt10,
        native_type: i16,
    },
    {
        type_name: FheInt12,
        compressed_type_name: CompressedFheInt12,
        proven_type: ProvenFheInt12,
        native_type: i16,
    },
    {
        type_name: FheInt14,
        compressed_type_name: CompressedFheInt14,
        proven_type: ProvenFheInt14,
        native_type: i16,
    },
    {
        type_name: FheInt16,
        compressed_type_name: CompressedFheInt16,
        proven_type: ProvenFheInt16,
        native_type: i16,
    },
    {
        type_name: FheInt32,
        compressed_type_name: CompressedFheInt32,
        proven_type: ProvenFheInt32,
        native_type: i32,
    },
    {
        type_name: FheInt64,
        compressed_type_name: CompressedFheInt64,
        proven_type: ProvenFheInt64,
        native_type: i64,
    },
);

#[wasm_bindgen]
pub struct CompactCiphertextListBuilder(crate::high_level_api::CompactCiphertextListBuilder);

#[wasm_bindgen]
pub struct CompactCiphertextListExpander(crate::high_level_api::CompactCiphertextListExpander);

#[wasm_bindgen]
pub struct CompactCiphertextList(crate::high_level_api::CompactCiphertextList);

#[cfg(feature = "zk-pok")]
#[wasm_bindgen]
pub struct ProvenCompactCiphertextList(crate::high_level_api::ProvenCompactCiphertextList);

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
    pub fn expand(&self) -> Result<CompactCiphertextListExpander, JsError> {
        catch_panic_result(|| {
            self.0
                .expand()
                .map_err(into_js_error)
                .map(CompactCiphertextListExpander)
        })
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<CompactCiphertextList, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(CompactCiphertextList)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                .serialize_into(&self.0, &mut buffer)
                .map_err(into_js_error)
        })?;

        Ok(buffer)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(
        buffer: &[u8],
        serialized_size_limit: u64,
    ) -> Result<CompactCiphertextList, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(CompactCiphertextList)
                .map_err(into_js_error)
        })
    }
}

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
    pub fn verify_and_expand(
        &self,
        crs: &CompactPkeCrs,
        public_key: &TfheCompactPublicKey,
        metadata: &[u8],
    ) -> Result<CompactCiphertextListExpander, JsError> {
        catch_panic_result(|| {
            let inner = self
                .0
                .verify_and_expand(&crs.0, &public_key.0, metadata)
                .map_err(into_js_error)?;
            Ok(CompactCiphertextListExpander(inner))
        })
    }

    #[wasm_bindgen]
    pub fn expand_without_verification(&self) -> Result<CompactCiphertextListExpander, JsError> {
        catch_panic_result(|| {
            let inner = self
                .0
                .expand_without_verification()
                .map_err(into_js_error)?;
            Ok(CompactCiphertextListExpander(inner))
        })
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        catch_panic_result(|| bincode::serialize(&self.0).map_err(into_js_error))
    }

    #[wasm_bindgen]
    pub fn deserialize(buffer: &[u8]) -> Result<ProvenCompactCiphertextList, JsError> {
        catch_panic_result(|| {
            bincode::deserialize(buffer)
                .map(ProvenCompactCiphertextList)
                .map_err(into_js_error)
        })
    }

    #[wasm_bindgen]
    pub fn safe_serialize(&self, serialized_size_limit: u64) -> Result<Vec<u8>, JsError> {
        let mut buffer = vec![];
        catch_panic_result(|| {
            crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
                .serialize_into(&self.0, &mut buffer)
                .map_err(into_js_error)
        })?;

        Ok(buffer)
    }

    #[wasm_bindgen]
    pub fn safe_deserialize(
        buffer: &[u8],
        serialized_size_limit: u64,
    ) -> Result<ProvenCompactCiphertextList, JsError> {
        catch_panic_result(|| {
            crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
                .disable_conformance()
                .deserialize_from(buffer)
                .map(ProvenCompactCiphertextList)
                .map_err(into_js_error)
        })
    }
}

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

#[cfg(feature = "extended-types")]
define_builder_push_method!(unsigned: {
    24 <= u32,
    40 <= u64,
    48 <= u64,
    56 <= u64,
});

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

#[cfg(feature = "extended-types")]
define_builder_push_method!(signed: {
    24 <= i32,
    40 <= i64,
    48 <= i64,
    56 <= i64,
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

    #[cfg(feature = "zk-pok")]
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
            if seed.len() != 16 {
                return Err(into_js_error("seed must be exactly 16 bytes"));
            }
            let seed_value = crate::core_crypto::commons::math::random::Seed(
                u128::from_le_bytes(seed.try_into().unwrap()),
            );
            self.0
                .build_with_proof_packed_seeded(&crs.0, metadata, compute_load.into(), seed_value)
                .map_err(into_js_error)
                .map(ProvenCompactCiphertextList)
        })
    }
}

#[cfg(feature = "extended-types")]
#[wasm_bindgen]
impl CompactCiphertextListBuilder {
    #[wasm_bindgen]
    pub fn push_u72(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 72)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u80(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 80)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u88(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 88)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u96(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 96)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u104(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 104)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u112(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 112)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u120(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = u128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 120)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u136(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 136)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u144(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 144)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u152(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 152)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u168(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 168)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u176(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 176)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u184(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 184)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u192(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 192)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u200(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 200)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u208(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 208)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u216(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 216)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u224(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 224)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u232(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 232)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u240(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 240)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_u248(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = U256::try_from(value)?;
            self.0.push_with_num_bits(value, 248)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i72(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 72)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i80(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 80)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i88(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 88)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i96(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 96)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i104(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 104)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i112(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 112)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i120(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = i128::try_from(value).map_err(into_js_error)?;
            self.0.push_with_num_bits(value, 120)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i136(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 136)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i144(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 144)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i152(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 152)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i168(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 168)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i176(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 176)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i184(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 184)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i192(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 192)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i200(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 200)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i208(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 208)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i216(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 216)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i224(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 224)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i232(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 232)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i240(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 240)?;
            Ok(())
        })
    }

    #[wasm_bindgen]
    pub fn push_i248(&mut self, value: JsValue) -> Result<(), JsError> {
        catch_panic_result(|| {
            let value = I256::try_from(value)?;
            self.0.push_with_num_bits(value, 248)?;
            Ok(())
        })
    }
}

/// Helper macro to define get methods for the expander
/// one method per Fhe type possible as JS is not a typed language as Rust is
macro_rules! define_expander_get_method {
    (
        unsigned: {
            $($num_bits:literal),*
            $(,)?
        }
    ) => {
        ::paste::paste!{
            #[wasm_bindgen]
            impl CompactCiphertextListExpander {
                $(
                    #[wasm_bindgen]
                    pub fn [<get_uint $num_bits>] (&mut self, index: usize) -> Result<[<FheUint $num_bits>], JsError> {
                        catch_panic_result(|| {
                            self.0.get::<crate::[<FheUint $num_bits>]>(index)
                                .map_err(into_js_error)
                                .map(|val|
                                      val.map_or_else(
                                          || Err(JsError::new(&format!("Index {index} is out of bounds"))),
                                          |val| Ok([<FheUint $num_bits>](val))
                                    ))?
                        })
                    }
                )*
            }
        }
    };
    (
        signed: {
            $($num_bits:literal),*
            $(,)?
        }
    ) => {
        ::paste::paste!{
            #[wasm_bindgen]
            impl CompactCiphertextListExpander {
                $(
                    #[wasm_bindgen]
                    pub fn [<get_int $num_bits>] (&mut self, index: usize) -> Result<[<FheInt $num_bits>], JsError> {
                        catch_panic_result(|| {
                           self.0.get::<crate::[<FheInt $num_bits>]>(index)
                                .map_err(into_js_error)
                                .map(|val|
                                      val.map_or_else(
                                          || Err(JsError::new(&format!("Index {index} is out of bounds"))),
                                          |val| Ok([<FheInt $num_bits>](val))
                                    ))?
                        })
                    }
                )*
            }
        }
    };
}

#[cfg(feature = "extended-types")]
define_expander_get_method!(
    unsigned: { 24, 40, 48, 56, 72, 80, 88, 96, 104, 112, 120, 136, 144, 152, 168, 176, 184,
                192, 200, 208, 216, 224, 232, 240, 248, 256 }
);

define_expander_get_method!(
    unsigned: { 2, 4, 6, 8, 10, 12, 14, 16, 32, 64, 128, 160, 512, 1024, 2048 }
);

#[cfg(feature = "extended-types")]
define_expander_get_method!(
    signed: { 24, 40, 48, 56, 72, 80, 88, 96, 104, 112, 120, 136, 144, 152, 168, 176, 184, 192,
              200, 208, 216, 224, 232, 240, 248 }
);

define_expander_get_method!(
    signed: { 2, 4, 6, 8, 10, 12, 14, 16, 32, 64, 128, 160, 256, 512, 1024, 2048 }
);

#[wasm_bindgen]
impl CompactCiphertextListExpander {
    #[wasm_bindgen]
    pub fn get_bool(&self, index: usize) -> Result<FheBool, JsError> {
        catch_panic_result(|| {
            self.0
                .get::<crate::FheBool>(index)
                .map_err(into_js_error)
                .map(|val| {
                    val.map_or_else(
                        || Err(JsError::new(&format!("Index {index} is out of bounds"))),
                        |val| Ok(FheBool(val)),
                    )
                })?
        })
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
